// Package cli is the routecheck command: flags, loading the registry, the
// VRPs and the MRT inputs, calling routecheck.Checker.Check, and writing its
// results as text or JSON (spec §8). cmd/routecheck is its shim.
package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"strings"
	"time"

	"github.com/rkolesnichenko/routecheck"
	"github.com/rkolesnichenko/routecheck/observe"
	"github.com/rkolesnichenko/rpsl/resolve/peval"
	"github.com/rkolesnichenko/rpsl/types"
)

// The exit statuses (spec §8, as rpslcheck's).
const (
	exitOK       = 0 // nothing Rejected (Undecided routes and "no policy" alone exit 0)
	exitRejected = 1 // some route Rejected, in either direction
	exitUsage    = 2 // a command line routecheck cannot use
	exitFailed   = 3 // the check could not complete
)

// maxExamples is how many routes each group of Rejected or Undecided routes
// shows.
const maxExamples = 5

const synopsis = `routecheck -peer AS (-session FILE [-local AS] | -collector FILE -local AS)
           (-dump FILE | -irrd HOST:PORT [-sources LIST]) [-policy FILE]
           [-vrps FILE] [-af ipv4|ipv6|both] [-direction import|export|both]
           [-peer-addr IP] [-at TIME] [-pre-policy]
           [-local-rtr IP] [-peer-rtr IP] [-format text|json]
           [-routes all|rejected|undecided|none]`

const about = `Checks the routes a BGP neighbour X (-peer) really announces against the
registered RPSL policy of the local AS L (-local): which routes L's import
policy accepts and through which clause, which it rejects and why, and which
it cannot decide and why; and which routes X's own export policy does not
permit.

Routes come from an MRT capture of the L-X session (-session: BGP4MP
messages X sent) or from route-collector RIB dumps (-collector: every path
through X, cut to the part X announced, which approximates what X sends L).
-session, -collector and -dump are repeatable, one file each; several files
are read in the order given, and gzip and bzip2 files are read too.

The policy comes from IRR dump files (-dump; when two registries hold an
object, the one whose source: appears first in the dumps, in the order
given, wins) or a live IRRd (-irrd, with -sources its precedence). -policy
adds a local RPSL file, a draft not yet published: its aut-nums and
inet-rtrs answer before the registry's, under any source. Sets and routes
always come from the registry: a draft's sets, routes and objects of classes
routecheck does not use (mntner, person, ...) are skipped with a warning.
Its diagnostics are written to stderr; an aut-num or inet-rtr with an error,
and a file with no aut-num and no inet-rtr, fail the run.

In session mode -local defaults to the capture's local AS. When most routes
seen do not start with X - the announcements skipped for it outnumber the
routes held at the end of the capture, all families together, so they are
more than half of the two - the report says X looks like a transparent route
server, which this version does not support (not judged when a family has
"no policy" in every direction checked, since its routes are then not
counted).`

const exitStatus = `Exit status:
  0  nothing Rejected (Undecided routes and "no policy" alone exit 0)
  1  some route Rejected, in either direction
  2  a bad command line
  3  could not complete: a file unreadable, an aut-num missing, the policy
     not evaluable, the server unreachable, the run interrupted`

// listFlag is a repeatable flag: each use adds one value.
type listFlag []string

func (l *listFlag) String() string     { return strings.Join(*l, ",") }
func (l *listFlag) Set(s string) error { *l = append(*l, s); return nil }

// config is a command line, checked.
type config struct {
	mode       routecheck.Mode
	inputs     []string
	dumps      []string
	irrd       string
	sources    []string
	policyFile string
	vrps       string
	opts       routecheck.Options
	localGiven bool
	// draftSupplies is what -policy answers first ("aut-num AS1 (TEST)"),
	// set by loadPolicy.
	draftSupplies []string
	format        string
	routes        string
}

// usageError is a command line routecheck cannot use.
type usageError struct{ msg string }

func (e *usageError) Error() string { return e.msg }

func usagef(format string, a ...any) error { return &usageError{fmt.Sprintf(format, a...)} }

// Run runs routecheck with the given arguments and returns its exit status.
// ctx ends the run early (cmd/routecheck cancels it on SIGINT and SIGTERM).
func Run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	cfg, err := parse(args, stdout, stderr)
	if errors.Is(err, flag.ErrHelp) {
		return exitOK
	}
	if err != nil {
		fmt.Fprintf(stderr, "routecheck: %v\nrun 'routecheck -h' for usage\n", err)
		return exitUsage
	}
	fail := func(err error) int {
		fmt.Fprintln(stderr, message(err))
		return exitFailed
	}

	// The inputs are looked for first, so that a mistyped name fails before
	// a long registry load; each is opened only when it is read.
	if err := checkInputs(cfg.inputs); err != nil {
		return fail(err)
	}
	if cfg.vrps != "" {
		if cfg.opts.VRPs, err = readVRPs(cfg.vrps); err != nil {
			return fail(err)
		}
	}
	src, closeSrc, err := loadPolicy(cfg, stderr)
	if err != nil {
		return fail(err)
	}
	defer closeSrc()

	c := &routecheck.Checker{Eval: peval.Evaluator{Src: src}, Routes: src}
	results, err := c.Check(ctx, cfg.mode, records(cfg.inputs), cfg.opts)
	if errors.Is(err, routecheck.ErrOptions) {
		hint := ""
		if !cfg.localGiven {
			hint = " (give -local)"
		}
		fmt.Fprintf(stderr, "%s%s\nrun 'routecheck -h' for usage\n", message(err), hint)
		return exitUsage
	}
	if errors.Is(err, observe.ErrRIBNotPrePolicy) {
		return fail(fmt.Errorf("%w (pass -pre-policy if the table is %s's Adj-RIB-In before import policy)", err, cfg.opts.Peer))
	}
	if err != nil {
		return fail(err)
	}
	if cfg.format == "json" {
		err = writeJSON(stdout, results)
	} else {
		err = writeText(stdout, cfg, results)
	}
	if err != nil {
		return fail(err)
	}
	for _, r := range results {
		if r.Import != nil && r.Import.Rejected > 0 {
			return exitRejected
		}
		for _, e := range r.Export {
			if e.Rejected > 0 {
				return exitRejected
			}
		}
	}
	return exitOK
}

// message is err's text for stderr, starting "routecheck: " once (the
// library's own errors already do).
func message(err error) string {
	if m := err.Error(); strings.HasPrefix(m, "routecheck: ") {
		return m
	}
	return "routecheck: " + err.Error()
}

// parse reads and checks the command line. -h writes the usage to stdout and
// returns flag.ErrHelp; any other mistake returns an error to print.
func parse(args []string, stdout, stderr io.Writer) (*config, error) {
	fs := flag.NewFlagSet("routecheck", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var session, collector, dumps listFlag
	local := fs.String("local", "", "the local AS `L`, whose import policy is checked (session mode: default the capture's local AS)")
	peer := fs.String("peer", "", "the neighbour AS `X`, whose routes are checked")
	fs.Var(&session, "session", "an MRT capture `file` of the L-X session: BGP4MP messages X sent (repeatable)")
	fs.Var(&collector, "collector", "a route-collector MRT RIB dump `file` (repeatable)")
	fs.Var(&dumps, "dump", "an IRR dump `file` holding the policies, sets and routes (repeatable)")
	irrd := fs.String("irrd", "", "a live IRRd `host:port` (port 43 when absent) instead of -dump")
	sources := fs.String("sources", "", "with -irrd: the registries, comma-separated, in precedence `order` (default: the server's)")
	policyFile := fs.String("policy", "", "a local RPSL `file` (a draft) whose aut-nums and inet-rtrs answer first")
	vrps := fs.String("vrps", "", "a VRP JSON `file` (rpki-client, Routinator) for each route's RPKI state")
	af := fs.String("af", "both", "address `families` checked: ipv4, ipv6 or both (unicast)")
	direction := fs.String("direction", "both", "`policies` checked: import (L's), export (X's) or both")
	peerAddr := fs.String("peer-addr", "", "session mode: read only the capture's records with this peer `address`")
	at := fs.String("at", "", "session mode: the state at this `time` (RFC 3339, records at it included); default the end of the capture")
	prePolicy := fs.Bool("pre-policy", false, "session mode: RIB dumps in the input are X's Adj-RIB-In before import policy")
	localRtr := fs.String("local-rtr", "", "L's router `address` on the session, for peerings that name routers")
	peerRtr := fs.String("peer-rtr", "", "X's router `address` on the session, for peerings that name routers")
	format := fs.String("format", "text", "output `format`: text or json")
	routes := fs.String("routes", "none", "text: the routes `listed` after the summary: all, rejected, undecided or none")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprintf(stdout, "Usage:\n  %s\n\n%s\n\nOptions:\n", synopsis, about)
			fs.SetOutput(stdout)
			fs.PrintDefaults()
			fmt.Fprintf(stdout, "\n%s\n", exitStatus)
		}
		return nil, err
	}
	if fs.NArg() > 0 {
		return nil, usagef("unexpected argument %q: give each input file its own -session, -collector or -dump", fs.Arg(0))
	}
	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })

	cfg := &config{dumps: dumps, irrd: *irrd, policyFile: *policyFile, vrps: *vrps, format: *format, routes: *routes}
	var err error
	if *peer == "" {
		return nil, usagef("-peer is required")
	}
	if cfg.opts.Peer, err = parseAS("-peer", *peer); err != nil {
		return nil, err
	}
	if *local != "" {
		if cfg.opts.Local, err = parseAS("-local", *local); err != nil {
			return nil, err
		}
		cfg.localGiven = true
	}
	if cfg.localGiven && cfg.opts.Local == cfg.opts.Peer {
		return nil, usagef("-local and -peer must differ")
	}
	switch {
	case len(session) > 0 && len(collector) > 0, len(session) == 0 && len(collector) == 0:
		return nil, usagef("give -session or -collector files, not both")
	case len(session) > 0:
		cfg.mode, cfg.inputs = routecheck.ModeSession, session
	default:
		cfg.mode, cfg.inputs = routecheck.ModeCollector, collector
		for _, name := range []string{"pre-policy", "at", "peer-addr"} {
			if set[name] {
				return nil, usagef("-%s belongs to session mode (-session)", name)
			}
		}
	}
	if (len(dumps) > 0) == (*irrd != "") {
		return nil, usagef("give -dump or -irrd (one of the two)")
	}
	if *sources != "" {
		if *irrd == "" {
			return nil, usagef("-sources belongs to -irrd (with -dump the order of the dumps decides)")
		}
		for _, s := range strings.Split(*sources, ",") {
			if s = strings.TrimSpace(s); s != "" {
				cfg.sources = append(cfg.sources, strings.ToUpper(s))
			}
		}
	}
	if cfg.opts.AF, err = families(*af); err != nil {
		return nil, err
	}
	switch *direction {
	case "import":
		cfg.opts.Directions = routecheck.DirImport
	case "export":
		cfg.opts.Directions = routecheck.DirExport
	case "both":
		cfg.opts.Directions = routecheck.DirBoth
	default:
		return nil, usagef("-direction: %q is not import, export or both", *direction)
	}
	if cfg.mode == routecheck.ModeCollector && !cfg.localGiven && cfg.opts.Directions&routecheck.DirImport != 0 {
		return nil, usagef("-local is required in collector mode when the import direction is checked")
	}
	for _, a := range []struct {
		flag, val string
		dst       *netip.Addr
	}{{"-peer-addr", *peerAddr, &cfg.opts.PeerAddr}, {"-local-rtr", *localRtr, &cfg.opts.LocalRtr}, {"-peer-rtr", *peerRtr, &cfg.opts.PeerRtr}} {
		if a.val == "" {
			continue
		}
		if *a.dst, err = netip.ParseAddr(a.val); err != nil {
			return nil, usagef("%s: %q is not an IP address", a.flag, a.val)
		}
	}
	if *at != "" {
		if cfg.opts.At, err = time.Parse(time.RFC3339, *at); err != nil {
			return nil, usagef("-at: %q is not an RFC 3339 time (such as 2026-10-16T12:00:00Z)", *at)
		}
	}
	cfg.opts.PrePolicyRIB = *prePolicy
	if *format != "text" && *format != "json" {
		return nil, usagef("-format: %q is not text or json", *format)
	}
	switch *routes {
	case "all", "rejected", "undecided", "none":
	default:
		return nil, usagef("-routes: %q is not all, rejected, undecided or none", *routes)
	}
	return cfg, nil
}

// parseAS reads "AS65001" or "65001".
func parseAS(flagName, s string) (types.ASN, error) {
	t := s
	if !strings.HasPrefix(strings.ToUpper(t), "AS") {
		t = "AS" + t
	}
	as, err := types.ParseASN(t)
	if err != nil {
		return 0, usagef("%s: %q is not an AS number", flagName, s)
	}
	return as, nil
}

func families(s string) ([]types.AddrFamily, error) {
	v4 := types.AddrFamily{AFI: types.AFIv4, SAFI: types.SAFIUnicast}
	v6 := types.AddrFamily{AFI: types.AFIv6, SAFI: types.SAFIUnicast}
	switch s {
	case "ipv4":
		return []types.AddrFamily{v4}, nil
	case "ipv6":
		return []types.AddrFamily{v6}, nil
	case "both":
		return []types.AddrFamily{v4, v6}, nil
	}
	return nil, usagef("-af: %q is not ipv4, ipv6 or both", s)
}
