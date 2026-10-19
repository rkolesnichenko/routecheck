package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"iter"
	"net"
	"os"
	"slices"
	"strings"

	"github.com/rkolesnichenko/mrt"
	"github.com/rkolesnichenko/rpsl"
	"github.com/rkolesnichenko/rpsl/object"
	"github.com/rkolesnichenko/rpsl/resolve"
	"github.com/rkolesnichenko/rpsl/resolve/irrd"
	"github.com/rkolesnichenko/rpsl/resolve/rpki"
	"github.com/rkolesnichenko/rpsl/types"
)

// checkInputs fails, naming the file, when an input of -session or
// -collector does not exist, before anything is loaded. It opens nothing.
func checkInputs(names []string) error {
	for _, name := range names {
		if _, err := os.Stat(name); err != nil {
			return err
		}
	}
	return nil
}

// openInput opens an input file; tests replace it to watch the opens.
var openInput = func(name string) (io.ReadCloser, error) { return os.Open(name) }

// records reads the inputs one after another, in the order given, each
// through gzip or bzip2 when it is compressed (mrt.Decompress). A file is
// opened when its turn comes and closed before the next one is opened, so
// any number of inputs needs one descriptor. Every error is wrapped with its
// file's name; the wrapping keeps *mrt.RecordError and mrt.ErrTruncated
// visible to errors.As and errors.Is, which observe reads.
func records(names []string) iter.Seq2[mrt.Record, error] {
	return func(yield func(mrt.Record, error) bool) {
		for _, name := range names {
			if !readInput(name, yield) {
				return
			}
		}
	}
}

// readInput yields one input's records and reports whether to go on.
func readInput(name string, yield func(mrt.Record, error) bool) bool {
	f, err := openInput(name)
	if err != nil {
		yield(nil, err)
		return false
	}
	defer f.Close()
	r, err := mrt.Decompress(f)
	if err != nil {
		yield(nil, fmt.Errorf("%s: %w", name, err))
		return false
	}
	for rec, err := range mrt.Records(r) {
		if err != nil {
			err = fmt.Errorf("%s: %w", name, err)
		}
		if !yield(rec, err) {
			return false
		}
	}
	return true
}

// readVRPs reads a VRP JSON file (rpki.ReadJSON), compressed or not.
func readVRPs(name string) (*rpki.VRPs, error) {
	f, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	r, err := mrt.Decompress(f)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	v, err := rpki.ReadJSON(r)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	return v, nil
}

// irrdAddr is -irrd's address with IRRd's port, 43, when it names none:
// "host", "192.0.2.1", "2001:db8::1" and "[2001:db8::1]" each get ":43".
func irrdAddr(s string) string {
	if _, _, err := net.SplitHostPort(s); err == nil {
		return s
	}
	return net.JoinHostPort(strings.TrimSuffix(strings.TrimPrefix(s, "["), "]"), "43")
}

// loaded is what loadPolicy loads.
type loaded struct {
	// src is the policy source, wrapped in a resolve.Cache (peval reads the
	// same aut-nums and sets for every report).
	src resolve.PolicySource
	// verified answers route objects from the verified sources present
	// alone; nil when none is (the marking is off).
	verified resolve.Source
	// verifiedNote is the stderr line naming the verified sources present
	// and absent.
	verifiedNote string
	// close releases the sources.
	close func()
}

// loadPolicy builds the policy source the command line names and, for the
// route-object marking, a view of the same registries restricted to the
// -verified-sources present in them. It records in cfg.draftSupplies what
// -policy answers first.
//
// With -dump the files are parsed (rpsl.Parse, rpsl.Decode) into one
// resolve.Corpus that keeps policy objects, in the order given; the source
// precedence is the order in which each source: first appears in them, so an
// object of the first dump's registry wins over another registry's. -policy
// is read last into the same Corpus (its aut-nums and inet-rtrs only), so
// they replace any of the same class, primary key and source (its new
// sources rank last). The verified sources present are the dumps' (never the
// draft's, which holds no route object), in the order they first appear, and
// their view is Corpus.SourceOf.
//
// With -irrd the server is an irrd.Source with -sources as its precedence.
// The verified sources present are those within -sources (when given) that
// the server serves, each probed alone (probeSource), in -verified-sources'
// order; their view is a second irrd.Source asking for them alone.
//
// Either way, -policy's aut-nums and inet-rtrs answer before the registry's,
// under any source (spec §5): a draft written with another source: than the
// registry's is still the one checked. Sets and routes always come from the
// registry (readDraft skips a draft's).
func loadPolicy(ctx context.Context, cfg *config, stderr io.Writer) (*loaded, error) {
	var d *draft
	if cfg.policyFile != "" {
		var err error
		if d, err = readDraft(cfg.policyFile, stderr); err != nil {
			return nil, err
		}
		cfg.draftSupplies = d.supplies
	}

	var reg resolve.PolicySource
	var verified resolve.Source // stays a nil interface when the marking is off
	var present []string
	closeReg := func() {}
	if len(cfg.dumps) > 0 {
		c := &resolve.Corpus{KeepPolicy: true}
		var order []string
		for _, name := range cfg.dumps {
			err := readRPSL(name, func(o rpsl.Object, _, _, source string, _ []rpsl.Diagnostic) {
				if source != "" && !slices.Contains(order, source) {
					order = append(order, source)
				}
				c.Put(o)
			})
			if err != nil {
				return nil, err
			}
		}
		// The verified sources present are the dumps' own: a draft's
		// source: supplies no route object.
		for _, s := range order {
			if slices.Contains(cfg.verified, s) {
				present = append(present, s)
			}
		}
		if len(present) > 0 {
			verified = c.SourceOf(present...)
		}
		if d != nil {
			for _, o := range d.objs {
				c.Put(o)
			}
			for _, s := range d.sources {
				if !slices.Contains(order, s) {
					order = append(order, s)
				}
			}
		}
		reg = c.Source(order...)
	} else {
		addr := irrdAddr(cfg.irrd)
		for _, name := range cfg.verified {
			if len(cfg.sources) > 0 && !slices.Contains(cfg.sources, name) {
				continue
			}
			ok, err := probeSource(ctx, addr, name)
			if err != nil {
				return nil, err
			}
			if ok {
				present = append(present, name)
			}
		}
		s := &irrd.Source{Addr: addr, Sources: cfg.sources}
		reg, closeReg = s, func() { s.Close() }
		if len(present) > 0 {
			v := &irrd.Source{Addr: addr, Sources: present}
			verified, closeReg = v, func() { s.Close(); v.Close() }
		}
	}
	if d != nil {
		reg = &draftFirst{PolicySource: reg, draft: d.corpus.Source(d.sources...)}
	}
	return &loaded{
		src:          resolve.NewCache(reg, 0),
		verified:     verified,
		verifiedNote: verifiedNote(cfg.verified, present),
		close:        closeReg,
	}, nil
}

// probeSource reports whether the IRRd at addr serves the source name. It
// asks "!g" for AS64496 (a documentation ASN, RFC 5398) with the source list
// restricted to name alone. Any irrd.ErrQueryRefused, whether the server
// refused the "!s" selection or the query itself, counts the source as
// absent. IRRd refuses a whole "!s" list when one name in it is unknown, so
// the verified sources are probed one at a time and the absent ones left
// out. Any other failure, a context error included, is an error naming the
// source.
func probeSource(ctx context.Context, addr, name string) (bool, error) {
	s := &irrd.Source{Addr: addr, Sources: []string{name}}
	defer s.Close()
	_, err := s.OriginatedRoutes(ctx, 64496, types.AFIv4)
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, irrd.ErrQueryRefused):
		return false, nil
	}
	return false, fmt.Errorf("probing the verified source %s: %w", name, err)
}

// verifiedNote is the stderr line naming the verified sources present (in
// present's order) and the absent ones (in -verified-sources' order), or
// saying that none is present and answers are not marked.
func verifiedNote(verified, present []string) string {
	if len(present) == 0 {
		return fmt.Sprintf("route objects: none of the verified sources (%s) is present; answers are not marked", strings.Join(verified, ", "))
	}
	note := "route objects: verified sources " + strings.Join(present, ", ")
	var absent []string
	for _, v := range verified {
		if !slices.Contains(present, v) {
			absent = append(absent, v)
		}
	}
	if len(absent) > 0 {
		note += "; absent: " + strings.Join(absent, ", ")
	}
	return note
}

// draft is a -policy file, read and checked.
type draft struct {
	objs     []rpsl.Object   // what joins the dumps: its aut-nums and inet-rtrs
	corpus   *resolve.Corpus // the file's aut-nums and inet-rtrs alone
	sources  []string        // their sources, in first-seen order
	supplies []string        // "aut-num AS64496 (TEST)", "inet-rtr rtr1.example.net"
}

// setClasses are the set classes: in a draft they are skipped, since sets
// always come from the registry (rulings R15, R17).
var setClasses = map[string]bool{"as-set": true, "route-set": true, "filter-set": true, "peering-set": true, "rtr-set": true}

// readDraft reads a -policy file (ruling R17). Every parse and decode
// diagnostic is written to stderr. What the draft supplies is its aut-nums
// and inet-rtrs; the run fails, naming the file and the object, when one of
// them raises an Error (it would be checked misread: a typo in a policy
// turns "accept" into a router name) or is not kept (a key that does not
// parse), and when the file supplies none (it would change nothing). Every
// other object is skipped with a warning, broken or not (rulings R17, R18):
// a set or a route or route6 (they come from the registry: a draft's would
// change set expansions and route-object answers) and a class routecheck
// does not use (mntner, person, …).
func readDraft(name string, stderr io.Writer) (*draft, error) {
	d := &draft{corpus: &resolve.Corpus{KeepPolicy: true}}
	var bad error
	err := readRPSL(name, func(o rpsl.Object, class, key, source string, diags []rpsl.Diagnostic) {
		failed := false
		for _, dg := range diags {
			fmt.Fprintf(stderr, "routecheck: %s:%s\n", name, dg)
			failed = failed || dg.Severity >= rpsl.Error
		}
		class = strings.ToLower(class)
		what := class + " " + key
		skip := func(why string) { fmt.Fprintf(stderr, "routecheck: %s: %s skipped: %s\n", name, what, why) }
		switch {
		case bad != nil:
			return
		case class == "aut-num" || class == "inet-rtr":
			if failed {
				bad = fmt.Errorf("%s: %s does not decode cleanly (see the diagnostics above)", name, what)
				return
			}
			if !d.corpus.Put(o) {
				bad = fmt.Errorf("%s: %s is not kept: its key does not parse", name, what)
				return
			}
		case setClasses[class]:
			skip("sets come from the registry")
			return
		case class == "route" || class == "route6":
			skip("routes come from the registry")
			return
		default:
			skip("routecheck does not use this class")
			return
		}
		d.objs = append(d.objs, o)
		if source != "" && !slices.Contains(d.sources, source) {
			d.sources = append(d.sources, source)
		}
		label := what
		switch x := o.(type) {
		case *object.AutNum:
			label = "aut-num " + x.AS.String()
		case *object.InetRtr:
			label = "inet-rtr " + x.Name
		}
		if source != "" {
			label += " (" + source + ")"
		}
		d.supplies = append(d.supplies, label)
	})
	switch {
	case err != nil:
		return nil, err
	case bad != nil:
		return nil, bad
	case len(d.supplies) == 0:
		return nil, fmt.Errorf("%s: no aut-num and no inet-rtr: -policy would change nothing", name)
	}
	return d, nil
}

// draftFirst answers AutNum and InetRtr from the -policy file's objects
// first, and from the registry when the file has none; everything else
// (sets, routes) from the registry.
type draftFirst struct {
	resolve.PolicySource
	draft *resolve.MemSource
}

func (d *draftFirst) AutNum(ctx context.Context, as types.ASN, source string) (*object.AutNum, error) {
	a, err := d.draft.AutNum(ctx, as, source)
	if err == nil || !errors.Is(err, resolve.ErrNotFound) {
		return a, err
	}
	return d.PolicySource.AutNum(ctx, as, source)
}

func (d *draftFirst) InetRtr(ctx context.Context, name, source string) (*object.InetRtr, error) {
	r, err := d.draft.InetRtr(ctx, name, source)
	if err == nil || !errors.Is(err, resolve.ErrNotFound) {
		return r, err
	}
	return d.PolicySource.InetRtr(ctx, name, source)
}

// readRPSL parses an RPSL file (a dump or -policy), compressed or not, and
// calls fn with each object, decoded, its class and primary key as written,
// its source: in upper case ("" when it has none) and its parse and decode
// diagnostics. A failure to read the file is an error naming it, so that a
// truncated dump is never taken for a short one.
func readRPSL(name string, fn func(o rpsl.Object, class, key, source string, diags []rpsl.Diagnostic)) error {
	f, err := os.Open(name)
	if err != nil {
		return err
	}
	defer f.Close()
	r, err := mrt.Decompress(f)
	if err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	for o, ds := range rpsl.Parse(r) {
		for _, d := range ds {
			if d.Rule == "rpsl/read-error" {
				return fmt.Errorf("%s: reading: %s", name, d.Message)
			}
		}
		if o == nil {
			continue
		}
		obj, dds := rpsl.Decode(o)
		if obj == nil {
			continue
		}
		source := ""
		for _, a := range o.Attributes() {
			if f := strings.Fields(a.Value); strings.EqualFold(a.Name, "source") && len(f) > 0 {
				source = strings.ToUpper(f[0])
				break
			}
		}
		fn(obj, o.Class(), o.Key(), source, slices.Concat(ds, dds))
	}
	return nil
}
