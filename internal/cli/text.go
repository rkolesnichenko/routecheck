package cli

import (
	"fmt"
	"io"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/rkolesnichenko/routecheck"
	"github.com/rkolesnichenko/routecheck/verdict"
	"github.com/rkolesnichenko/rpsl/policy"
	"github.com/rkolesnichenko/rpsl/resolve/peval"
	"github.com/rkolesnichenko/rpsl/types"
)

// writeText writes the results as text (spec §8): what was read, the
// coverage warnings, then per family and direction the counts, the
// policy's clauses, the Rejected routes grouped by the first failing test
// of the first clause, the Undecided routes grouped by reason, and the
// routes -routes asks for; last, the router-address hint. Nothing in it
// depends on the time of the run or the working directory: file names are
// printed as given.
func writeText(w io.Writer, cfg *config, results []routecheck.Result) error {
	p := &printer{cfg: cfg, x: cfg.opts.Peer, l: cfg.opts.Local}
	var cov routecheck.Coverage
	if len(results) > 0 {
		cov = results[0].Coverage
	}
	if !cfg.localGiven && cov.Session != nil {
		p.l = cov.Session.LocalAS
	}
	p.header()
	p.coverage(results, cov)
	for _, r := range results {
		p.result(r)
	}
	p.hint(results, cov)
	_, err := io.WriteString(w, p.b.String())
	return err
}

type printer struct {
	b    strings.Builder
	cfg  *config
	x, l types.ASN
}

func (p *printer) line(format string, a ...any) {
	fmt.Fprintf(&p.b, format, a...)
	p.b.WriteByte('\n')
}

// count is "1 route", "2 routes".
func count(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return strconv.Itoa(n) + " " + many
}

// local names L, or "the local AS" when it is not known (collector mode,
// export only, no -local).
func (p *printer) local() string {
	if p.l == 0 {
		return "the local AS"
	}
	return p.l.String()
}

func (p *printer) header() {
	cfg := p.cfg
	mode := "session mode"
	if cfg.mode == routecheck.ModeCollector {
		mode = "collector mode"
	}
	p.line("routecheck: %s: local %s, peer %s", mode, p.local(), p.x)
	if !cfg.localGiven && cfg.mode == routecheck.ModeSession {
		p.line("local AS from the capture: %s", p.l)
	}
	p.line("routes: %s", strings.Join(cfg.inputs, ", "))
	if len(cfg.dumps) > 0 {
		p.line("policy: -dump %s", strings.Join(cfg.dumps, ", "))
	} else if len(cfg.sources) > 0 {
		p.line("policy: -irrd %s -sources %s", cfg.irrd, strings.Join(cfg.sources, ","))
	} else {
		p.line("policy: -irrd %s", cfg.irrd)
	}
	if cfg.policyFile != "" {
		verb := "answers"
		if len(cfg.draftSupplies) != 1 {
			verb = "answer"
		}
		p.line("policy: -policy %s: %s %s first", cfg.policyFile, strings.Join(cfg.draftSupplies, ", "), verb)
	}
	if cfg.opts.VRPs != nil {
		p.line("rpki: -vrps %s (%s)", cfg.vrps, count(cfg.opts.VRPs.Len(), "VRP", "VRPs"))
	}
	if cfg.mode == routecheck.ModeCollector {
		// Spec §6.3: what collector mode's routes are, always stated.
		x, l := p.x.String(), p.local()
		p.line("note: collector mode: these are routes %s announced to someone. %s may not", x, x)
		p.line("  announce all of them to %s (a peer gets %s's customer cone, a customer", l, x)
		p.line("  gets everything), and may announce routes to %s that no collector sees.", l)
		p.line("  A rejected route reads \"if %s sends this, %s's policy rejects it\",", x, l)
		p.line("  not \"%s sends this to %s\".", x, l)
	}
}

// coverage writes what the input says about its own completeness, once:
// observe's info and the other families' count are the same in every
// Result.
func (p *printer) coverage(results []routecheck.Result, cov routecheck.Coverage) {
	x := p.x.String()
	if s := cov.Session; s != nil {
		if w := localMismatch(p.cfg, s); w != "" {
			p.line("%s", w)
		}
		if s.MidSession {
			p.line("warning: capture starts mid-session; routes announced earlier are not seen")
		}
		if s.DownAtEnd {
			p.line("warning: session down at the end of the capture")
		}
		if s.NoRecordsBeforeAt {
			p.line("warning: no record of the session at or before -at: the state is empty")
		}
		if n := s.MalformedResets; n > 0 {
			p.line("warning: %s malformed past treat-as-withdraw (RFC 7606 session reset): the session's routes were cleared", count(n, "UPDATE", "UPDATEs"))
		}
		if n := s.Malformed; n > 0 {
			p.line("warning: %s malformed, treated as withdrawals (RFC 7606)", count(n, "announcement", "announcements"))
		}
		if n := s.NotFirstAS; n > 0 {
			p.line("warning: %s did not start with %s: skipped, each withdrawing the route it replaced", count(n, "announcement", "announcements"), x)
			if held, ok := heldRoutes(results, cov); ok && n > held {
				p.line("warning: most routes seen do not start with %s: %s looks like a transparent route server, which routecheck does not support", x, x)
			}
		}
		if n := s.Skipped; n > 0 {
			p.line("warning: %s could not be read: skipped", count(n, "record or RIB entry", "records or RIB entries"))
		}
	}
	if c := cov.Collector; c != nil {
		p.line("collector: %s read, %d through %s (%d on %s's own feed to a collector)",
			count(c.Entries, "RIB entry", "RIB entries"), c.Through, x, c.Direct, x)
		if n := c.Ignored; n > 0 {
			p.line("warning: %s ignored: collector mode reads RIB dumps only", count(n, "update record", "update records"))
		}
		if n := c.Malformed; n > 0 {
			p.line("warning: %s in the whole table malformed (RFC 7606), through %s or not: skipped", count(n, "RIB entry", "RIB entries"), x)
		}
		if n := c.NoNeighbour; n > 0 {
			verb := "names"
			if n != 1 {
				verb = "name"
			}
			p.line("warning: %s through %s %s no neighbour (an AS_SET, a confederation segment or AS_TRANS left of %s, or a collector peer of no AS): not checked against %s's export", count(n, "sighting", "sightings"), x, verb, x, x)
		}
		if n := c.NotSequence; n > 0 {
			p.line("warning: %s %s inside an AS_SET or a confederation segment: no route to check", count(n, "sighting has", "sightings have"), x)
		}
		if n := c.Skipped; n > 0 {
			p.line("warning: %s could not be read: skipped", count(n, "record or RIB entry", "records or RIB entries"))
		}
	}
	if n := cov.OtherFamilies; n > 0 {
		p.line("warning: %s in an address family not checked: dropped", count(n, "route", "routes"))
	}
}

// heldRoutes is the routes held at the end of the capture, over the
// families checked and the others: each family's count is its reports'
// (every session-mode report covers all of the family's routes). It is not
// known when a family has only "no policy" reports, which list no routes.
func heldRoutes(results []routecheck.Result, cov routecheck.Coverage) (int, bool) {
	held := cov.OtherFamilies
	for _, r := range results {
		known := false
		for _, rep := range reports(r) {
			if !rep.NoPolicy {
				held += len(rep.Routes)
				known = true
				break
			}
		}
		if !known {
			return 0, false
		}
	}
	return held, true
}

// reports lists a Result's reports, import first.
func reports(r routecheck.Result) []*routecheck.Report {
	var out []*routecheck.Report
	if r.Import != nil {
		out = append(out, r.Import)
	}
	for i := range r.Export {
		out = append(out, &r.Export[i])
	}
	return out
}

func (p *printer) result(r routecheck.Result) {
	p.line("")
	p.line("%s", r.AF)
	if n := r.Coverage.DirectNotChecked; n > 0 {
		x := p.x.String()
		p.line("  warning: %s seen on %s's own feed to a collector: that sighting is checked toward no neighbour (one also seen announced to a neighbour is checked toward it)", count(n, "route", "routes"), x)
	}
	if r.Import != nil {
		p.report("import", *r.Import, fmt.Sprintf("import, %s from %s", p.local(), r.Import.Toward), p.local())
	}
	if r.Export != nil && len(r.Export) == 0 {
		p.line("  export, %s: no neighbour seen", p.x)
	}
	for _, e := range r.Export {
		p.report("export", e, fmt.Sprintf("export, %s to %s", p.x, e.Toward), p.x.String())
	}
}

// report writes one Report: dir is "import" or "export", label its title,
// owner the AS whose policy it is.
func (p *printer) report(dir string, rep routecheck.Report, label, owner string) {
	if rep.NoPolicy {
		p.line("  %s: no policy: %s has no %s term toward %s in this family; its routes are not decided", label, owner, dir, rep.Toward)
		return
	}
	p.line("  %s: %s: %d accepted, %d rejected, %d undecided", label, count(len(rep.Routes), "route", "routes"), rep.Accepted, rep.Rejected, rep.Undecided)
	for pos, c := range rep.Policy.Clauses {
		p.line("    clause %d (%s attribute %d): %s", pos+1, dir, c.Index+1, termText(dir, c.Term))
	}
	for _, u := range rep.Policy.Undecided {
		t := "the whole attribute"
		if u.Term.Peering != nil || u.Term.Filter != nil {
			t = termText(dir, u.Term)
		}
		p.line("    undecided term (%s attribute %d): %s: %s", dir, u.Index+1, t, u.Why)
	}
	if m := rep.Policy.Missing(); len(m) > 0 {
		p.line("    missing from the registry: %s", refs(m))
	}
	if rep.Unevaluable != "" {
		p.line("    policy not evaluable, no route decided: %s", rep.Unevaluable)
	}

	multiPeer := false
	for _, rv := range rep.Routes {
		if rv.Evidence.PeerAddr != rep.Routes[0].Evidence.PeerAddr {
			multiPeer = true
			break
		}
	}
	short := func(rv routecheck.RouteVerdict) string { return p.routeShort(rv, multiPeer) }

	// Rejected, by the first failing test of the first clause.
	var rej groups
	firstClause := 0 // the clause of the first Fail: the first clause, as verdict orders Fails
	for _, rv := range rep.Routes {
		if rv.Verdict.Outcome == verdict.Rejected && len(rv.Verdict.Fails) > 0 {
			f := rv.Verdict.Fails[0]
			if len(rej.keys) == 0 {
				firstClause = f.Clause
			}
			key := f.Test
			if len(f.Missing) > 0 {
				key += " (missing " + refs(f.Missing) + ")"
			}
			rej.add(key, short(rv))
		}
	}
	if len(rej.keys) > 0 {
		p.line("    rejected, by the first failing test of clause %d:", firstClause+1)
		p.groups(rej)
	}

	// Undecided, by reason.
	var und groups
	for _, rv := range rep.Routes {
		if rv.Verdict.Outcome != verdict.Undecided {
			continue
		}
		var seen []string
		for _, rs := range rv.Verdict.Reasons {
			key := rs.Kind
			if rs.Kind == verdict.ReasonPeval || rs.Kind == verdict.ReasonUnevaluable {
				key = rs.Kind + ": " + rs.Why
			}
			if !slices.Contains(seen, key) {
				seen = append(seen, key)
				und.add(key, short(rv))
			}
		}
	}
	if len(und.keys) > 0 {
		p.line("    undecided, by reason (a route may have several):")
		p.groups(und)
	}

	want := p.cfg.routes
	if want == "none" {
		return
	}
	p.line("    routes (%s):", want)
	for _, rv := range rep.Routes {
		o := rv.Verdict.Outcome
		if want == "all" || want == "rejected" && o == verdict.Rejected || want == "undecided" && o == verdict.Undecided {
			p.line("      %s  %s%s", short(rv), outcome(dir, rv.Verdict), hygiene(rv))
		}
	}
}

// groups holds routes by key, keys in first-seen order.
type groups struct {
	keys   []string
	routes map[string][]string
}

func (g *groups) add(key, route string) {
	if g.routes == nil {
		g.routes = map[string][]string{}
	}
	if _, ok := g.routes[key]; !ok {
		g.keys = append(g.keys, key)
	}
	g.routes[key] = append(g.routes[key], route)
}

// groups writes the groups, the largest first (then by key), each with up
// to maxExamples of its routes in prefix order.
func (p *printer) groups(g groups) {
	keys := slices.Clone(g.keys)
	slices.SortStableFunc(keys, func(a, b string) int {
		if d := len(g.routes[b]) - len(g.routes[a]); d != 0 {
			return d
		}
		return strings.Compare(a, b)
	})
	for _, k := range keys {
		rs := g.routes[k]
		p.line("      %s: %s", k, count(len(rs), "route", "routes"))
		for _, r := range rs[:min(len(rs), maxExamples)] {
			p.line("        %s", r)
		}
		if len(rs) > maxExamples {
			p.line("        and %d more", len(rs)-maxExamples)
		}
	}
}

// routeShort is a route's prefix, path and, in collector mode, whom it was
// seen announced to; in session mode with routes from several peer
// addresses, the one it came from.
func (p *printer) routeShort(rv routecheck.RouteVerdict, multiPeer bool) string {
	var b strings.Builder
	b.WriteString(rv.Route.Prefix.String())
	b.WriteString("  ")
	b.WriteString(pathText(rv.Route))
	e := rv.Evidence
	if p.cfg.mode == routecheck.ModeCollector {
		var parts []string
		if len(e.Neighbours) > 0 {
			ns := make([]string, len(e.Neighbours))
			for i, n := range e.Neighbours {
				ns[i] = n.String()
			}
			parts = append(parts, "to "+strings.Join(ns, " "))
		}
		if e.Direct {
			parts = append(parts, "direct feed")
		}
		parts = append(parts, count(e.CollectorPeers, "collector peer", "collector peers"))
		b.WriteString("  [" + strings.Join(parts, "; ") + "]")
	} else if multiPeer && e.PeerAddr != (netip.Addr{}) {
		b.WriteString("  [peer " + e.PeerAddr.String() + "]")
	}
	return b.String()
}

// pathText is a route's AS path as X announced it.
func pathText(r verdict.Route) string {
	ss := make([]string, len(r.Path))
	for i, a := range r.Path {
		ss[i] = a.String()
	}
	s := strings.Join(ss, " ")
	if s == "" {
		s = "(empty path)"
	}
	if !r.PathKnown {
		s += " (not a plain AS_SEQUENCE)"
	}
	return s
}

// outcome is a verdict and what decided it.
func outcome(dir string, v verdict.Verdict) string {
	switch v.Outcome {
	case verdict.Accepted:
		s := fmt.Sprintf("accepted by clause %d", v.Clause+1)
		if len(v.EarlierUndecided) > 0 {
			ns := make([]string, len(v.EarlierUndecided))
			for i, c := range v.EarlierUndecided {
				ns[i] = strconv.Itoa(c + 1)
			}
			s += ", after undecided clause " + strings.Join(ns, ", ")
		}
		for _, r := range v.Reasons {
			s += fmt.Sprintf(", after an undecided term (%s attribute %d: %s)", dir, r.Index+1, r.Why)
		}
		return s
	case verdict.Rejected:
		fs := make([]string, len(v.Fails))
		for i, f := range v.Fails {
			fs[i] = fmt.Sprintf("clause %d: %s", f.Clause+1, f.Test)
			if len(f.Missing) > 0 {
				fs[i] += " (missing " + refs(f.Missing) + ")"
			}
		}
		return "rejected: " + strings.Join(fs, "; ")
	case verdict.Undecided:
		rs := make([]string, len(v.Reasons))
		for i, r := range v.Reasons {
			switch r.Kind {
			case verdict.ReasonPeval:
				rs[i] = fmt.Sprintf("%s attribute %d: peval: %s", dir, r.Index+1, r.Why)
			case verdict.ReasonUnevaluable:
				rs[i] = "unevaluable: " + r.Why
			default:
				rs[i] = fmt.Sprintf("clause %d: %s (%s)", r.Clause+1, r.Kind, r.Term)
			}
		}
		return "undecided: " + strings.Join(rs, "; ")
	}
	return "no verdict"
}

// hygiene is a route's RPKI state and route-object answer, when known.
func hygiene(rv routecheck.RouteVerdict) string {
	s := ""
	if rv.RPKI != nil {
		s += "  rpki " + rv.RPKI.String()
	}
	if rv.RouteObj != nil {
		if *rv.RouteObj {
			s += "  route object yes"
		} else {
			s += "  route object no"
		}
	}
	return s
}

// termText writes a term as its attribute reads: "from PEERING accept
// FILTER" or "to PEERING announce FILTER", with rpsl's rendering of each
// part (policy.Term.String writes "PEERING | FILTER").
func termText(dir string, t policy.Term) string {
	peering, filter, _ := strings.Cut(t.String(), " | ")
	peering, filter = strings.TrimSpace(peering), strings.TrimSpace(filter)
	from, accept := "from ", " accept "
	if dir == "export" {
		from, accept = "to ", " announce "
	}
	s := ""
	if peering != "" {
		s = from + peering
	}
	if filter != "" {
		s = strings.TrimSpace(s + accept + filter)
	}
	return s
}

func refs(rs []types.SetRef) string {
	ss := make([]string, len(rs))
	for i, r := range rs {
		ss[i] = r.String()
	}
	return strings.Join(ss, ", ")
}

// hint writes, when a term was undecided for want of a router address, the
// capture's addresses as candidates for -local-rtr and -peer-rtr (spec §5:
// never taken from the capture, only offered).
func (p *printer) hint(results []routecheck.Result, cov routecheck.Coverage) {
	need := false
	for _, r := range results {
		for _, rep := range reports(r) {
			for _, u := range rep.Policy.Undecided {
				need = need || u.Why == peval.WhyLocalRouter || u.Why == peval.WhyPeerRouter
			}
		}
	}
	if !need {
		return
	}
	p.line("")
	if cov.HintLocalAddr.IsValid() || cov.HintPeerAddr.IsValid() {
		p.line("hint: a peering names a router and the session's routers were not given; if the capture's")
		p.line("  addresses are those routers, pass -local-rtr %s -peer-rtr %s", addrText(cov.HintLocalAddr), addrText(cov.HintPeerAddr))
		return
	}
	p.line("hint: a peering names a router and the session's routers were not given: pass -local-rtr and -peer-rtr")
}

func addrText(a netip.Addr) string {
	if !a.IsValid() {
		return "(unknown)"
	}
	return a.String()
}
