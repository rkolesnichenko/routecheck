package routecheck_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/rkolesnichenko/mrt"
	"github.com/rkolesnichenko/mrt/bgp"
	"github.com/rkolesnichenko/routecheck"
	"github.com/rkolesnichenko/routecheck/internal/mrtgen"
	"github.com/rkolesnichenko/routecheck/observe"
	"github.com/rkolesnichenko/routecheck/verdict"
	"github.com/rkolesnichenko/rpsl/object"
	"github.com/rkolesnichenko/rpsl/resolve"
	"github.com/rkolesnichenko/rpsl/resolve/peval"
	"github.com/rkolesnichenko/rpsl/resolve/rpki"
	"github.com/rkolesnichenko/rpsl/types"
)

// The session under test: L (AS64496) at localAddr, X (AS64500) at
// peerAddr; Y and Z originate routes behind X; N1 and N2 are X's other
// neighbours, seen at a collector.
const (
	asL  bgp.ASN = 64496
	asX  bgp.ASN = 64500
	asY  bgp.ASN = 64501
	asZ  bgp.ASN = 64502
	asN1 bgp.ASN = 64510
	asN2 bgp.ASN = 64511
)

var (
	peerAddr  = netip.MustParseAddr("192.0.2.1")
	localAddr = netip.MustParseAddr("192.0.2.2")
	nh4       = netip.MustParseAddr("192.0.2.1")
	nh6       = netip.MustParseAddr("2001:db8::1")
	t0        = time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)
	v4u       = bgp.Family{AFI: bgp.AFIIPv4, SAFI: bgp.SAFIUnicast}
	v4m       = bgp.Family{AFI: bgp.AFIIPv4, SAFI: bgp.SAFIMulticast}
	v6u       = bgp.Family{AFI: bgp.AFIIPv6, SAFI: bgp.SAFIUnicast}
)

// routes is the registry's route objects every test shares.
const routes = `route: 192.0.2.0/24
origin: AS64500
source: TEST

route: 192.0.2.128/25
origin: AS64500
source: TEST

route6: 2001:db8:1::/48
origin: AS64500
source: TEST

route: 198.51.100.0/24
origin: AS64501
source: TEST
`

// autL is L's usual policy: two v4 clauses (X's routes; a path through X
// to Y), X's routes over IPv6, and anything over IPv4 multicast.
const autL = `aut-num: AS64496
as-name: L
import: from AS64500 accept AS64500
import: from AS64500 accept <^AS64500 AS64501$>
mp-import: afi ipv6.unicast from AS64500 accept AS64500
mp-import: afi ipv4.multicast from AS64500 accept ANY
source: TEST
`

// autX is X's usual policy: its own routes to L and to N1, none to N2.
const autX = `aut-num: AS64500
as-name: X
export: to AS64496 announce AS64500
mp-export: afi ipv6.unicast to AS64496 announce AS64500
export: to AS64510 announce AS64500
source: TEST
`

// registry loads the route objects and the given aut-nums (and any other
// objects) into a policy-serving MemSource.
func registry(t testing.TB, objs ...string) *resolve.MemSource {
	t.Helper()
	l := &resolve.DumpLoader{KeepPolicy: true}
	if err := l.Read(strings.NewReader(strings.Join(append([]string{routes}, objs...), "\n"))); err != nil {
		t.Fatal(err)
	}
	return l.Source()
}

func checker(src *resolve.MemSource) *routecheck.Checker {
	return &routecheck.Checker{Eval: peval.Evaluator{Src: src}, Routes: src}
}

func at(sec int) time.Time { return t0.Add(time.Duration(sec) * time.Second) }

func pfx(s string) netip.Prefix { return netip.MustParsePrefix(s) }

func nlri(ps ...string) []bgp.NLRI {
	var out []bgp.NLRI
	for _, p := range ps {
		out = append(out, bgp.NLRI{Prefix: pfx(p)})
	}
	return out
}

func af(t testing.TB, s string) types.AddrFamily {
	t.Helper()
	a, err := types.ParseAddrFamily(s)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// attrs4 is a well-formed attribute block for IPv4 NLRI with the AS path
// segs and the given communities.
func attrs4(segs []bgp.Segment, comms ...bgp.Community) []byte {
	b := slices.Concat(mrtgen.Origin(bgp.OriginIGP), mrtgen.ASPath(true, segs...), mrtgen.NextHop(nh4))
	if len(comms) > 0 {
		b = append(b, mrtgen.Communities(comms...)...)
	}
	return b
}

func seq(asns ...bgp.ASN) []bgp.Segment { return []bgp.Segment{mrtgen.Seq(asns...)} }

// mp is an attribute block carrying nlri in MP_REACH_NLRI for fam.
func mp(fam bgp.Family, path []bgp.ASN, ps ...string) []byte {
	nh := nh4
	if fam.AFI == bgp.AFIIPv6 {
		nh = nh6
	}
	return slices.Concat(mrtgen.Origin(bgp.OriginIGP), mrtgen.ASPath(true, mrtgen.Seq(path...)),
		mrtgen.MPReach(fam, []netip.Addr{nh}, nlri(ps...), false))
}

// upd is an UPDATE X sent L (4-byte ASNs, no add-path).
func upd(ts time.Time, announced []bgp.NLRI, attrs []byte) []byte {
	st := mrt.SubMessageAS4
	return mrtgen.Header(mrt.TypeBGP4MP, st, ts,
		mrtgen.BGP4MP(st, asX, asL, peerAddr, localAddr, mrtgen.Update(nil, announced, attrs, false)))
}

func established(ts time.Time) []byte {
	st := mrt.SubStateChangeAS4
	return mrtgen.Header(mrt.TypeBGP4MP, st, ts,
		mrtgen.StateChange(st, asX, asL, peerAddr, localAddr, mrt.StateOpenConfirm, mrt.StateEstablished))
}

// capture is the session capture most tests use: from X, a route of X's
// own (accepted by clause 0), a path to Y (accepted by clause 1), a path to
// Z (rejected), a path ending in an AS_SET (undecided: clause 1's regexp
// cannot read it), and a path not starting with X (skipped, never decided).
func capture() [][]byte {
	return [][]byte{
		established(at(0)),
		upd(at(1), nlri("192.0.2.0/24"), attrs4(seq(asX))),
		upd(at(2), nlri("198.51.100.0/24"), attrs4(seq(asX, asY))),
		upd(at(3), nlri("203.0.113.0/24"), attrs4(seq(asX, asZ))),
		upd(at(4), nlri("10.0.0.0/8"), attrs4([]bgp.Segment{mrtgen.Seq(asX), mrtgen.Set(asY, asZ)})),
		upd(at(5), nlri("10.1.0.0/16"), attrs4(seq(asY, asX))),
	}
}

// pitRec, ribRec and ent build collector-mode RIB dumps.
var collectorID = netip.MustParseAddr("192.0.2.254")

func cpeer(n byte, as bgp.ASN) mrt.Peer {
	a := netip.AddrFrom4([4]byte{198, 51, 100, n})
	return mrt.Peer{BGPID: a, Addr: a, AS: as}
}

func pitRec(ts time.Time, peers ...mrt.Peer) []byte {
	return mrtgen.Header(mrt.TypeTableDumpV2, mrt.SubPeerIndexTable, ts, mrtgen.PeerIndexTable(collectorID, "", peers))
}

func ribRec(ts time.Time, p string, entries ...mrtgen.Entry) []byte {
	st := mrt.SubRIBIPv4Unicast
	return mrtgen.Header(mrt.TypeTableDumpV2, st, ts, mrtgen.RIB(st, 0, pfx(p), entries))
}

func ent(peer uint16, path ...bgp.ASN) mrtgen.Entry {
	return mrtgen.Entry{PeerIndex: peer, Originated: at(-100), Attrs: attrs4(seq(path...))}
}

func records(recs [][]byte) func(func(mrt.Record, error) bool) {
	return mrt.Records(bytes.NewReader(slices.Concat(recs...)))
}

func run(t *testing.T, c *routecheck.Checker, mode routecheck.Mode, recs [][]byte, o routecheck.Options) []routecheck.Result {
	t.Helper()
	res, err := c.Check(context.Background(), mode, records(recs), o)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	return res
}

// summary is a route verdict as "prefix outcome", the outcome followed by
// the accepting clause's Pos or the reasons' kinds.
func summary(rv routecheck.RouteVerdict) string {
	s := rv.Route.Prefix.String() + " "
	v := rv.Verdict
	switch v.Outcome {
	case verdict.Accepted:
		s += "accepted:" + string(rune('0'+v.Clause))
	case verdict.Rejected:
		s += "rejected"
	case verdict.Undecided:
		s += "undecided"
		for _, r := range v.Reasons {
			s += ":" + r.Kind
			if r.Why != "" {
				s += "(" + r.Why + ")"
			}
		}
	default:
		s += "none"
	}
	return s
}

func summaries(rep routecheck.Report) []string {
	var out []string
	for _, rv := range rep.Routes {
		out = append(out, summary(rv))
	}
	return out
}

// checkCounts checks the report's counts against its routes.
func checkCounts(t *testing.T, name string, rep routecheck.Report, acc, rej, und int) {
	t.Helper()
	if rep.Accepted != acc || rep.Rejected != rej || rep.Undecided != und {
		t.Errorf("%s: counts %d/%d/%d, want %d/%d/%d", name, rep.Accepted, rep.Rejected, rep.Undecided, acc, rej, und)
	}
	if n := rep.Accepted + rep.Rejected + rep.Undecided; n != len(rep.Routes) {
		t.Errorf("%s: counts sum to %d, %d routes", name, n, len(rep.Routes))
	}
}

func TestCheckSessionImport(t *testing.T) {
	c := checker(registry(t, autL, autX))
	// Local is not given: it comes from the capture (R13a).
	res := run(t, c, routecheck.ModeSession, capture(), routecheck.Options{
		Peer: types.ASN(asX), AF: []types.AddrFamily{af(t, "ipv4.unicast")}, Directions: routecheck.DirImport,
	})
	if len(res) != 1 || res[0].AF != af(t, "ipv4.unicast") {
		t.Fatalf("results: %+v", res)
	}
	r := res[0]
	if r.Export != nil {
		t.Errorf("Export = %+v, want nil (not asked)", r.Export)
	}
	imp := r.Import
	if imp == nil {
		t.Fatal("Import is nil")
	}
	if imp.Toward != types.ASN(asX) || imp.NoPolicy || len(imp.Policy.Clauses) != 2 {
		t.Errorf("Toward %v, NoPolicy %v, %d clauses", imp.Toward, imp.NoPolicy, len(imp.Policy.Clauses))
	}
	want := []string{
		"10.0.0.0/8 undecided:" + verdict.ReasonPathNotSequence,
		"192.0.2.0/24 accepted:0",
		"198.51.100.0/24 accepted:1",
		"203.0.113.0/24 rejected",
	}
	if got := summaries(*imp); !slices.Equal(got, want) {
		t.Errorf("routes:\n got %q\nwant %q", got, want)
	}
	checkCounts(t, "import", *imp, 2, 1, 1)
	// A rejected route names each clause's first failing test.
	if f := imp.Routes[3].Verdict.Fails; len(f) != 2 || f[0].Test != verdict.FailPrefixNotIn || !strings.Contains(f[1].Test, "AS64501") {
		t.Errorf("203.0.113.0/24 fails: %+v", f)
	}
	// Evidence and the route are observe's.
	if rv := imp.Routes[1]; !rv.Evidence.Time.Equal(at(1)) || rv.Evidence.PeerAddr != peerAddr ||
		!slices.Equal(rv.Route.Path, []types.ASN{types.ASN(asX)}) || !rv.Route.CommsKnown {
		t.Errorf("192.0.2.0/24: %+v", rv)
	}
	cov := r.Coverage
	if cov.Session == nil || cov.Collector != nil || cov.Session.NotFirstAS != 1 || cov.Session.LocalAS != types.ASN(asL) {
		t.Errorf("coverage: %+v / %+v", cov, cov.Session)
	}
	if cov.HintLocalAddr != localAddr || cov.HintPeerAddr != peerAddr || cov.OtherFamilies != 0 || cov.DirectNotChecked != 0 {
		t.Errorf("coverage: %+v", cov)
	}

	// A capture with no selected record names no local AS: Local must be given.
	// Both post-drain Local errors are option errors (ErrOptions), not run
	// failures.
	_, err := c.Check(context.Background(), routecheck.ModeSession, records(nil), routecheck.Options{Peer: types.ASN(asX)})
	if !errors.Is(err, routecheck.ErrOptions) || !strings.Contains(fmt.Sprint(err), "names no local AS (it holds no record of a session with AS64500)") {
		t.Errorf("no Local and no capture: %v, want ErrOptions", err)
	}
	// A capture whose local AS is X itself (an internal session).
	ibgp := mrtgen.Header(mrt.TypeBGP4MP, mrt.SubMessageAS4, at(1), mrtgen.BGP4MP(mrt.SubMessageAS4, asX, asX, peerAddr, localAddr,
		mrtgen.Update(nil, nlri("192.0.2.0/24"), attrs4(seq(asX)), false)))
	_, err = c.Check(context.Background(), routecheck.ModeSession, records([][]byte{ibgp}), routecheck.Options{Peer: types.ASN(asX)})
	if !errors.Is(err, routecheck.ErrOptions) || !strings.Contains(fmt.Sprint(err), "is the peer") {
		t.Errorf("capture's local AS is the peer: %v, want ErrOptions", err)
	}
	// With Local given, an empty capture is an empty report.
	res = run(t, c, routecheck.ModeSession, nil, routecheck.Options{Local: types.ASN(asL), Peer: types.ASN(asX), Directions: routecheck.DirImport})
	if len(res) != 2 || res[0].Import == nil || len(res[0].Import.Routes) != 0 || res[0].Import.NoPolicy {
		t.Errorf("empty capture: %+v", res)
	}
}

func TestCheckSessionExport(t *testing.T) {
	c := checker(registry(t, autL, autX))
	res := run(t, c, routecheck.ModeSession, capture(), routecheck.Options{
		Local: types.ASN(asL), Peer: types.ASN(asX), AF: []types.AddrFamily{af(t, "ipv4.unicast")}, Directions: routecheck.DirExport,
	})
	if len(res) != 1 || res[0].Import != nil || len(res[0].Export) != 1 {
		t.Fatalf("results: %+v", res)
	}
	exp := res[0].Export[0]
	if exp.Toward != types.ASN(asL) || exp.NoPolicy || len(exp.Policy.Clauses) != 1 {
		t.Errorf("Toward %v, NoPolicy %v, %d clauses", exp.Toward, exp.NoPolicy, len(exp.Policy.Clauses))
	}
	// X registers 192.0.2.0/24 (and a /25 it does not announce); every route
	// originated elsewhere is announced beyond X's registered policy.
	want := []string{"10.0.0.0/8 rejected", "192.0.2.0/24 accepted:0", "198.51.100.0/24 rejected", "203.0.113.0/24 rejected"}
	if got := summaries(exp); !slices.Equal(got, want) {
		t.Errorf("routes:\n got %q\nwant %q", got, want)
	}
	checkCounts(t, "export", exp, 1, 3, 0)

	// Both directions (the zero Directions) give both reports.
	res = run(t, c, routecheck.ModeSession, capture(), routecheck.Options{
		Local: types.ASN(asL), Peer: types.ASN(asX), AF: []types.AddrFamily{af(t, "ipv4.unicast")},
	})
	if len(res) != 1 || res[0].Import == nil || len(res[0].Export) != 1 {
		t.Fatalf("both directions: %+v", res)
	}
}

func TestCheckCollectorExportPerNeighbour(t *testing.T) {
	c := checker(registry(t, autL, autX))
	recs := [][]byte{
		pitRec(at(0), cpeer(1, asN2), cpeer(2, asN1), cpeer(3, asX)),
		// X's own route, seen announced to N1 and N2 and on X's direct feed.
		ribRec(at(0), "192.0.2.0/24", ent(0, asN2, asX), ent(1, asN1, asX), ent(2, asX)),
		// a route to Y, seen announced to N1 only
		ribRec(at(0), "198.51.100.0/24", ent(1, asN1, asX, asY)),
		// a route to Z on the direct feed only
		ribRec(at(0), "203.0.113.0/24", ent(2, asX, asZ)),
	}
	res := run(t, c, routecheck.ModeCollector, recs, routecheck.Options{
		Local: types.ASN(asL), Peer: types.ASN(asX), AF: []types.AddrFamily{af(t, "ipv4.unicast")},
	})
	if len(res) != 1 {
		t.Fatalf("results: %+v", res)
	}
	r := res[0]
	// Import is decided over every observation.
	if r.Import == nil || r.Import.Toward != types.ASN(asX) {
		t.Fatalf("Import: %+v", r.Import)
	}
	// Communities are unknown at a collector, but L's clauses test none.
	if got, want := summaries(*r.Import), []string{"192.0.2.0/24 accepted:0", "198.51.100.0/24 accepted:1", "203.0.113.0/24 rejected"}; !slices.Equal(got, want) {
		t.Errorf("import routes:\n got %q\nwant %q", got, want)
	}
	checkCounts(t, "import", *r.Import, 2, 1, 0)

	// Export: one Report per neighbour, by AS.
	if len(r.Export) != 2 {
		t.Fatalf("Export: %d reports, want 2: %+v", len(r.Export), r.Export)
	}
	n1, n2 := r.Export[0], r.Export[1]
	if n1.Toward != types.ASN(asN1) || n2.Toward != types.ASN(asN2) {
		t.Fatalf("Export toward %v, %v; want N1, N2", n1.Toward, n2.Toward)
	}
	if got, want := summaries(n1), []string{"192.0.2.0/24 accepted:0", "198.51.100.0/24 rejected"}; !slices.Equal(got, want) || n1.NoPolicy {
		t.Errorf("toward N1:\n got %q\nwant %q", got, want)
	}
	checkCounts(t, "toward N1", n1, 1, 1, 0)
	// X has no term for N2: NoPolicy, not a reject of every route.
	if !n2.NoPolicy || n2.Routes != nil || len(n2.Policy.Clauses) != 0 || len(n2.Policy.Undecided) != 0 {
		t.Errorf("toward N2: %+v", n2)
	}
	checkCounts(t, "toward N2", n2, 0, 0, 0)

	cov := r.Coverage
	// Two observations were seen on X's direct feed; that sighting is not
	// checked for export (the first is still checked toward N1 and N2).
	if cov.DirectNotChecked != 2 || cov.Collector == nil || cov.Session != nil {
		t.Errorf("coverage: %+v", cov)
	}
	if cov.HintLocalAddr.IsValid() || cov.HintPeerAddr.IsValid() {
		t.Errorf("collector mode has hint addresses: %+v", cov)
	}
	if cov.Collector.Direct != 2 || cov.Collector.Through != 5 {
		t.Errorf("collector info: %+v", *cov.Collector)
	}

	// Export only: Local is not needed.
	res = run(t, c, routecheck.ModeCollector, recs, routecheck.Options{
		Peer: types.ASN(asX), AF: []types.AddrFamily{af(t, "ipv4.unicast")}, Directions: routecheck.DirExport,
	})
	if len(res) != 1 || res[0].Import != nil || len(res[0].Export) != 2 {
		t.Errorf("export only: %+v", res)
	}
	// Import only: no export reports, and the direct feed is not counted.
	res = run(t, c, routecheck.ModeCollector, recs, routecheck.Options{
		Local: types.ASN(asL), Peer: types.ASN(asX), AF: []types.AddrFamily{af(t, "ipv4.unicast")}, Directions: routecheck.DirImport,
	})
	if len(res) != 1 || res[0].Import == nil || res[0].Export != nil || res[0].Coverage.DirectNotChecked != 0 {
		t.Errorf("import only: %+v", res)
	}
}

func TestCheckNoPolicy(t *testing.T) {
	// L registers a term for another AS only, X none toward L.
	c := checker(registry(t, `aut-num: AS64496
as-name: L
import: from AS64999 accept ANY
source: TEST
`, `aut-num: AS64500
as-name: X
export: to AS64999 announce ANY
source: TEST
`))
	res := run(t, c, routecheck.ModeSession, capture(), routecheck.Options{
		Local: types.ASN(asL), Peer: types.ASN(asX), AF: []types.AddrFamily{af(t, "ipv4.unicast")},
	})
	if len(res) != 1 {
		t.Fatalf("results: %+v", res)
	}
	for name, rep := range map[string]*routecheck.Report{"import": res[0].Import, "export": &res[0].Export[0]} {
		if rep == nil || !rep.NoPolicy || rep.Routes != nil || rep.Accepted+rep.Rejected+rep.Undecided != 0 {
			t.Errorf("%s: %+v", name, rep)
		}
	}
	if res[0].Import.Toward != types.ASN(asX) || res[0].Export[0].Toward != types.ASN(asL) {
		t.Errorf("Toward: %v, %v", res[0].Import.Toward, res[0].Export[0].Toward)
	}
}

func TestCheckFamilies(t *testing.T) {
	c := checker(registry(t, autL, autX))
	recs := [][]byte{
		established(at(0)),
		upd(at(1), nlri("192.0.2.0/24"), attrs4(seq(asX))),
		// IPv4 unicast in MP_REACH_NLRI: still ipv4.unicast
		upd(at(2), nil, mp(v4u, []bgp.ASN{asX, asY}, "198.51.100.0/24")),
		upd(at(3), nil, mp(v6u, []bgp.ASN{asX}, "2001:db8:1::/48")),
		// IPv4 multicast: L accepts anything there, and its unicast policy
		// would reject this prefix
		upd(at(4), nil, mp(v4m, []bgp.ASN{asX, asZ}, "203.0.113.0/24")),
	}
	o := routecheck.Options{Local: types.ASN(asL), Peer: types.ASN(asX), Directions: routecheck.DirImport}
	type want struct {
		af     string
		routes []string
	}
	v4 := want{"ipv4.unicast", []string{"192.0.2.0/24 accepted:0", "198.51.100.0/24 accepted:1"}}
	v6 := want{"ipv6.unicast", []string{"2001:db8:1::/48 accepted:0"}}
	mc := want{"ipv4.multicast", []string{"203.0.113.0/24 accepted:" + string(rune('0'+multicastAnyPos(t, c)))}}
	tests := []struct {
		name  string
		afs   []string
		want  []want
		other int
	}{
		{"default: ipv4.unicast and ipv6.unicast", nil, []want{v4, v6}, 1},
		{"ipv4.unicast only", []string{"ipv4.unicast"}, []want{v4}, 2},
		{"in the order given", []string{"ipv6.unicast", "ipv4.multicast"}, []want{v6, mc}, 2},
		{"all four", []string{"ipv4.unicast", "ipv4.multicast", "ipv6.unicast", "ipv6.multicast"},
			[]want{v4, mc, v6, {"ipv6.multicast", nil}}, 0},
	}
	for _, tt := range tests {
		o := o
		o.AF = nil
		for _, s := range tt.afs {
			o.AF = append(o.AF, af(t, s))
		}
		res := run(t, c, routecheck.ModeSession, recs, o)
		if len(res) != len(tt.want) {
			t.Fatalf("%s: %d results, want %d", tt.name, len(res), len(tt.want))
		}
		for i, w := range tt.want {
			r := res[i]
			if r.AF != af(t, w.af) {
				t.Errorf("%s: result %d is %v, want %s", tt.name, i, r.AF, w.af)
				continue
			}
			if got := summaries(*r.Import); !slices.Equal(got, w.routes) {
				t.Errorf("%s, %s:\n got %q\nwant %q", tt.name, w.af, got, w.routes)
			}
			if r.Coverage.OtherFamilies != tt.other {
				t.Errorf("%s, %s: OtherFamilies %d, want %d", tt.name, w.af, r.Coverage.OtherFamilies, tt.other)
			}
		}
	}
}

// multicastAnyPos is the Pos of L's "accept ANY" clause over ipv4.multicast:
// whether the plain import: terms also apply there is peval's to say.
func multicastAnyPos(t *testing.T, c *routecheck.Checker) int {
	t.Helper()
	p, err := c.Eval.Import(context.Background(), peval.Session{Local: types.ASN(asL), Peer: types.ASN(asX), AF: af(t, "ipv4.multicast")})
	if err != nil {
		t.Fatal(err)
	}
	for i, cl := range p.Clauses {
		if fmt.Sprint(cl.Term.Filter) == "ANY" {
			return i
		}
	}
	t.Fatalf("no ANY clause over ipv4.multicast: %+v", p.Clauses)
	return -1
}

func TestCheckCompilesOncePerReport(t *testing.T) {
	// L has no IPv6 term here, so of four reports three have a policy.
	c := checker(registry(t, `aut-num: AS64496
as-name: L
import: from AS64500 accept AS64500
source: TEST
`, autX))
	recs := [][]byte{established(at(0))}
	for i := range 300 {
		p := netip.PrefixFrom(netip.AddrFrom4([4]byte{10, byte(i >> 8), byte(i), 0}), 24)
		recs = append(recs, upd(at(1), nlri(p.String()), attrs4(seq(asX, asY))))
	}
	recs = append(recs, upd(at(2), nil, mp(v6u, []bgp.ASN{asX}, "2001:db8:1::/48")))
	before := routecheck.Compiles()
	res := run(t, c, routecheck.ModeSession, recs, routecheck.Options{Local: types.ASN(asL), Peer: types.ASN(asX)})
	compiles := routecheck.Compiles() - before
	withPolicy := 0
	for _, r := range res {
		for _, rep := range append([]routecheck.Report{*r.Import}, r.Export...) {
			if !rep.NoPolicy {
				withPolicy++
			}
		}
	}
	if withPolicy != 3 || compiles != 3 {
		t.Errorf("%d compiles for %d reports with a policy, want 3 and 3", compiles, withPolicy)
	}
	if n := len(res[0].Import.Routes); n != 300 {
		t.Errorf("%d v4 routes, want 300", n)
	}
}

func TestCheckRouterHint(t *testing.T) {
	// L's term names both routers; so does X's toward L, from X's side.
	c := checker(registry(t, `aut-num: AS64496
as-name: L
import: from AS64500 192.0.2.1 at 192.0.2.2 accept ANY
source: TEST
`, `aut-num: AS64500
as-name: X
export: to AS64496 192.0.2.2 at 192.0.2.1 announce AS64500
source: TEST
`))
	recs := capture()[:2]
	o := routecheck.Options{Local: types.ASN(asL), Peer: types.ASN(asX), AF: []types.AddrFamily{af(t, "ipv4.unicast")}}

	// No routers: both undecided, not NoPolicy; the capture's addresses are
	// the hint.
	res := run(t, c, routecheck.ModeSession, recs, o)
	r := res[0]
	if r.Import.NoPolicy || len(r.Import.Policy.Undecided) != 1 || len(r.Import.Policy.Clauses) != 0 {
		t.Fatalf("import policy: %+v", r.Import)
	}
	if got, want := summaries(*r.Import), []string{"192.0.2.0/24 undecided:peval(" + peval.WhyPeerRouter + ")"}; !slices.Equal(got, want) {
		t.Errorf("import, no routers: got %q, want %q", got, want)
	}
	if r.Coverage.HintLocalAddr != localAddr || r.Coverage.HintPeerAddr != peerAddr {
		t.Errorf("hints: %v, %v", r.Coverage.HintLocalAddr, r.Coverage.HintPeerAddr)
	}

	// Only X's router (PeerRtr): L's term lacks its local router; X's term,
	// read from X's side, has its own router (X's LocalRtr is PeerRtr) and
	// lacks L's (X's PeerRtr is LocalRtr).
	o.PeerRtr = peerAddr
	r = run(t, c, routecheck.ModeSession, recs, o)[0]
	if got, want := summaries(*r.Import), []string{"192.0.2.0/24 undecided:peval(" + peval.WhyLocalRouter + ")"}; !slices.Equal(got, want) {
		t.Errorf("import, PeerRtr only: got %q, want %q", got, want)
	}
	if got, want := summaries(r.Export[0]), []string{"192.0.2.0/24 undecided:peval(" + peval.WhyPeerRouter + ")"}; !slices.Equal(got, want) {
		t.Errorf("export, PeerRtr only: got %q, want %q", got, want)
	}
	// The hints are set whether or not the routers are given.
	if r.Coverage.HintLocalAddr != localAddr || r.Coverage.HintPeerAddr != peerAddr {
		t.Errorf("hints with PeerRtr: %v, %v", r.Coverage.HintLocalAddr, r.Coverage.HintPeerAddr)
	}

	// Both routers: both decided.
	o.LocalRtr = localAddr
	r = run(t, c, routecheck.ModeSession, recs, o)[0]
	if got := append(summaries(*r.Import), summaries(r.Export[0])...); !slices.Equal(got, []string{"192.0.2.0/24 accepted:0", "192.0.2.0/24 accepted:0"}) {
		t.Errorf("both routers: %q", got)
	}
	// Routers swapped: neither term covers the session.
	o.LocalRtr, o.PeerRtr = peerAddr, localAddr
	r = run(t, c, routecheck.ModeSession, recs, o)[0]
	if !r.Import.NoPolicy || !r.Export[0].NoPolicy {
		t.Errorf("wrong routers: import %+v, export %+v", r.Import, r.Export[0])
	}
}

func TestCheckPevalError(t *testing.T) {
	src := registry(t, `aut-num: AS64496
as-name: L
import: from AS64500 accept AS-BIG
source: TEST
`, autX, `as-set: AS-BIG
members: AS64500, AS64501
source: TEST
`)
	c := checker(src)
	c.Eval.Expander = resolve.Expander{MaxPrefixes: 1}
	res, err := c.Check(context.Background(), routecheck.ModeSession, records(capture()), routecheck.Options{
		Local: types.ASN(asL), Peer: types.ASN(asX),
	})
	var tooLarge *resolve.SetTooLargeError
	if !errors.As(err, &tooLarge) || errors.Is(err, routecheck.ErrOptions) || res != nil {
		t.Errorf("Check = %v, %v; want nil and a *resolve.SetTooLargeError", res, err)
	}
	// A missing aut-num is an error too, never a verdict.
	c = checker(registry(t, autL))
	res, err = c.Check(context.Background(), routecheck.ModeSession, records(capture()), routecheck.Options{
		Local: types.ASN(asL), Peer: types.ASN(asX), Directions: routecheck.DirExport,
	})
	if !errors.Is(err, resolve.ErrNotFound) || errors.Is(err, routecheck.ErrOptions) || res != nil {
		t.Errorf("missing aut-num: Check = %v, %v", res, err)
	}
}

// TestCheckUnevaluable pins ruling R19: a policy peval cannot evaluate
// because a filter names a set that reaches AS-ANY (a *resolve.AnySetError;
// in an AS-path regexp it would evaluate as any AS) gives that one
// report Undecided routes with the single reason "unevaluable", while the
// other direction decides as usual; any other peval error still fails the
// run.
func TestCheckUnevaluable(t *testing.T) {
	autLAny := `aut-num: AS64496
as-name: L
import: from AS64500 accept AS-ANYSET
source: TEST
`
	anySet := `as-set: AS-ANYSET
members: AS-ANY
source: TEST
`
	src := registry(t, autLAny, autX, anySet)
	o := routecheck.Options{Local: types.ASN(asL), Peer: types.ASN(asX), AF: []types.AddrFamily{af(t, "ipv4.unicast")}}
	res := run(t, checker(src), routecheck.ModeSession, capture(), o)
	imp := res[0].Import
	if imp.NoPolicy || len(imp.Policy.Clauses) != 0 || len(imp.Policy.Undecided) != 0 {
		t.Errorf("import: NoPolicy %v, policy %+v; want a report with an empty policy", imp.NoPolicy, imp.Policy)
	}
	checkCounts(t, "import", *imp, 0, 0, 4)
	if !strings.Contains(imp.Unevaluable, "AS-ANYSET") || !strings.Contains(imp.Unevaluable, "AS-ANY denotes") {
		t.Errorf("import: Unevaluable %q", imp.Unevaluable)
	}
	if u := res[0].Export[0].Unevaluable; u != "" {
		t.Errorf("export: Unevaluable %q, want empty", u)
	}
	for _, rv := range imp.Routes {
		v := rv.Verdict
		if v.Outcome != verdict.Undecided || len(v.Reasons) != 1 {
			t.Errorf("import, %s: %+v; want Undecided with one reason", rv.Route.Prefix, v)
			continue
		}
		r := v.Reasons[0]
		if r.Kind != "unevaluable" || !strings.Contains(r.Why, "AS-ANYSET") ||
			!strings.Contains(r.Why, "AS-ANY denotes") || r.Clause != -1 || r.Index != -1 || r.Term != "" {
			t.Errorf("import, %s: reason %+v", rv.Route.Prefix, r)
		}
		if rv.RouteObj == nil && rv.Route.Prefix != pfx("10.0.0.0/8") {
			t.Errorf("import, %s: hygiene not computed for an unevaluable report", rv.Route.Prefix)
		}
	}
	// X's export toward L is evaluable and decides as usual.
	want := []string{"10.0.0.0/8 rejected", "192.0.2.0/24 accepted:0", "198.51.100.0/24 rejected", "203.0.113.0/24 rejected"}
	if got := summaries(res[0].Export[0]); !slices.Equal(got, want) {
		t.Errorf("export: %v, want %v", got, want)
	}

	// Ruling R21: the other family. L's ipv6 import names the set and X sent
	// no ipv6 route: that report has no routes and still says it is
	// unevaluable, while ipv4, whose policy evaluates, decides as usual.
	autLv6 := `aut-num: AS64496
as-name: L
import: from AS64500 accept AS64500
mp-import: afi ipv6.unicast from AS64500 accept AS-ANYSET
source: TEST
`
	res = run(t, checker(registry(t, autLv6, autX, anySet)), routecheck.ModeSession, capture(), routecheck.Options{
		Local: types.ASN(asL), Peer: types.ASN(asX), Directions: routecheck.DirImport,
	})
	if len(res) != 2 || res[1].AF != af(t, "ipv6.unicast") {
		t.Fatalf("families: %+v", res)
	}
	v4, v6 := res[0].Import, res[1].Import
	if v4.Unevaluable != "" || len(v4.Policy.Clauses) == 0 {
		t.Errorf("ipv4: Unevaluable %q, %d clauses; want an evaluated policy", v4.Unevaluable, len(v4.Policy.Clauses))
	}
	if got, want := summaries(*v4), []string{"10.0.0.0/8 rejected", "192.0.2.0/24 accepted:0", "198.51.100.0/24 rejected", "203.0.113.0/24 rejected"}; !slices.Equal(got, want) {
		t.Errorf("ipv4: %v, want %v", got, want)
	}
	if !strings.Contains(v6.Unevaluable, "AS-ANYSET") || v6.NoPolicy || len(v6.Routes) != 0 || len(v6.Policy.Clauses) != 0 {
		t.Errorf("ipv6: Unevaluable %q, NoPolicy %v, %d routes, %d clauses; want unevaluable with no routes",
			v6.Unevaluable, v6.NoPolicy, len(v6.Routes), len(v6.Policy.Clauses))
	}
	checkCounts(t, "ipv6", *v6, 0, 0, 0)

	// Collector mode, export toward a neighbour: the same report shape.
	autXAny := `aut-num: AS64500
as-name: X
export: to AS64510 announce AS-ANYSET
source: TEST
`
	recs := [][]byte{pitRec(at(0), cpeer(1, asN1)), ribRec(at(0), "192.0.2.0/24", ent(0, asN1, asX))}
	res = run(t, checker(registry(t, autL, autXAny, anySet)), routecheck.ModeCollector, recs, routecheck.Options{
		Local: types.ASN(asL), Peer: types.ASN(asX), AF: []types.AddrFamily{af(t, "ipv4.unicast")},
	})
	if got := summaries(*res[0].Import); !slices.Equal(got, []string{"192.0.2.0/24 accepted:0"}) {
		t.Errorf("collector import: %v", got)
	}
	if len(res[0].Export) != 1 || len(res[0].Export[0].Routes) != 1 ||
		res[0].Export[0].Routes[0].Verdict.Reasons[0].Kind != verdict.ReasonUnevaluable {
		t.Errorf("collector export: %+v", res[0].Export)
	}

	// Any other error from peval's Source still fails the run: only an
	// *AnySetError is narrowed to Undecided.
	c := checker(src)
	c.Eval.Src = failingSets{src}
	res, err := c.Check(context.Background(), routecheck.ModeSession, records(capture()), o)
	var anyErr *resolve.AnySetError
	if !errors.Is(err, errSource) || errors.As(err, &anyErr) || res != nil {
		t.Errorf("failing GetSet: Check = %v, %v; want nil and the Source's error", res, err)
	}
}

// failingSets is a policy source whose GetSet fails.
type failingSets struct{ *resolve.MemSource }

func (failingSets) GetSet(context.Context, types.SetRef) (object.NamedSet, error) {
	return nil, errSource
}

// failing is a Source whose OriginatedRoutes fails.
type failing struct{ resolve.Source }

var errSource = errors.New("source down")

func (failing) OriginatedRoutes(context.Context, types.ASN, types.AFI) ([]netip.Prefix, error) {
	return nil, errSource
}

func TestCheckHygiene(t *testing.T) {
	src := registry(t, autL, autX)
	vrps, err := rpki.NewVRPs([]rpki.VRP{
		{Prefix: pfx("192.0.2.0/24"), MaxLength: 24, ASN: types.ASN(asX)},
		{Prefix: pfx("198.51.100.0/24"), MaxLength: 24, ASN: 64999},
		{Prefix: pfx("10.0.0.0/8"), MaxLength: 8, ASN: types.ASN(asZ)},
	})
	if err != nil {
		t.Fatal(err)
	}
	o := routecheck.Options{Local: types.ASN(asL), Peer: types.ASN(asX), AF: []types.AddrFamily{af(t, "ipv4.unicast")}, VRPs: vrps}
	res := run(t, checker(src), routecheck.ModeSession, capture(), o)
	type hyg struct {
		rpki string
		obj  string
	}
	show := func(rv routecheck.RouteVerdict) hyg {
		h := hyg{"nil", "nil"}
		if rv.RPKI != nil {
			h.rpki = rv.RPKI.String()
		}
		if rv.RouteObj != nil {
			h.obj = map[bool]string{true: "yes", false: "no"}[*rv.RouteObj]
		}
		return h
	}
	want := map[string]hyg{
		// an AS_SET origin: validated as AS0, never a route-object lookup
		"10.0.0.0/8":      {rpki.Invalid.String(), "nil"},
		"192.0.2.0/24":    {rpki.Valid.String(), "yes"},
		"198.51.100.0/24": {rpki.Invalid.String(), "yes"},
		"203.0.113.0/24":  {rpki.NotFound.String(), "no"},
	}
	for name, rep := range map[string]routecheck.Report{"import": *res[0].Import, "export": res[0].Export[0]} {
		if len(rep.Routes) != len(want) {
			t.Fatalf("%s: %d routes", name, len(rep.Routes))
		}
		for _, rv := range rep.Routes {
			if got := show(rv); got != want[rv.Route.Prefix.String()] {
				t.Errorf("%s, %s: %+v, want %+v", name, rv.Route.Prefix, got, want[rv.Route.Prefix.String()])
			}
		}
	}

	// No VRPs and no Routes: both nil.
	o.VRPs = nil
	c := checker(src)
	c.Routes = nil
	res = run(t, c, routecheck.ModeSession, capture(), o)
	for _, rv := range append(res[0].Import.Routes, res[0].Export[0].Routes...) {
		if rv.RPKI != nil || rv.RouteObj != nil {
			t.Errorf("%s: hygiene without data: %+v", rv.Route.Prefix, show(rv))
		}
	}

	// A Source error is an error for the run.
	c.Routes = failing{src}
	if res, err := c.Check(context.Background(), routecheck.ModeSession, records(capture()), o); !errors.Is(err, errSource) || res != nil {
		t.Errorf("failing Routes: Check = %v, %v", res, err)
	}
}

func TestCheckOptions(t *testing.T) {
	c := checker(registry(t, autL, autX))
	base := routecheck.Options{Local: types.ASN(asL), Peer: types.ASN(asX)}
	tests := []struct {
		name string
		mode routecheck.Mode
		edit func(*routecheck.Options)
	}{
		{"no mode", 0, func(*routecheck.Options) {}},
		{"unknown mode", 3, func(*routecheck.Options) {}},
		{"no Peer", routecheck.ModeSession, func(o *routecheck.Options) { o.Peer = 0 }},
		{"Local is Peer", routecheck.ModeSession, func(o *routecheck.Options) { o.Local = o.Peer }},
		{"unknown direction", routecheck.ModeSession, func(o *routecheck.Options) { o.Directions = 4 }},
		{"AF any", routecheck.ModeSession, func(o *routecheck.Options) { o.AF = []types.AddrFamily{af(t, "any")} }},
		{"AF ipv4", routecheck.ModeSession, func(o *routecheck.Options) { o.AF = []types.AddrFamily{af(t, "ipv4")} }},
		{"AF zero", routecheck.ModeSession, func(o *routecheck.Options) { o.AF = []types.AddrFamily{{}} }},
		{"AF twice", routecheck.ModeSession, func(o *routecheck.Options) {
			o.AF = []types.AddrFamily{af(t, "ipv4.unicast"), af(t, "ipv4.unicast")}
		}},
		{"collector: no Local for import", routecheck.ModeCollector, func(o *routecheck.Options) { o.Local = 0 }},
		{"collector: At", routecheck.ModeCollector, func(o *routecheck.Options) { o.At = at(0) }},
		{"collector: PeerAddr", routecheck.ModeCollector, func(o *routecheck.Options) { o.PeerAddr = peerAddr }},
		{"collector: PrePolicyRIB", routecheck.ModeCollector, func(o *routecheck.Options) { o.PrePolicyRIB = true }},
	}
	for _, tt := range tests {
		o := base
		tt.edit(&o)
		if res, err := c.Check(context.Background(), tt.mode, records(capture()), o); !errors.Is(err, routecheck.ErrOptions) || res != nil {
			t.Errorf("%s: Check = %v, %v; want an ErrOptions error", tt.name, res, err)
		}
	}
}

func TestCheckInputErrors(t *testing.T) {
	c := checker(registry(t, autL, autX))
	o := routecheck.Options{Local: types.ASN(asL), Peer: types.ASN(asX)}
	// A RIB dump in session mode without PrePolicyRIB.
	rib := [][]byte{pitRec(at(0), cpeer(1, asX)), ribRec(at(0), "192.0.2.0/24", ent(0, asX))}
	if res, err := c.Check(context.Background(), routecheck.ModeSession, records(rib), o); !errors.Is(err, observe.ErrRIBNotPrePolicy) || errors.Is(err, routecheck.ErrOptions) || res != nil {
		t.Errorf("RIB in session mode: Check = %v, %v", res, err)
	}
	// With it, the dump is X's Adj-RIB-In.
	o.PrePolicyRIB = true
	if res := run(t, c, routecheck.ModeSession, rib, o); len(res[0].Import.Routes) != 1 {
		t.Errorf("RIB with PrePolicyRIB: %+v", res[0].Import)
	}
	// A truncated stream.
	all := slices.Concat(capture()...)
	trunc := [][]byte{all[:len(all)-3]}
	if res, err := c.Check(context.Background(), routecheck.ModeSession, records(trunc), routecheck.Options{Local: types.ASN(asL), Peer: types.ASN(asX)}); err == nil || res != nil {
		t.Errorf("truncated: Check = %v, %v", res, err)
	}
}

func TestCheckContext(t *testing.T) {
	c := checker(registry(t, autL, autX))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	res, err := c.Check(ctx, routecheck.ModeSession, records(capture()), routecheck.Options{Local: types.ASN(asL), Peer: types.ASN(asX)})
	if !errors.Is(err, context.Canceled) || res != nil {
		t.Errorf("cancelled: Check = %v, %v", res, err)
	}
}

// counted passes recs on, calling at(n) before the nth record (from 1) and
// counting the records pulled.
func counted(recs [][]byte, at func(n int), pulled *int) func(func(mrt.Record, error) bool) {
	return func(yield func(mrt.Record, error) bool) {
		for rec, err := range records(recs) {
			*pulled++
			at(*pulled)
			if !yield(rec, err) {
				return
			}
		}
	}
}

// manyRoutes is a session capture of n routes from X to Y.
func manyRoutes(n int) [][]byte {
	recs := [][]byte{established(at(0))}
	for i := range n {
		p := netip.PrefixFrom(netip.AddrFrom4([4]byte{10, byte(i >> 8), byte(i), 0}), 24)
		recs = append(recs, upd(at(1), nlri(p.String()), attrs4(seq(asX, asY))))
	}
	return recs
}

func TestCheckCancelDuringRead(t *testing.T) {
	c := checker(registry(t, autL, autX))
	const n = 3 * 4096
	coll := [][]byte{pitRec(at(0), cpeer(1, asN1))}
	for i := range n {
		p := netip.PrefixFrom(netip.AddrFrom4([4]byte{10, byte(i >> 8), byte(i), 0}), 24)
		coll = append(coll, ribRec(at(0), p.String(), ent(0, asN1, asX, asY)))
	}
	for _, tt := range []struct {
		name string
		mode routecheck.Mode
		recs [][]byte
	}{
		{"session", routecheck.ModeSession, manyRoutes(n)},
		{"collector", routecheck.ModeCollector, coll},
	} {
		ctx, cancel := context.WithCancel(context.Background())
		pulled := 0
		res, err := c.Check(ctx, tt.mode, counted(tt.recs, func(k int) {
			if k == 10 {
				cancel()
			}
		}, &pulled), routecheck.Options{Local: types.ASN(asL), Peer: types.ASN(asX)})
		cancel()
		if !errors.Is(err, context.Canceled) || errors.Is(err, routecheck.ErrOptions) || res != nil {
			t.Errorf("%s: Check = %v, %v; want context.Canceled", tt.name, res, err)
		}
		// The read stops at the next check, not at the end of the input.
		if pulled > 4096 {
			t.Errorf("%s: %d of %d records read after the cancel at 10", tt.name, pulled, len(tt.recs))
		}
	}
}

// cancelling is a Source that cancels a context on its first
// OriginatedRoutes call, which only deciding makes.
type cancelling struct {
	resolve.Source
	cancel context.CancelFunc
}

func (s cancelling) OriginatedRoutes(ctx context.Context, as types.ASN, afi types.AFI) ([]netip.Prefix, error) {
	s.cancel()
	return s.Source.OriginatedRoutes(context.Background(), as, afi)
}

func TestCheckCancelDuringDecide(t *testing.T) {
	src := registry(t, autL, autX)
	c := checker(src)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c.Routes = cancelling{src, cancel}
	// One report, so no later per-report check can catch the cancel, and
	// every route of its own origin, so hygiene's cache (which reads ctx on
	// a hit) never answers: only the check every 4096 routes can.
	recs := [][]byte{established(at(0))}
	for i := range 3 * 4096 {
		p := netip.PrefixFrom(netip.AddrFrom4([4]byte{10, byte(i >> 8), byte(i), 0}), 24)
		recs = append(recs, upd(at(1), nlri(p.String()), attrs4(seq(asX, bgp.ASN(4200000000+i)))))
	}
	res, err := c.Check(ctx, routecheck.ModeSession, records(recs), routecheck.Options{
		Local: types.ASN(asL), Peer: types.ASN(asX), AF: []types.AddrFamily{af(t, "ipv4.unicast")}, Directions: routecheck.DirImport,
	})
	if !errors.Is(err, context.Canceled) || res != nil {
		t.Errorf("Check = %v, %v; want context.Canceled", res, err)
	}
}
