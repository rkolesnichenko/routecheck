package cli

import (
	"bytes"
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/rkolesnichenko/mrt"
	"github.com/rkolesnichenko/mrt/bgp"
	"github.com/rkolesnichenko/routecheck/internal/mrtgen"
)

// The tests run from the repository's root, so that the file names the
// command prints are the ones a user types there (testdata/...).
func TestMain(m *testing.M) {
	if err := os.Chdir(filepath.Join("..", "..")); err != nil {
		panic(err)
	}
	os.Exit(m.Run())
}

// update reports whether the goldens and the session fixtures are rewritten
// rather than compared.
func update() bool { return os.Getenv("ROUTECHECK_GOLDEN_UPDATE") == "1" }

// The golden session: AS64500 (X) at 192.0.2.1 and AS64496 (L) at 192.0.2.2.
const (
	gX  bgp.ASN = 64500
	gY  bgp.ASN = 64501
	gZ  bgp.ASN = 64502
	gL  bgp.ASN = 64496
	gNP bgp.ASN = 64511
)

var (
	gNH6 = addr("2001:db8::1")
	gT0  = time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)
)

func gAt(sec int) time.Time { return gT0.Add(time.Duration(sec) * time.Second) }

// gAttrs is a well-formed IPv4 attribute block with the path segs and the
// communities given.
func gAttrs(nh string, segs []bgp.Segment, comms ...bgp.Community) []byte {
	b := slices.Concat(mrtgen.Origin(bgp.OriginIGP), mrtgen.ASPath(true, segs...), mrtgen.NextHop(addr(nh)))
	if len(comms) > 0 {
		b = append(b, mrtgen.Communities(comms...)...)
	}
	return b
}

func gSeq(asns ...bgp.ASN) []bgp.Segment { return []bgp.Segment{mrtgen.Seq(asns...)} }

func gNLRI(ps ...string) []bgp.NLRI {
	var out []bgp.NLRI
	for _, p := range ps {
		out = append(out, bgp.NLRI{Prefix: prefix(p)})
	}
	return out
}

// gUpdate is an UPDATE peer sent local (4-byte ASNs, no add-path).
func gUpdate(ts time.Time, peerAS, localAS bgp.ASN, peer, local string, withdrawn, announced []bgp.NLRI, attrs []byte) []byte {
	st := mrt.SubMessageAS4
	return mrtgen.Header(mrt.TypeBGP4MP, st, ts,
		mrtgen.BGP4MP(st, peerAS, localAS, addr(peer), addr(local), mrtgen.Update(withdrawn, announced, attrs, false)))
}

// sessionGolden is testdata/session/golden.mrt: what AS64500 sent AS64496,
// with no transition to Established first (a capture that starts
// mid-session). Against testdata/irr/golden-policy.txt, L's import accepts
// 192.0.2.0/24 (clause 1) and 198.51.100.0/24 (clause 2), rejects the two
// AS64502 routes, and cannot decide 10.0.0.0/8 (an AS_SET in its path);
// 10.1.0.0/16 does not start with AS64500 and is skipped; 192.0.2.128/25 is
// announced and withdrawn; over IPv6, 2001:db8:1::/48 is accepted and
// 2001:db8:dead::/48 rejected.
func sessionGolden() []byte {
	x, l := "192.0.2.1", "192.0.2.2"
	upd := func(sec int, withdrawn, announced []bgp.NLRI, attrs []byte) []byte {
		return gUpdate(gAt(sec), gX, gL, x, l, withdrawn, announced, attrs)
	}
	v6 := func(sec int, path []bgp.ASN, p string) []byte {
		attrs := slices.Concat(mrtgen.Origin(bgp.OriginIGP), mrtgen.ASPath(true, mrtgen.Seq(path...)),
			mrtgen.MPReach(bgp.Family{AFI: bgp.AFIIPv6, SAFI: bgp.SAFIUnicast}, []netip.Addr{gNH6}, gNLRI(p), false))
		return upd(sec, nil, nil, attrs)
	}
	return slices.Concat(
		upd(1, nil, gNLRI("192.0.2.0/24"), gAttrs(x, gSeq(gX), bgp.Community(64500<<16|100))),
		upd(2, nil, gNLRI("198.51.100.0/24"), gAttrs(x, gSeq(gX, gY))),
		upd(3, nil, gNLRI("203.0.113.0/24", "203.0.113.128/25"), gAttrs(x, gSeq(gX, gZ))),
		upd(4, nil, gNLRI("10.0.0.0/8"), gAttrs(x, []bgp.Segment{mrtgen.Seq(gX), mrtgen.Set(gY, gZ)})),
		upd(5, nil, gNLRI("10.1.0.0/16"), gAttrs(x, gSeq(gY, gX))),
		upd(6, nil, gNLRI("192.0.2.128/25"), gAttrs(x, gSeq(gX))),
		upd(7, gNLRI("192.0.2.128/25"), nil, nil),
		v6(8, []bgp.ASN{gX}, "2001:db8:1::/48"),
		v6(9, []bgp.ASN{gX, gZ}, "2001:db8:dead::/48"),
	)
}

// sessionNoPolicy is testdata/session/nopolicy.mrt: AS64511's session with
// AS64496, from Established on, one route. golden-policy.txt has no import
// term from AS64511 and no export term of AS64511 toward AS64496.
func sessionNoPolicy() []byte {
	x, l := "192.0.2.5", "192.0.2.6"
	st := mrt.SubStateChangeAS4
	return slices.Concat(
		mrtgen.Header(mrt.TypeBGP4MP, st, gAt(0),
			mrtgen.StateChange(st, gNP, gL, addr(x), addr(l), mrt.StateOpenConfirm, mrt.StateEstablished)),
		gUpdate(gAt(1), gNP, gL, x, l, nil, gNLRI("192.0.2.0/24"), gAttrs(x, gSeq(gNP, gX))),
	)
}

// collectorFamilies is testdata/collector/families.mrt: a route collector's
// RIB dump over both unicast families, its peers AS64496 (L), AS64510 and
// AS64500 (X, its own feed). Over IPv4, X is seen announcing to AS64496
// (192.0.2.0/24, 203.0.113.0/24) and to AS64510 (192.0.2.0/24,
// 198.51.100.0/24), and on its own feed (192.0.2.0/24): against
// golden-policy.txt, X's export toward AS64496 is decided and toward AS64510
// is "no policy". Over IPv6, 2001:db8:1::/48 is seen on X's own feed only:
// no neighbour, so that family's export has no report.
func collectorFamilies() []byte {
	peers := []mrt.Peer{
		{BGPID: addr("198.51.100.1"), Addr: addr("198.51.100.1"), AS: gL},
		{BGPID: addr("198.51.100.2"), Addr: addr("198.51.100.2"), AS: 64510},
		{BGPID: addr("198.51.100.3"), Addr: addr("198.51.100.3"), AS: gX},
	}
	ent := func(peer uint16, path ...bgp.ASN) mrtgen.Entry {
		nh := peers[peer].Addr.String()
		return mrtgen.Entry{PeerIndex: peer, Originated: gAt(-100), Attrs: gAttrs(nh, gSeq(path...))}
	}
	rib := func(p string, es ...mrtgen.Entry) []byte {
		st := mrt.SubRIBIPv4Unicast
		return mrtgen.Header(mrt.TypeTableDumpV2, st, gAt(0), mrtgen.RIB(st, 0, prefix(p), es))
	}
	v6 := mrt.SubRIBIPv6Unicast
	direct6 := mrtgen.Entry{PeerIndex: 2, Originated: gAt(-100),
		Attrs: slices.Concat(mrtgen.Origin(bgp.OriginIGP), mrtgen.ASPath(true, mrtgen.Seq(gX)), mrtgen.MPReachAbbrev(gNH6))}
	return slices.Concat(
		mrtgen.Header(mrt.TypeTableDumpV2, mrt.SubPeerIndexTable, gAt(0), mrtgen.PeerIndexTable(addr("192.0.2.254"), "", peers)),
		rib("192.0.2.0/24", ent(0, gL, gX), ent(1, 64510, gX), ent(2, gX)),
		rib("198.51.100.0/24", ent(1, 64510, gX, gY)),
		rib("203.0.113.0/24", ent(0, gL, gX, gZ)),
		mrtgen.Header(mrt.TypeTableDumpV2, v6, gAt(0), mrtgen.RIB(v6, 1, prefix("2001:db8:1::/48"), []mrtgen.Entry{direct6})),
	)
}

// TestSessionFixtures holds the committed captures and RIB dumps to their
// generators.
func TestSessionFixtures(t *testing.T) {
	for name, data := range map[string][]byte{
		"testdata/session/golden.mrt":     sessionGolden(),
		"testdata/session/nopolicy.mrt":   sessionNoPolicy(),
		"testdata/collector/families.mrt": collectorFamilies(),
	} {
		checkFile(t, name, data)
	}
}

// goldens are the command lines TestGoldens runs, each once with -format text
// and once with -format json, and the exit status each must give.
var goldens = []struct {
	name string
	args []string
	exit int
}{
	{"session", []string{"-local", "AS64496", "-peer", "AS64500", "-session", "testdata/session/golden.mrt",
		"-dump", "testdata/irr/golden-policy.txt", "-vrps", "testdata/rpki/vrps.json", "-routes", "all"}, exitRejected},
	{"collector", []string{"-local", "AS64496", "-peer", "AS4766", "-collector", "testdata/mrt/rv2-rib.20261015.1200.gz",
		"-dump", "testdata/irr/golden-policy.txt", "-direction", "import", "-routes", "all"}, exitOK},
	{"nopolicy", []string{"-local", "AS64496", "-peer", "AS64511", "-session", "testdata/session/nopolicy.mrt",
		"-dump", "testdata/irr/golden-policy.txt"}, exitOK},
}

func TestGoldens(t *testing.T) {
	for _, g := range goldens {
		for _, format := range []string{"text", "json"} {
			ext := map[string]string{"text": "txt", "json": "json"}[format]
			t.Run(g.name+"."+ext, func(t *testing.T) {
				var stdout, stderr bytes.Buffer
				code := Run(context.Background(), append(slices.Clone(g.args), "-format", format), &stdout, &stderr)
				if code != g.exit {
					t.Errorf("exit %d, want %d; stderr:\n%s", code, g.exit, stderr.String())
				}
				if stderr.String() != noneNote {
					t.Errorf("stderr:\n%s\nwant only:\n%s", stderr.String(), noneNote)
				}
				checkFile(t, filepath.Join("testdata", "golden", g.name+"."+ext), stdout.Bytes())
			})
		}
	}
}

// streamGoldens are more command lines TestStreamingMatchesGoldens runs as
// TestGoldens runs its own: output that the command assembles from reports
// handed over one at a time (Checker.CheckEach) across several families.
var streamGoldens = []struct {
	name string
	args []string
	exit int
}{
	// Both families, both directions: IPv4 with an import report and two
	// export reports (one "no policy"), IPv6 with an import report and no
	// neighbour.
	{"families", []string{"-local", "AS64496", "-peer", "AS64500", "-collector", "testdata/collector/families.mrt",
		"-dump", "testdata/irr/golden-policy.txt", "-routes", "all"}, exitRejected},
}

func TestStreamingMatchesGoldens(t *testing.T) {
	for _, g := range streamGoldens {
		for _, format := range []string{"text", "json"} {
			ext := map[string]string{"text": "txt", "json": "json"}[format]
			t.Run(g.name+"."+ext, func(t *testing.T) {
				var stdout, stderr bytes.Buffer
				code := Run(context.Background(), append(slices.Clone(g.args), "-format", format), &stdout, &stderr)
				if code != g.exit {
					t.Errorf("exit %d, want %d; stderr:\n%s", code, g.exit, stderr.String())
				}
				if stderr.String() != noneNote {
					t.Errorf("stderr:\n%s\nwant only:\n%s", stderr.String(), noneNote)
				}
				checkFile(t, filepath.Join("testdata", "golden", g.name+"."+ext), stdout.Bytes())
			})
		}
	}
}

// checkFile compares got with the file name, or rewrites the file when
// ROUTECHECK_GOLDEN_UPDATE=1.
func checkFile(t *testing.T, name string, got []byte) {
	t.Helper()
	if update() {
		if err := os.WriteFile(filepath.FromSlash(name), got, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(filepath.FromSlash(name))
	if err != nil {
		t.Fatalf("%v (ROUTECHECK_GOLDEN_UPDATE=1 writes it)", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("%s differs (ROUTECHECK_GOLDEN_UPDATE=1 rewrites it; review the diff); got:\n%s", name, got)
	}
}
