package cli

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/rkolesnichenko/mrt"
	"github.com/rkolesnichenko/mrt/bgp"
	"github.com/rkolesnichenko/routecheck/internal/mrtgen"
	"github.com/rkolesnichenko/routecheck/verdict"
	"github.com/rkolesnichenko/rpsl"
	"github.com/rkolesnichenko/rpsl/resolve"
	"github.com/rkolesnichenko/rpsl/resolve/irrdq"
	"github.com/rkolesnichenko/rpsl/resolve/irrdserver"
)

func addr(s string) netip.Addr     { return netip.MustParseAddr(s) }
func prefix(s string) netip.Prefix { return netip.MustParsePrefix(s) }

// run runs the command and returns its exit status, stdout and stderr.
func run(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	return runCtx(t, context.Background(), args...)
}

func runCtx(t *testing.T, ctx context.Context, args ...string) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := Run(ctx, args, &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

// write writes data to a file named name in a new temporary directory and
// returns its path.
func write(t *testing.T, name string, data []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func gzipped(t *testing.T, data []byte) []byte {
	t.Helper()
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	if _, err := w.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// The usual inputs: the golden capture and registry.
const (
	capture  = "testdata/session/golden.mrt"
	registry = "testdata/irr/golden-policy.txt"
)

// session is the usual session command line, followed by more.
func session(more ...string) []string {
	return append([]string{"-local", "AS64496", "-peer", "AS64500", "-session", capture, "-dump", registry}, more...)
}

func wantContains(t *testing.T, label, got string, wants ...string) {
	t.Helper()
	for _, w := range wants {
		if !strings.Contains(got, w) {
			t.Errorf("%s does not contain %q:\n%s", label, w, got)
		}
	}
}

func TestHelp(t *testing.T) {
	code, stdout, stderr := run(t, "-h")
	if code != exitOK {
		t.Errorf("exit %d, want 0; stderr %s", code, stderr)
	}
	wantContains(t, "usage", stdout,
		"routecheck -local AS -peer AS (-session FILE | -collector FILE)",
		"-irrd", "-sources", "-policy", "-vrps", "-af", "-direction", "-peer-addr", "-at", "-pre-policy",
		"-local-rtr", "-peer-rtr", "-format", "-routes", "repeatable", "Exit status")
}

func TestBadCommandLines(t *testing.T) {
	rib := "testdata/mrt/rv2-rib.20261015.1200.gz"
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{"no -peer", []string{"-local", "AS64496", "-session", capture, "-dump", registry}, "-peer"},
		{"no -local, collector", []string{"-peer", "AS4766", "-collector", rib, "-dump", registry}, "-local"},
		{"both modes", session("-collector", rib), "-session or -collector"},
		{"no mode", []string{"-local", "AS64496", "-peer", "AS64500", "-dump", registry}, "-session or -collector"},
		{"no policy source", []string{"-local", "AS64496", "-peer", "AS64500", "-session", capture}, "-dump or -irrd"},
		{"both policy sources", session("-irrd", "127.0.0.1:43"), "-dump or -irrd"},
		{"local is peer", []string{"-local", "AS64500", "-peer", "AS64500", "-session", capture, "-dump", registry}, "differ"},
		{"pre-policy collector", []string{"-local", "AS64496", "-peer", "AS4766", "-collector", rib, "-dump", registry, "-pre-policy"}, "-pre-policy"},
		{"at collector", []string{"-local", "AS64496", "-peer", "AS4766", "-collector", rib, "-dump", registry, "-at", "2026-10-16T12:00:00Z"}, "-at"},
		{"peer-addr collector", []string{"-local", "AS64496", "-peer", "AS4766", "-collector", rib, "-dump", registry, "-peer-addr", "192.0.2.1"}, "-peer-addr"},
		{"unknown af", session("-af", "ipv5"), "-af"},
		{"unknown direction", session("-direction", "sideways"), "-direction"},
		{"unknown format", session("-format", "xml"), "-format"},
		{"unknown routes", session("-routes", "some"), "-routes"},
		{"bad AS", []string{"-local", "ASX", "-peer", "AS64500", "-session", capture, "-dump", registry}, "AS number"},
		{"bad time", session("-at", "noon"), "-at"},
		{"bad peer address", session("-peer-addr", "192.0.2"), "-peer-addr"},
		{"bad local router", session("-local-rtr", "x"), "-local-rtr"},
		{"bad peer router", session("-peer-rtr", "x"), "-peer-rtr"},
		{"sources without irrd", session("-sources", "TEST"), "-sources"},
		{"positional argument", session("extra.mrt"), "extra.mrt"},
		{"unknown flag", session("-frobnicate"), "frobnicate"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, stdout, stderr := run(t, tc.args...)
			if code != exitUsage {
				t.Errorf("exit %d, want %d; stderr %s", code, exitUsage, stderr)
			}
			if stdout != "" {
				t.Errorf("stdout %q, want nothing", stdout)
			}
			wantContains(t, "stderr", stderr, tc.want)
		})
	}
}

// TestLocalFromCapture: in session mode -local may be left out, and is the
// capture's local AS; a capture whose local AS is the peer is a bad command
// line, found only after reading it (routecheck.ErrOptions).
func TestLocalFromCapture(t *testing.T) {
	code, stdout, stderr := run(t, "-peer", "AS64500", "-session", capture, "-dump", registry, "-direction", "import")
	if code != exitRejected {
		t.Fatalf("exit %d, want %d; stderr %s", code, exitRejected, stderr)
	}
	wantContains(t, "stdout", stdout, "local AS from the capture: AS64496", "import, AS64496 from AS64500: 5 routes: 2 accepted, 2 rejected, 1 undecided")

	self := write(t, "self.mrt", gUpdate(gAt(1), gX, gX, "192.0.2.1", "192.0.2.2", nil, gNLRI("192.0.2.0/24"), gAttrs("192.0.2.1", gSeq(gX))))
	code, _, stderr = run(t, "-peer", "AS64500", "-session", self, "-dump", registry)
	if code != exitUsage {
		t.Errorf("capture's local AS is the peer: exit %d, want %d; stderr %s", code, exitUsage, stderr)
	}
	empty := write(t, "empty.mrt", nil)
	code, _, stderr = run(t, "-peer", "AS64500", "-session", empty, "-dump", registry)
	if code != exitUsage {
		t.Errorf("capture naming no local AS: exit %d, want %d; stderr %s", code, exitUsage, stderr)
	}
	wantContains(t, "stderr", stderr, "give -local")
}

func TestFailures(t *testing.T) {
	missingAutNum := write(t, "reg.txt", []byte("aut-num: AS64500\nexport: to AS64496 announce AS64500\nsource: TEST\n"))
	truncated := write(t, "cut.mrt", sessionGolden()[:len(sessionGolden())-7])
	rib := mrtgen.Header(mrt.TypeTableDumpV2, mrt.SubPeerIndexTable, gAt(0),
		mrtgen.PeerIndexTable(addr("192.0.2.254"), "", []mrt.Peer{{BGPID: addr("192.0.2.1"), Addr: addr("192.0.2.1"), AS: gX}}))
	ribFile := write(t, "rib.mrt", rib)
	badVRPs := write(t, "vrps.json", []byte(`{"roas": [{"asn": "AS1"}]}`))
	brokenGzip := write(t, "broken.mrt.gz", []byte{0x1f, 0x8b, 0, 0})
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{"missing dump", []string{"-local", "AS64496", "-peer", "AS64500", "-session", capture, "-dump", "testdata/irr/nonexistent.txt"}, "testdata/irr/nonexistent.txt"},
		{"missing policy file", session("-policy", "testdata/irr/nonexistent.txt"), "testdata/irr/nonexistent.txt"},
		{"missing capture", []string{"-local", "AS64496", "-peer", "AS64500", "-session", "testdata/session/nonexistent.mrt", "-dump", registry}, "testdata/session/nonexistent.mrt"},
		{"missing VRPs", session("-vrps", "testdata/rpki/nonexistent.json"), "testdata/rpki/nonexistent.json"},
		{"bad VRPs", session("-vrps", badVRPs), badVRPs},
		{"missing aut-num", []string{"-local", "AS64496", "-peer", "AS64500", "-session", capture, "-dump", missingAutNum}, "AS64496"},
		{"truncated capture", []string{"-local", "AS64496", "-peer", "AS64500", "-session", capture, "-session", truncated, "-dump", registry}, truncated},
		{"broken gzip", []string{"-local", "AS64496", "-peer", "AS64500", "-session", brokenGzip, "-dump", registry}, brokenGzip},
		{"RIB in session mode", []string{"-local", "AS64496", "-peer", "AS64500", "-session", ribFile, "-dump", registry}, "-pre-policy"},
		{"unreachable irrd", []string{"-local", "AS64496", "-peer", "AS64500", "-session", capture, "-irrd", closedPort(t)}, "routecheck:"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, stdout, stderr := run(t, tc.args...)
			if code != exitFailed {
				t.Errorf("exit %d, want %d; stderr %s", code, exitFailed, stderr)
			}
			if stdout != "" {
				t.Errorf("stdout %q, want nothing", stdout)
			}
			wantContains(t, "stderr", stderr, tc.want)
		})
	}
	// A truncated capture is named as such.
	_, _, stderr := run(t, "-local", "AS64496", "-peer", "AS64500", "-session", truncated, "-dump", registry)
	wantContains(t, "stderr", stderr, truncated+": ", "truncated")
}

// closedPort returns a localhost address nothing listens on: a port bound
// and released.
func closedPort(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	a := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}
	return a
}

// TestCancelled: a cancelled context ends the run with status 3.
func TestCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	code, _, stderr := runCtx(t, ctx, session()...)
	if code != exitFailed {
		t.Errorf("exit %d, want %d", code, exitFailed)
	}
	wantContains(t, "stderr", stderr, "context canceled")
}

// TestExitStatus: a Rejected route in either direction exits 1; Undecided
// routes alone exit 0.
func TestExitStatus(t *testing.T) {
	undecidedOnly := write(t, "undecided.mrt",
		gUpdate(gAt(1), gX, gL, "192.0.2.1", "192.0.2.2", nil, gNLRI("10.0.0.0/8"),
			gAttrs("192.0.2.1", []bgp.Segment{mrtgen.Seq(gX), mrtgen.Set(gY, gZ)})))
	accepted := write(t, "accepted.mrt",
		gUpdate(gAt(1), gX, gL, "192.0.2.1", "192.0.2.2", nil, gNLRI("192.0.2.0/24"), gAttrs("192.0.2.1", gSeq(gX))))
	exportRejects := write(t, "export.mrt",
		gUpdate(gAt(1), gX, gL, "192.0.2.1", "192.0.2.2", nil, gNLRI("198.51.100.0/24"), gAttrs("192.0.2.1", gSeq(gX, gY))))
	for _, tc := range []struct {
		name string
		args []string
		want int
	}{
		{"undecided only", []string{"-local", "AS64496", "-peer", "AS64500", "-session", undecidedOnly, "-dump", registry, "-direction", "import"}, exitOK},
		{"accepted", []string{"-local", "AS64496", "-peer", "AS64500", "-session", accepted, "-dump", registry}, exitOK},
		{"rejected by import", session("-direction", "import"), exitRejected},
		{"rejected by export only", []string{"-local", "AS64496", "-peer", "AS64500", "-session", exportRejects, "-dump", registry}, exitRejected},
		{"import accepts what export rejects", []string{"-local", "AS64496", "-peer", "AS64500", "-session", exportRejects, "-dump", registry, "-direction", "import"}, exitOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, _, stderr := run(t, tc.args...)
			if code != tc.want {
				t.Errorf("exit %d, want %d; stderr %s", code, tc.want, stderr)
			}
		})
	}
}

// TestFlags checks what each option changes in the output.
func TestFlags(t *testing.T) {
	t.Run("af", func(t *testing.T) {
		_, out, _ := run(t, session("-af", "ipv6")...)
		if strings.Contains(out, "ipv4.unicast") || !strings.Contains(out, "ipv6.unicast") {
			t.Errorf("-af ipv6:\n%s", out)
		}
		_, out, _ = run(t, session("-af", "ipv4")...)
		if !strings.Contains(out, "ipv4.unicast") || strings.Contains(out, "\nipv6.unicast") {
			t.Errorf("-af ipv4:\n%s", out)
		}
		wantContains(t, "-af ipv4", out, "2 routes in an address family not checked")
	})
	t.Run("direction", func(t *testing.T) {
		_, out, _ := run(t, session("-direction", "export")...)
		if strings.Contains(out, "import, ") || !strings.Contains(out, "export, AS64500 to AS64496") {
			t.Errorf("-direction export:\n%s", out)
		}
		_, out, _ = run(t, session("-direction", "import")...)
		if strings.Contains(out, "export, ") || !strings.Contains(out, "import, AS64496 from AS64500") {
			t.Errorf("-direction import:\n%s", out)
		}
	})
	t.Run("at", func(t *testing.T) {
		// At second 2 only 192.0.2.0/24 and 198.51.100.0/24 were announced.
		_, out, _ := run(t, session("-af", "ipv4", "-direction", "import", "-at", "2026-10-16T12:00:02Z")...)
		wantContains(t, "-at", out, "import, AS64496 from AS64500: 2 routes: 2 accepted, 0 rejected, 0 undecided")
		_, out, _ = run(t, session("-af", "ipv4", "-direction", "import", "-at", "2026-10-16T11:00:00Z")...)
		wantContains(t, "-at before the capture", out, "no record of the session at or before -at")
	})
	t.Run("peer-addr", func(t *testing.T) {
		_, out, _ := run(t, session("-af", "ipv4", "-direction", "import", "-peer-addr", "192.0.2.99")...)
		wantContains(t, "-peer-addr", out, "0 routes")
		_, out, _ = run(t, session("-af", "ipv4", "-direction", "import", "-peer-addr", "192.0.2.1")...)
		wantContains(t, "-peer-addr", out, "5 routes")
	})
	t.Run("pre-policy", func(t *testing.T) {
		peer := mrt.Peer{BGPID: addr("192.0.2.1"), Addr: addr("192.0.2.1"), AS: gX}
		rib := slices.Concat(
			mrtgen.Header(mrt.TypeTableDumpV2, mrt.SubPeerIndexTable, gAt(0), mrtgen.PeerIndexTable(addr("192.0.2.2"), "", []mrt.Peer{peer})),
			mrtgen.Header(mrt.TypeTableDumpV2, mrt.SubRIBIPv4Unicast, gAt(0), mrtgen.RIB(mrt.SubRIBIPv4Unicast, 0, prefix("192.0.2.0/24"),
				[]mrtgen.Entry{{PeerIndex: 0, Originated: gAt(-10), Attrs: gAttrs("192.0.2.1", gSeq(gX))}})))
		f := write(t, "adj-rib-in.mrt", rib)
		code, out, stderr := run(t, "-local", "AS64496", "-peer", "AS64500", "-session", f, "-dump", registry, "-pre-policy", "-af", "ipv4")
		if code != exitOK {
			t.Fatalf("exit %d; stderr %s", code, stderr)
		}
		wantContains(t, "-pre-policy", out, "import, AS64496 from AS64500: 1 route: 1 accepted, 0 rejected, 0 undecided")
	})
	t.Run("format json", func(t *testing.T) {
		code, out, stderr := run(t, session("-format", "json")...)
		if code != exitRejected {
			t.Fatalf("exit %d; stderr %s", code, stderr)
		}
		// The policies hold interfaces, which do not decode back; the
		// counts and the field names do.
		type report struct {
			Toward                        string
			Accepted, Rejected, Undecided int
		}
		var res []struct {
			AF       string
			Import   *report
			Export   []report
			Coverage map[string]any
		}
		if err := json.Unmarshal([]byte(out), &res); err != nil {
			t.Fatalf("not the JSON of []routecheck.Result: %v\n%s", err, out)
		}
		if len(res) != 2 || res[0].AF != "ipv4.unicast" || res[0].Import == nil || res[0].Import.Rejected != 2 || len(res[0].Export) != 1 ||
			res[0].Export[0].Toward != "AS64496" || res[1].Import.Accepted != 1 || res[0].Coverage["Session"] == nil {
			t.Errorf("results %+v", res)
		}
		if !strings.Contains(out, `"EarlierUndecided"`) || !strings.Contains(out, `"Coverage"`) {
			t.Errorf("JSON does not hold Go's field names:\n%.400s", out)
		}
	})
	t.Run("routes", func(t *testing.T) {
		base := session("-af", "ipv4", "-direction", "import")
		_, none, _ := run(t, base...)
		_, all, _ := run(t, append(slices.Clone(base), "-routes", "all")...)
		_, rej, _ := run(t, append(slices.Clone(base), "-routes", "rejected")...)
		_, und, _ := run(t, append(slices.Clone(base), "-routes", "undecided")...)
		line := func(out, p string) bool {
			for _, l := range strings.Split(out, "\n") {
				if strings.HasPrefix(strings.TrimSpace(l), p+"  ") && strings.Contains(l, " by clause ") {
					return true
				}
			}
			return false
		}
		// An accepted route appears only in the listing (-routes all).
		if line(none, "192.0.2.0/24") || !line(all, "192.0.2.0/24") || line(rej, "192.0.2.0/24") || line(und, "192.0.2.0/24") {
			t.Errorf("accepted route listed wrongly:\nnone:\n%s\nall:\n%s", none, all)
		}
		if strings.Contains(none, "routes (") || !strings.Contains(all, "  routes (all):") || !strings.Contains(rej, "  routes (rejected):") || !strings.Contains(und, "  routes (undecided):") {
			t.Errorf("listing headers:\nnone:\n%s\nrejected:\n%s\nundecided:\n%s", none, rej, und)
		}
	})
}

// TestRouterHint: a term whose peering names a router is undecided without
// -local-rtr/-peer-rtr, and the report gives the capture's addresses; with
// them it is decided.
func TestRouterHint(t *testing.T) {
	reg := write(t, "reg.txt", []byte(`aut-num: AS64496
import: from AS64500 192.0.2.1 at 192.0.2.2 accept AS64500
source: TEST

aut-num: AS64500
export: to AS64496 announce AS64500
source: TEST

route: 192.0.2.0/24
origin: AS64500
source: TEST
`))
	args := []string{"-local", "AS64496", "-peer", "AS64500", "-session", capture, "-dump", reg, "-af", "ipv4", "-direction", "import"}
	code, out, stderr := run(t, args...)
	if code != exitOK {
		t.Fatalf("exit %d; stderr %s", code, stderr)
	}
	wantContains(t, "stdout", out, "0 accepted, 0 rejected, 5 undecided", "peval: "+"peer router not given",
		"hint: ", "-local-rtr 192.0.2.2", "-peer-rtr 192.0.2.1")
	_, out, _ = run(t, append(args, "-local-rtr", "192.0.2.2", "-peer-rtr", "192.0.2.1")...)
	wantContains(t, "with routers", out, "1 accepted, 4 rejected, 0 undecided")
	if strings.Contains(out, "hint: ") {
		t.Errorf("hint with the routers given:\n%s", out)
	}
}

// TestNotFirstAS: announcements not starting with X are counted, and when
// most routes are like that the report says X looks like a transparent
// route server.
func TestNotFirstAS(t *testing.T) {
	var recs [][]byte
	for i, p := range []string{"10.0.0.0/8", "10.1.0.0/16", "10.2.0.0/16"} {
		recs = append(recs, gUpdate(gAt(i), gX, gL, "192.0.2.1", "192.0.2.2", nil, gNLRI(p), gAttrs("192.0.2.1", gSeq(gY, gZ))))
	}
	recs = append(recs, gUpdate(gAt(9), gX, gL, "192.0.2.1", "192.0.2.2", nil, gNLRI("192.0.2.0/24"), gAttrs("192.0.2.1", gSeq(gX))))
	f := write(t, "rs.mrt", slices.Concat(recs...))
	_, out, _ := run(t, "-local", "AS64496", "-peer", "AS64500", "-session", f, "-dump", registry)
	wantContains(t, "stdout", out, "3 announcements did not start with AS64500", "transparent route server")

	_, out, _ = run(t, session()...)
	wantContains(t, "stdout", out, "1 announcement did not start with AS64500")
	if strings.Contains(out, "transparent route server") {
		t.Errorf("the golden capture is not a route server's:\n%s", out)
	}
}

// TestSeveralInputs: inputs are read in the order given, compressed or not.
func TestSeveralInputs(t *testing.T) {
	first := write(t, "1.mrt.gz", gzipped(t, gUpdate(gAt(1), gX, gL, "192.0.2.1", "192.0.2.2", nil, gNLRI("192.0.2.0/24", "192.0.2.128/25"), gAttrs("192.0.2.1", gSeq(gX)))))
	second := write(t, "2.mrt", gUpdate(gAt(2), gX, gL, "192.0.2.1", "192.0.2.2", gNLRI("192.0.2.128/25"), nil, nil))
	dump := write(t, "reg.txt.gz", gzipped(t, mustRead(t, registry)))
	_, out, stderr := run(t, "-local", "AS64496", "-peer", "AS64500", "-session", first, "-session", second, "-dump", dump, "-af", "ipv4", "-direction", "import")
	wantContains(t, "in order", out, "1 route: 1 accepted")
	_, out, _ = run(t, "-local", "AS64496", "-peer", "AS64500", "-session", second, "-session", first, "-dump", dump, "-af", "ipv4", "-direction", "import")
	wantContains(t, "reversed", out, "2 routes: 1 accepted, 1 rejected")
	if stderr != "" {
		t.Errorf("stderr %s", stderr)
	}
}

func mustRead(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestCollectorCoverage: collector mode's own warnings, and the meaning line
// it always prints.
func TestCollectorCoverage(t *testing.T) {
	peers := []mrt.Peer{
		{BGPID: addr("198.51.100.1"), Addr: addr("198.51.100.1"), AS: 64510},
		{BGPID: addr("198.51.100.2"), Addr: addr("198.51.100.2"), AS: gX},
	}
	ent := func(peer uint16, attrs []byte) mrtgen.Entry {
		return mrtgen.Entry{PeerIndex: peer, Originated: gAt(-100), Attrs: attrs}
	}
	rib := func(p string, es ...mrtgen.Entry) []byte {
		return mrtgen.Header(mrt.TypeTableDumpV2, mrt.SubRIBIPv4Unicast, gAt(0), mrtgen.RIB(mrt.SubRIBIPv4Unicast, 0, prefix(p), es))
	}
	badComms := slices.Concat(mrtgen.Origin(bgp.OriginIGP), mrtgen.ASPath(true, mrtgen.Seq(64510, 64999)), mrtgen.NextHop(addr("198.51.100.1")),
		mrtgen.Raw(mrtgen.FlagOptional|mrtgen.FlagTransitive, 8, []byte{1, 2, 3}))
	data := slices.Concat(
		mrtgen.Header(mrt.TypeTableDumpV2, mrt.SubPeerIndexTable, gAt(0), mrtgen.PeerIndexTable(addr("192.0.2.254"), "", peers)),
		rib("192.0.2.0/24", ent(0, gAttrs("198.51.100.1", gSeq(64510, gX))), ent(1, gAttrs("198.51.100.2", gSeq(gX)))),
		rib("198.51.100.0/24", ent(0, gAttrs("198.51.100.1", []bgp.Segment{mrtgen.Set(64510), mrtgen.Seq(gX, gY)}))),
		rib("203.0.113.0/24", ent(0, badComms)),
		rib("100.64.0.0/10", ent(0, gAttrs("198.51.100.1", gSeq(64510, gX, gZ)))),
		gUpdate(gAt(5), gX, gL, "192.0.2.1", "192.0.2.2", nil, gNLRI("192.0.2.0/24"), gAttrs("192.0.2.1", gSeq(gX))),
	)
	f := write(t, "rib.mrt", data)
	code, out, stderr := run(t, "-local", "AS64496", "-peer", "AS64500", "-collector", f, "-dump", registry, "-af", "ipv4")
	if code != exitRejected {
		t.Fatalf("exit %d; stderr %s", code, stderr)
	}
	wantContains(t, "stdout", out,
		"these are routes AS64500 announced to someone",
		"1 update record ignored",
		"1 RIB entry in the whole table malformed",
		"1 sighting through AS64500 names no neighbour",
		"1 route seen on AS64500's own feed to a collector",
		"export, AS64500 to AS64510",
	)
	if strings.Contains(out, "malformed") && strings.Contains(out, "through AS64500 malformed") {
		t.Errorf("malformed entries described as X's:\n%s", out)
	}
}

// TestPolicyOverridesDump: -policy's objects replace the dump's of the same
// class, key and source; its aut-num answers first even under another
// source.
func TestPolicyOverridesDump(t *testing.T) {
	reg := write(t, "reg.txt", []byte(`aut-num: AS64496
import: from AS64500 accept {10.0.0.0/8}
source: TEST

aut-num: AS64500
export: to AS64496 announce AS64500
source: TEST

route: 192.0.2.0/24
origin: AS64500
source: TEST
`))
	f := write(t, "accepted.mrt", gUpdate(gAt(1), gX, gL, "192.0.2.1", "192.0.2.2", nil, gNLRI("192.0.2.0/24"), gAttrs("192.0.2.1", gSeq(gX))))
	args := []string{"-local", "AS64496", "-peer", "AS64500", "-session", f, "-dump", reg, "-af", "ipv4", "-direction", "import"}
	code, out, _ := run(t, args...)
	if code != exitRejected {
		t.Fatalf("without -policy: exit %d\n%s", code, out)
	}
	for _, src := range []string{"TEST", "DRAFT"} {
		draft := write(t, "draft.txt", []byte("aut-num: AS64496\nimport: from AS64500 accept AS64500\nsource: "+src+"\n"))
		code, out, stderr := run(t, append(slices.Clone(args), "-policy", draft)...)
		if code != exitOK {
			t.Errorf("source %s: exit %d; stderr %s\n%s", src, code, stderr, out)
		}
		wantContains(t, "source "+src, out, "1 route: 1 accepted", "accept AS64500", "-policy "+draft)
	}
}

// TestPolicyOverIRRd: with -irrd, -policy's aut-num answers first and the
// sets come from the server, never from the file.
func TestPolicyOverIRRd(t *testing.T) {
	srv := serve(t, `aut-num: AS64496
import: from AS64500 accept {10.0.0.0/8}
source: TEST

aut-num: AS64500
export: to AS64496 announce AS-SERVER
source: TEST

as-set: AS-SERVER
members: AS64500
source: TEST

route: 192.0.2.0/24
origin: AS64500
source: TEST
`)
	f := write(t, "accepted.mrt", gUpdate(gAt(1), gX, gL, "192.0.2.1", "192.0.2.2", nil, gNLRI("192.0.2.0/24"), gAttrs("192.0.2.1", gSeq(gX))))
	args := []string{"-local", "AS64496", "-peer", "AS64500", "-session", f, "-irrd", srv, "-sources", "TEST", "-af", "ipv4", "-routes", "all"}

	code, out, stderr := run(t, args...)
	if code != exitRejected {
		t.Fatalf("server's aut-num: exit %d; stderr %s\n%s", code, stderr, out)
	}
	wantContains(t, "server's aut-num", out, "import, AS64496 from AS64500: 1 route: 0 accepted, 1 rejected",
		"export, AS64500 to AS64496: 1 route: 1 accepted", "route object yes")

	draft := write(t, "draft.txt", []byte(`aut-num: AS64496
import: from AS64500 accept AS-SERVER
import: from AS64500 accept AS-FILEONLY
source: TEST

as-set: AS-FILEONLY
members: AS64500
source: TEST
`))
	code, out, stderr = run(t, append(slices.Clone(args), "-policy", draft)...)
	if code != exitOK {
		t.Fatalf("-policy: exit %d; stderr %s\n%s", code, stderr, out)
	}
	wantContains(t, "-policy", out, "import, AS64496 from AS64500: 1 route: 1 accepted", "by clause 1")

	// The file's set is not read: a policy naming only it rejects, naming it missing.
	only := write(t, "only.txt", []byte("aut-num: AS64496\nimport: from AS64500 accept AS-FILEONLY\nsource: TEST\n\nas-set: AS-FILEONLY\nmembers: AS64500\nsource: TEST\n"))
	code, out, _ = run(t, append(slices.Clone(args), "-policy", only, "-direction", "import")...)
	if code != exitRejected {
		t.Fatalf("file-only set: exit %d\n%s", code, out)
	}
	wantContains(t, "file-only set", out, "missing AS-FILEONLY")
}

// serve serves the RPSL text as one IRRd registry, TEST, on a localhost
// port until the test ends, and returns its address.
func serve(t *testing.T, text string) string {
	t.Helper()
	c := &resolve.Corpus{KeepPolicy: true, KeepRouteText: true}
	for o, diags := range rpsl.Parse(strings.NewReader(text)) {
		if o == nil {
			t.Fatalf("%v", diags)
		}
		obj, _ := rpsl.Decode(o)
		c.Put(obj)
	}
	reg, err := irrdq.NewRegistry("TEST", 0, c)
	if err != nil {
		t.Fatal(err)
	}
	snap, err := irrdq.NewSnapshot([]*irrdq.Registry{reg}, irrdq.SnapshotOptions{Default: []string{"TEST"}})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &irrdserver.Server{Snapshot: func() *irrdq.Snapshot { return snap }}
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ln) }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := srv.Shutdown(ctx); err != nil {
			t.Errorf("Shutdown: %v", err)
		}
		if err := <-done; err != nil && !errors.Is(err, irrdserver.ErrServerClosed) {
			t.Errorf("Serve: %v", err)
		}
	})
	return ln.Addr().String()
}

// TestGroups: rejected routes are grouped by their first clause's first
// failing test, with at most maxExamples examples each, and undecided ones
// by reason.
func TestGroups(t *testing.T) {
	var recs [][]byte
	for i := range 7 {
		p := netip.PrefixFrom(netip.AddrFrom4([4]byte{203, 0, 113, byte(i * 16)}), 28).String()
		recs = append(recs, gUpdate(gAt(i), gX, gL, "192.0.2.1", "192.0.2.2", nil, gNLRI(p), gAttrs("192.0.2.1", gSeq(gX, gZ))))
	}
	f := write(t, "many.mrt", slices.Concat(recs...))
	_, out, _ := run(t, "-local", "AS64496", "-peer", "AS64500", "-session", f, "-dump", registry, "-af", "ipv4", "-direction", "import")
	wantContains(t, "stdout", out, verdict.FailPrefixNotIn+": 7 routes", "203.0.113.64/28", "and 2 more")
	if strings.Contains(out, "203.0.113.80/28") {
		t.Errorf("more than %d examples:\n%s", maxExamples, out)
	}
}
