package cli

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/rkolesnichenko/mrt"
	"github.com/rkolesnichenko/mrt/bgp"
	"github.com/rkolesnichenko/routecheck"
	"github.com/rkolesnichenko/routecheck/internal/mrtgen"
	"github.com/rkolesnichenko/routecheck/verdict"
	"github.com/rkolesnichenko/rpsl"
	"github.com/rkolesnichenko/rpsl/policy"
	"github.com/rkolesnichenko/rpsl/resolve"
	"github.com/rkolesnichenko/rpsl/resolve/irrdq"
	"github.com/rkolesnichenko/rpsl/resolve/irrdserver"
	"github.com/rkolesnichenko/rpsl/resolve/peval"
	"github.com/rkolesnichenko/rpsl/types"
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
		"routecheck -peer AS (-session FILE [-local AS] | -collector FILE -local AS)",
		"-irrd", "-sources", "-policy", "-vrps", "-af", "-direction", "-peer-addr", "-at", "-pre-policy",
		"-local-rtr", "-peer-rtr", "-max-prefixes", "[-max-prefixes N]", "-verified-sources", "[-verified-sources LIST]",
		"the registries whose route objects count as verified", "-format", "-routes", "repeatable", "Exit status",
		"a key that does not parse", "cut mid-record", "the session in the capture")
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
		{"zero max-prefixes", session("-max-prefixes", "0"), "-max-prefixes"},
		{"negative max-prefixes", session("-max-prefixes", "-5"), "-max-prefixes"},
		{"non-number max-prefixes", session("-max-prefixes", "many"), "-max-prefixes"},
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
	// A usage error found by Check prints no route-object note.
	if strings.Contains(stderr, "route objects:") {
		t.Errorf("capture's local AS is the peer: the note before a usage error:\n%s", stderr)
	}
	empty := write(t, "empty.mrt", nil)
	code, _, stderr = run(t, "-peer", "AS64500", "-session", empty, "-dump", registry)
	if code != exitUsage {
		t.Errorf("capture naming no local AS: exit %d, want %d; stderr %s", code, exitUsage, stderr)
	}
	wantContains(t, "stderr", stderr, "give -local")
	if strings.Contains(stderr, "route objects:") {
		t.Errorf("capture naming no local AS: the note before a usage error:\n%s", stderr)
	}
}

// TestNoSession: a capture with no record of the session selected is not
// "X announced nothing" (ruling R23): exit 3, naming the AS and the address,
// and nothing on stdout.
func TestNoSession(t *testing.T) {
	const hint = " in the capture (a 2-byte capture shows a 4-byte AS as AS23456)"
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{"wrong -peer-addr", session("-peer-addr", "192.0.2.99"), "routecheck: no record of a session with AS64500 from 192.0.2.99" + hint},
		{"wrong -peer-addr, json", session("-peer-addr", "192.0.2.99", "-format", "json"), "routecheck: no record of a session with AS64500 from 192.0.2.99" + hint},
		{"wrong -peer-addr, import only", session("-peer-addr", "192.0.2.99", "-direction", "import", "-af", "ipv4"), "from 192.0.2.99" + hint},
		{"a peer that never speaks", []string{"-local", "AS64496", "-peer", "AS64511", "-session", capture, "-dump", registry}, "routecheck: no record of a session with AS64511" + hint},
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
			if strings.Contains(stderr, "route objects") {
				t.Errorf("stderr %q has the route-object note, want none without a session", stderr)
			}
		})
	}
	// The right address is a session.
	if code, _, stderr := run(t, session("-peer-addr", "192.0.2.1")...); code != exitRejected {
		t.Errorf("-peer-addr 192.0.2.1: exit %d, want %d; stderr %s", code, exitRejected, stderr)
	}
	// Without -local the capture names no local AS either: a usage error
	// that says why.
	code, _, stderr := run(t, "-peer", "AS64500", "-session", capture, "-dump", registry, "-peer-addr", "192.0.2.99")
	if code != exitUsage {
		t.Errorf("no -local: exit %d, want %d; stderr %s", code, exitUsage, stderr)
	}
	wantContains(t, "stderr", stderr, "no record of a session with AS64500 from 192.0.2.99", "give -local")
}

// TestLocalMismatch: -local naming another AS than the capture's local AS is
// checked as given, with a warning on stderr and in the text; the exit
// status is unchanged.
func TestLocalMismatch(t *testing.T) {
	const warn = "warning: -local AS64511 is not the capture's local AS, AS64496: AS64511's policy is checked"
	args := []string{"-local", "AS64511", "-peer", "AS64500", "-session", capture, "-dump", registry}
	code, stdout, stderr := run(t, args...)
	if code != exitOK {
		t.Errorf("exit %d, want %d; stderr %s", code, exitOK, stderr)
	}
	wantContains(t, "stderr", stderr, "routecheck: "+warn)
	wantContains(t, "stdout", stdout, "\n"+warn+"\n", "import, AS64511 from AS64500: no policy")
	code, stdout, stderr = run(t, append(args, "-format", "json")...)
	if code != exitOK || strings.Contains(stdout, "warning") {
		t.Errorf("json: exit %d, stdout %s", code, stdout)
	}
	wantContains(t, "stderr", stderr, "routecheck: "+warn)
	// The capture's own local AS: no warning.
	_, stdout, stderr = run(t, session()...)
	if strings.Contains(stdout+stderr, "is not the capture's local AS") {
		t.Errorf("a warning for the capture's own local AS:\n%s%s", stdout, stderr)
	}
}

func TestFailures(t *testing.T) {
	missingAutNum := write(t, "reg.txt", []byte("aut-num: AS64500\nexport: to AS64496 announce AS64500\nsource: TEST\n"))
	dead := closedPort(t)
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
		{"unreachable irrd", []string{"-local", "AS64496", "-peer", "AS64500", "-session", capture, "-irrd", dead}, dead},
		{"second capture missing", []string{"-local", "AS64496", "-peer", "AS64500", "-session", capture, "-session", "testdata/session/nonexistent.mrt", "-dump", registry}, "testdata/session/nonexistent.mrt"},
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
			// A run that fails before or in Check prints no route-object note.
			if strings.Contains(stderr, "route objects:") {
				t.Errorf("the route-object note on a failed run:\n%s", stderr)
			}
		})
	}
	// A truncated capture is named as such.
	_, _, stderr := run(t, "-local", "AS64496", "-peer", "AS64500", "-session", truncated, "-dump", registry)
	wantContains(t, "stderr", stderr, truncated+": ", "truncated")
}

// TestFailureAfterSomeReports: a check that fails after it has handed over a
// report (X's aut-num is missing, so the export report fails after the
// import report is done) writes nothing to stdout, no route-object note, and
// exits 3, in either format.
func TestFailureAfterSomeReports(t *testing.T) {
	srv := serve(t, `aut-num: AS64496
import: from AS64500 accept AS64500
source: TEST

route: 192.0.2.0/24
origin: AS64500
source: TEST
`)
	args := []string{"-local", "AS64496", "-peer", "AS64500", "-session", capture, "-irrd", srv, "-sources", "TEST", "-af", "ipv4"}

	// The import report alone is produced.
	if code, out, stderr := run(t, append(slices.Clone(args), "-direction", "import")...); code == exitFailed ||
		!strings.Contains(out, "import, AS64496 from AS64500: ") {
		t.Fatalf("-direction import: exit %d; stderr %s\n%s", code, stderr, out)
	}
	// And CheckEach hands it over before the export report fails.
	cfg, err := parse(args, io.Discard, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	reg, err := loadPolicy(context.Background(), cfg, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	defer reg.close()
	c := &routecheck.Checker{Eval: peval.Evaluator{Src: reg.src}, Routes: reg.src, VerifiedRoutes: reg.verified}
	var handed []routecheck.Direction
	_, err = c.CheckEach(context.Background(), cfg.mode, records(cfg.inputs), cfg.opts,
		func(_ *routecheck.Result, dir routecheck.Direction, _ *routecheck.Report) error {
			handed = append(handed, dir)
			return nil
		})
	if err == nil || !slices.Equal(handed, []routecheck.Direction{routecheck.DirImport}) {
		t.Fatalf("CheckEach: handed %v, err %v; want the import report, then an error", handed, err)
	}

	for _, format := range []string{"text", "json"} {
		code, stdout, stderr := run(t, append(slices.Clone(args), "-format", format)...)
		if code != exitFailed {
			t.Errorf("%s: exit %d, want %d; stderr %s", format, code, exitFailed, stderr)
		}
		if stdout != "" {
			t.Errorf("%s: stdout %q, want nothing", format, stdout)
		}
		wantContains(t, format+" stderr", stderr, "not found")
		if strings.Contains(stderr, "route objects:") {
			t.Errorf("%s: the route-object note on a failed run:\n%s", format, stderr)
		}
	}
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
		// An address with no record is no session (TestNoSession), not 0 routes.
		code, out, _ := run(t, session("-af", "ipv4", "-direction", "import", "-peer-addr", "192.0.2.99")...)
		if code != exitFailed || out != "" {
			t.Errorf("-peer-addr 192.0.2.99: exit %d, stdout %q", code, out)
		}
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
	if stderr != noneNote {
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
		wantContains(t, "source "+src, out, "1 route: 1 accepted", "accept AS64500", "-policy "+draft+": aut-num AS64496 ("+src+") answers first")
	}
}

// TestDumpPrecedence: with the same aut-num in two registries, each in its
// own -dump file, the registry of the dump named first answers (load.go's
// source order: the order in which each source: first appears).
func TestDumpPrecedence(t *testing.T) {
	accepts := write(t, "accepts.txt", []byte("aut-num: AS64496\nimport: from AS64500 accept {192.0.2.0/24}\nsource: AAA\n"))
	rejects := write(t, "rejects.txt", []byte("aut-num: AS64496\nimport: from AS64500 accept {10.0.0.0/8}\nsource: BBB\n"))
	f := write(t, "one.mrt", gUpdate(gAt(1), gX, gL, "192.0.2.1", "192.0.2.2", nil, gNLRI("192.0.2.0/24"), gAttrs("192.0.2.1", gSeq(gX))))
	for _, tc := range []struct {
		name        string
		first, then string
		exit        int
		want        string
	}{
		{"AAA first", accepts, rejects, exitOK, "1 route: 1 accepted, 0 rejected"},
		{"BBB first", rejects, accepts, exitRejected, "1 route: 0 accepted, 1 rejected"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, out, stderr := run(t, "-local", "AS64496", "-peer", "AS64500", "-session", f,
				"-dump", tc.first, "-dump", tc.then, "-af", "ipv4", "-direction", "import")
			if code != tc.exit {
				t.Errorf("exit %d, want %d; stderr %s\n%s", code, tc.exit, stderr, out)
			}
			wantContains(t, "stdout", out, tc.want)
		})
	}
}

// TestUnevaluable: a report whose policy names, in filter position, a set
// that reaches AS-ANY (ruling R19) reads as not evaluable in text, every
// route undecided with that reason, and as the reason kind "unevaluable" in
// JSON; exit 0.
func TestUnevaluable(t *testing.T) {
	reg := write(t, "reg.txt", []byte(`aut-num: AS64496
import: from AS64500 accept AS-ANYSET
source: TEST

aut-num: AS64500
export: to AS64496 announce AS64500
source: TEST

as-set: AS-ANYSET
members: AS-ANY
source: TEST

route: 192.0.2.0/24
origin: AS64500
source: TEST
`))
	f := write(t, "one.mrt", gUpdate(gAt(1), gX, gL, "192.0.2.1", "192.0.2.2", nil, gNLRI("192.0.2.0/24"), gAttrs("192.0.2.1", gSeq(gX))))
	args := []string{"-local", "AS64496", "-peer", "AS64500", "-session", f, "-dump", reg, "-af", "ipv4"}
	code, out, stderr := run(t, append(slices.Clone(args), "-routes", "all")...)
	if code != exitOK {
		t.Fatalf("exit %d; stderr %s\n%s", code, stderr, out)
	}
	wantContains(t, "text", out,
		"import, AS64496 from AS64500: 1 route: 0 accepted, 0 rejected, 1 undecided",
		"policy not evaluable, no route decided: peval: ",
		"AS-ANYSET",
		"undecided, by reason (a route may have several):\n      unevaluable: peval: ",
		"undecided: unevaluable: peval: ",
		"export, AS64500 to AS64496: 1 route: 1 accepted, 0 rejected, 0 undecided")
	code, out, stderr = run(t, append(slices.Clone(args), "-format", "json")...)
	if code != exitOK {
		t.Fatalf("json: exit %d; stderr %s\n%s", code, stderr, out)
	}
	wantContains(t, "json", compact(t, out), `"Kind":"unevaluable"`, `"Clause":-1,"Index":-1`, `AS-ANYSET`)

	// Ruling R21: an unevaluable report with no routes (ipv6 here: the
	// capture has none) still says so, in text and in JSON.
	reg6 := write(t, "reg6.txt", []byte(`aut-num: AS64496
import: from AS64500 accept AS64500
mp-import: afi ipv6.unicast from AS64500 accept AS-ANYSET
source: TEST

aut-num: AS64500
export: to AS64496 announce AS64500
source: TEST

as-set: AS-ANYSET
members: AS-ANY
source: TEST

route: 192.0.2.0/24
origin: AS64500
source: TEST
`))
	args6 := []string{"-local", "AS64496", "-peer", "AS64500", "-session", f, "-dump", reg6, "-direction", "import"}
	code, out, stderr = run(t, args6...)
	if code != exitOK {
		t.Fatalf("no routes: exit %d; stderr %s\n%s", code, stderr, out)
	}
	wantContains(t, "no routes, text", out,
		"ipv6.unicast\n  import, AS64496 from AS64500: 0 routes: 0 accepted, 0 rejected, 0 undecided\n    policy not evaluable, no route decided: peval: ",
		"AS-ANYSET")
	code, out, stderr = run(t, append(slices.Clone(args6), "-format", "json")...)
	if code != exitOK {
		t.Fatalf("no routes, json: exit %d; stderr %s\n%s", code, stderr, out)
	}
	wantContains(t, "no routes, json", compact(t, out), `"Unevaluable":"peval: `, `"Unevaluable":""`)
	if !strings.Contains(out, "AS-ANYSET") {
		t.Errorf("no routes, json: the set is not named:\n%s", out)
	}
}

// limitRegistry is the registry TestUnevaluableLimit and TestMaxPrefixesOption
// share: L imports AS-BIG, which expands to exactly 2 prefixes, and X exports
// what export says.
func limitRegistry(export string) string {
	return `aut-num: AS64496
import: from AS64500 accept AS-BIG
source: TEST

aut-num: AS64500
export: to AS64496 announce ` + export + `
source: TEST

as-set: AS-BIG
members: AS64500, AS64501
source: TEST

route: 192.0.2.0/24
origin: AS64500
source: TEST

route: 198.51.100.0/24
origin: AS64501
source: TEST
`
}

// TestUnevaluableLimit: a set over one of rpsl's expansion limits makes that
// report unevaluable (Ruling R27); the run goes on and does not exit 3. The
// limit is lowered with -max-prefixes.
func TestUnevaluableLimit(t *testing.T) {
	registry := limitRegistry
	f := write(t, "one.mrt", gUpdate(gAt(1), gX, gL, "192.0.2.1", "192.0.2.2", nil, gNLRI("192.0.2.0/24"), gAttrs("192.0.2.1", gSeq(gX))))
	argsFor := func(reg string) []string {
		return []string{"-local", "AS64496", "-peer", "AS64500", "-session", f, "-dump", reg, "-af", "ipv4", "-max-prefixes", "1"}
	}

	// A: only the import is over the limit; the export (announce ANY) is decided.
	regA := write(t, "regA.txt", []byte(registry("ANY")))
	code, out, stderr := run(t, argsFor(regA)...)
	if code != exitOK {
		t.Fatalf("A: exit %d; stderr %s\n%s", code, stderr, out)
	}
	wantContains(t, "A text", out,
		"import, AS64496 from AS64500:",
		"policy not evaluable, no route decided: ",
		"MaxPrefixes",
		"export, AS64500 to AS64496: 1 route: ")
	if n := strings.Count(out, "policy not evaluable"); n != 1 {
		t.Errorf("A: %d 'policy not evaluable' lines, want 1:\n%s", n, out)
	}

	// B: JSON; only the import is unevaluable.
	code, out, stderr = run(t, append(argsFor(regA), "-format", "json")...)
	if code != exitOK {
		t.Fatalf("B: exit %d; stderr %s\n%s", code, stderr, out)
	}
	dec := json.NewDecoder(strings.NewReader(out))
	dec.DisallowUnknownFields()
	var view []jsonResult
	if err := dec.Decode(&view); err != nil {
		t.Fatalf("B: does not decode into the view: %v", err)
	}
	if len(view) != 1 || view[0].Import == nil || len(view[0].Export) != 1 {
		t.Fatalf("B: view: %+v", view)
	}
	if got := view[0].Import.Unevaluable; !strings.Contains(got, "MaxPrefixes") {
		t.Errorf("B: Import.Unevaluable %q does not name MaxPrefixes", got)
	}
	if got := view[0].Export[0].Unevaluable; got != "" {
		t.Errorf("B: Export[0].Unevaluable %q, want empty", got)
	}
	wantContains(t, "B json", compact(t, out), `"Kind":"unevaluable"`)

	// C: the export is over the limit too; both reports are unevaluable.
	regC := write(t, "regC.txt", []byte(registry("AS-BIG")))
	code, out, stderr = run(t, argsFor(regC)...)
	if code != exitOK {
		t.Fatalf("C: exit %d; stderr %s\n%s", code, stderr, out)
	}
	if n := strings.Count(out, "policy not evaluable"); n != 2 {
		t.Errorf("C: %d 'policy not evaluable' lines, want 2:\n%s", n, out)
	}
}

// TestMaxPrefixesOption: -max-prefixes sets the most prefixes one set's
// expansion may reach; AS-BIG expands to exactly 2, so 2 decides the report
// and 1 makes it unevaluable, over -dump and over -irrd alike.
func TestMaxPrefixesOption(t *testing.T) {
	f := write(t, "one.mrt", gUpdate(gAt(1), gX, gL, "192.0.2.1", "192.0.2.2", nil, gNLRI("192.0.2.0/24"), gAttrs("192.0.2.1", gSeq(gX))))
	text := limitRegistry("ANY")
	reg := write(t, "reg.txt", []byte(text))
	addr := serve(t, text)
	base := []string{"-local", "AS64496", "-peer", "AS64500", "-session", f, "-af", "ipv4"}
	dump := append(slices.Clone(base), "-dump", reg)
	decided := func(t *testing.T, out string) {
		t.Helper()
		if n := strings.Count(out, "policy not evaluable"); n != 0 {
			t.Errorf("%d 'policy not evaluable' lines, want 0:\n%s", n, out)
		}
		wantContains(t, "import line", out, "import, AS64496 from AS64500: 1 route: 1 accepted")
	}
	over := func(t *testing.T, out string) {
		t.Helper()
		if n := strings.Count(out, "policy not evaluable"); n != 1 {
			t.Errorf("%d 'policy not evaluable' lines, want 1:\n%s", n, out)
		}
		wantContains(t, "limit", out, "MaxPrefixes (1)")
	}
	for _, tc := range []struct {
		name string
		args []string
		want func(*testing.T, string)
	}{
		{"absent", dump, decided},
		{"at the size", append(slices.Clone(dump), "-max-prefixes", "2"), decided},
		{"below", append(slices.Clone(dump), "-max-prefixes", "1"), over},
		{"huge", append(slices.Clone(dump), "-max-prefixes", "1099511627776"), decided},
		{"irrd", append(slices.Clone(base), "-irrd", addr, "-sources", "TEST", "-max-prefixes", "1"), over},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, out, stderr := run(t, tc.args...)
			if code != exitOK {
				t.Fatalf("exit %d; stderr %s\n%s", code, stderr, out)
			}
			tc.want(t, out)
		})
	}
}

// TestAnySetPath: a set reaching AS-ANY named in an AS-path regexp is
// evaluated; the accepted route says which set let any AS through, in text
// and in JSON (Verdict.AnySets).
func TestAnySetPath(t *testing.T) {
	reg := write(t, "reg.txt", []byte(`aut-num: AS64496
import: from AS64500 accept <^AS64500 AS-ANYSET$>
source: TEST

aut-num: AS64500
export: to AS64496 announce AS64500
source: TEST

as-set: AS-ANYSET
members: AS-ANY
source: TEST

route: 198.51.100.0/24
origin: AS64501
source: TEST
`))
	f := write(t, "one.mrt", gUpdate(gAt(1), gX, gL, "192.0.2.1", "192.0.2.2", nil, gNLRI("198.51.100.0/24"), gAttrs("192.0.2.1", gSeq(gX, gY))))
	args := []string{"-local", "AS64496", "-peer", "AS64500", "-session", f, "-dump", reg, "-af", "ipv4", "-direction", "import"}
	code, out, stderr := run(t, append(slices.Clone(args), "-routes", "all")...)
	if code != exitOK {
		t.Fatalf("exit %d; stderr %s\n%s", code, stderr, out)
	}
	wantContains(t, "text", out,
		"import, AS64496 from AS64500: 1 route: 1 accepted, 0 rejected, 0 undecided",
		"accepted by clause 1 (AS-ANYSET reaches AS-ANY: any AS)")
	code, out, stderr = run(t, append(slices.Clone(args), "-format", "json")...)
	if code != exitOK {
		t.Fatalf("json: exit %d; stderr %s\n%s", code, stderr, out)
	}
	dec := json.NewDecoder(strings.NewReader(out))
	dec.DisallowUnknownFields()
	var view []jsonResult
	if err := dec.Decode(&view); err != nil {
		t.Fatalf("does not decode into the view: %v", err)
	}
	if len(view) != 1 || view[0].Import == nil || len(view[0].Import.Routes) != 1 {
		t.Fatalf("view: %+v", view)
	}
	if got := view[0].Import.Routes[0].Verdict.AnySets; !slices.Equal(got, []string{"AS-ANYSET"}) {
		t.Errorf("decoded AnySets %q, want [AS-ANYSET]", got)
	}
	wantContains(t, "json", compact(t, out), `"AnySets":["AS-ANYSET"]`)
	if strings.Contains(out, "accepted through a set") {
		t.Errorf("json: holds the text summary line:\n%s", out)
	}

	// With the default -routes (none), no route line is printed, and the
	// report block says how many routes a set reaching AS-ANY let through:
	// two of three here (the third, X alone, is rejected).
	two := write(t, "two.mrt", slices.Concat(
		gUpdate(gAt(1), gX, gL, "192.0.2.1", "192.0.2.2", nil, gNLRI("198.51.100.0/24", "198.51.101.0/24"), gAttrs("192.0.2.1", gSeq(gX, gY))),
		gUpdate(gAt(2), gX, gL, "192.0.2.1", "192.0.2.2", nil, gNLRI("192.0.2.0/24"), gAttrs("192.0.2.1", gSeq(gX)))))
	for _, c := range []struct {
		file, counts, line string
		exit               int
	}{
		{f, "1 route: 1 accepted, 0 rejected, 0 undecided; route objects 1 yes, 0 no", "AS-ANYSET (1 route)", exitOK},
		{two, "3 routes: 2 accepted, 1 rejected, 0 undecided; route objects 1 yes, 2 no", "AS-ANYSET (2 routes)", exitRejected},
	} {
		dflt := []string{"-local", "AS64496", "-peer", "AS64500", "-session", c.file, "-dump", reg, "-af", "ipv4", "-direction", "import"}
		code, out, stderr = run(t, dflt...)
		if code != c.exit {
			t.Fatalf("default -routes: exit %d, want %d; stderr %s\n%s", code, c.exit, stderr, out)
		}
		wantContains(t, "default -routes", out,
			"import, AS64496 from AS64500: "+c.counts+"\n    clause 1 (import attribute 1): ",
			"\n    accepted through a set reaching AS-ANY (any AS): "+c.line+"\n")
		if strings.Contains(out, "accepted by clause") || strings.Contains(out, "routes (") {
			t.Errorf("default -routes: a route line is printed:\n%s", out)
		}
	}
}

// TestAnySetSummaryCountsRoutes: the report block's line names each set once,
// sorted, and counts routes, not sets: one route is accepted through two sets
// and two through one of them, so the line names two sets and says 3 routes
// (4 set names in all). A single-set route comes first, so the sets are
// gathered out of order.
func TestAnySetSummaryCountsRoutes(t *testing.T) {
	reg := write(t, "reg.txt", []byte(`aut-num: AS64496
import: from AS64500 accept <^AS64500 AS-ANYB AS-ANYA$> OR <^AS64500 AS-ANYB$>
source: TEST

aut-num: AS64500
export: to AS64496 announce AS64500
source: TEST

as-set: AS-ANYA
members: AS-ANY
source: TEST

as-set: AS-ANYB
members: AS-ANY
source: TEST
`))
	f := write(t, "two-sets.mrt", slices.Concat(
		gUpdate(gAt(1), gX, gL, "192.0.2.1", "192.0.2.2", nil, gNLRI("198.51.100.0/24"), gAttrs("192.0.2.1", gSeq(gX, gY))),
		gUpdate(gAt(2), gX, gL, "192.0.2.1", "192.0.2.2", nil, gNLRI("198.51.101.0/24"), gAttrs("192.0.2.1", gSeq(gX, gY, gZ))),
		gUpdate(gAt(3), gX, gL, "192.0.2.1", "192.0.2.2", nil, gNLRI("198.51.102.0/24"), gAttrs("192.0.2.1", gSeq(gX, gZ)))))
	args := []string{"-local", "AS64496", "-peer", "AS64500", "-session", f, "-dump", reg, "-af", "ipv4", "-direction", "import"}

	code, out, stderr := run(t, append(slices.Clone(args), "-routes", "all")...)
	if code != exitOK {
		t.Fatalf("-routes all: exit %d; stderr %s\n%s", code, stderr, out)
	}
	wantContains(t, "-routes all", out,
		"accepted by clause 1 (AS-ANYB reaches AS-ANY: any AS)",
		"accepted by clause 1 (AS-ANYA, AS-ANYB reach AS-ANY: any AS)")

	code, out, stderr = run(t, args...)
	if code != exitOK {
		t.Fatalf("default -routes: exit %d; stderr %s\n%s", code, stderr, out)
	}
	wantContains(t, "default -routes", out,
		"import, AS64496 from AS64500: 3 routes: 3 accepted, 0 rejected, 0 undecided",
		"\n    accepted through a set reaching AS-ANY (any AS): AS-ANYA, AS-ANYB (3 routes)\n")
}

// TestOutcomeAnySets: one set reaches, several reach, and the sets come
// before any "after undecided" part.
func TestOutcomeAnySets(t *testing.T) {
	for _, c := range []struct {
		v    verdict.Verdict
		want string
	}{
		{verdict.Verdict{Outcome: verdict.Accepted, Clause: 1, AnySets: []string{"AS-X"}},
			"accepted by clause 2 (AS-X reaches AS-ANY: any AS)"},
		{verdict.Verdict{Outcome: verdict.Accepted, Clause: 1, AnySets: []string{"AS-X", "AS-Y"}, EarlierUndecided: []int{0}},
			"accepted by clause 2 (AS-X, AS-Y reach AS-ANY: any AS), after undecided clause 1"},
		{verdict.Verdict{Outcome: verdict.Accepted}, "accepted by clause 1"},
	} {
		if got := outcome("import", c.v); got != c.want {
			t.Errorf("outcome(%+v) = %q, want %q", c.v, got, c.want)
		}
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
	return serveRegistries(t, registryText{"TEST", text})
}

// registryText is one registry an in-process IRRd serves: its name and its
// objects, as RPSL text of that one source.
type registryText struct{ name, text string }

// serveRegistries serves the registries on a localhost port until the test
// ends, with all of them, in the order given, as the server's default
// source list, and returns its address.
func serveRegistries(t *testing.T, regs ...registryText) string {
	t.Helper()
	var built []*irrdq.Registry
	var names []string
	for _, r := range regs {
		c := &resolve.Corpus{KeepPolicy: true, KeepRouteText: true}
		for o, diags := range rpsl.Parse(strings.NewReader(r.text)) {
			if o == nil {
				t.Fatalf("%v", diags)
			}
			obj, _ := rpsl.Decode(o)
			c.Put(obj)
		}
		reg, err := irrdq.NewRegistry(r.name, 0, c)
		if err != nil {
			t.Fatal(err)
		}
		built, names = append(built, reg), append(names, r.name)
	}
	snap, err := irrdq.NewSnapshot(built, irrdq.SnapshotOptions{Default: names})
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

// TestDraftChecked: a -policy draft whose aut-num or inet-rtr does not
// decode cleanly, or that supplies no aut-num and no inet-rtr, fails the run
// (exit 3) naming the file and the object; its diagnostics are written to
// stderr (ruling R17).
func TestDraftChecked(t *testing.T) {
	for _, tc := range []struct {
		name, text string
		wants      []string
	}{
		{"typo", "aut-num: AS64496\nimport: from AS64500 acept AS64500\nsource: TEST\n",
			[]string{":2:35: error policy/expect-filter: expected 'accept' clause", ":2:22: warning policy/router", "aut-num AS64496"}},
		{"bad key", "aut-num: AS6449x\nimport: from AS64500 accept AS64500\nsource: TEST\n",
			[]string{"invalid ASN", "aut-num AS6449x"}},
		{"unknown class", "aut-nm: AS64496\nimport: from AS64500 accept AS64500\nsource: TEST\n",
			[]string{"aut-nm AS64496 skipped", "no aut-num and no inet-rtr"}},
		{"no aut-num", "route: 192.0.2.0/24\norigin: AS64500\nsource: TEST\n",
			[]string{"no aut-num and no inet-rtr"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			draft := write(t, "draft.txt", []byte(tc.text))
			for _, reg := range [][]string{{"-dump", registry}, {"-irrd", closedPort(t)}} {
				args := append([]string{"-local", "AS64496", "-peer", "AS64500", "-session", capture, "-policy", draft}, reg...)
				code, stdout, stderr := run(t, args...)
				if code != exitFailed {
					t.Errorf("%s: exit %d, want %d; stderr %s", reg[0], code, exitFailed, stderr)
				}
				if stdout != "" {
					t.Errorf("%s: stdout %q", reg[0], stdout)
				}
				wantContains(t, reg[0]+" stderr", stderr, append([]string{draft}, tc.wants...)...)
			}
		})
	}
}

// TestDraftSkips: objects of a class routecheck does not use, and sets and
// routes (which always come from the registry), are skipped with a warning; the
// draft's aut-num still answers first. A draft object with no source: is
// named without one.
func TestDraftSkips(t *testing.T) {
	draft := write(t, "draft.txt", []byte(`mntner: MNT-DRAFT
auth: BCRYPT-PW $2a$12$xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
source: TEST

route-set: RS-BROKEN
members: 192.0.2.0/33
source: TEST

as-set: AS-DRAFT
members: AS64500
source: TEST

route: 203.0.113.0/24
origin: AS64500
source: TEST

aut-num: AS64496
import: from AS64500 accept AS64500
`))
	code, out, stderr := run(t, "-local", "AS64496", "-peer", "AS64500", "-session", capture, "-dump", registry,
		"-policy", draft, "-af", "ipv4", "-direction", "import", "-routes", "all")
	if code != exitRejected {
		t.Fatalf("exit %d; stderr %s", code, stderr)
	}
	wantContains(t, "stderr", stderr,
		draft+": mntner MNT-DRAFT skipped: routecheck does not use this class",
		draft+": route-set RS-BROKEN skipped: sets come from the registry",
		draft+": as-set AS-DRAFT skipped: sets come from the registry",
		draft+": route 203.0.113.0/24 skipped: routes come from the registry")
	// The draft's route is not used: AS64500's expansion does not gain it,
	// and no route object is found for it (ruling R18).
	wantContains(t, "stdout", out, "203.0.113.0/24  AS64500 AS64502  rejected: clause 1: prefix not in filter  route object no")
	wantContains(t, "stdout", out, "policy: -policy "+draft+": aut-num AS64496 answers first\n",
		"from AS64500 accept AS64500", "1 accepted, 4 rejected")
	if strings.Contains(out, "()") {
		t.Errorf("empty parentheses:\n%s", out)
	}
}

func TestIRRdAddr(t *testing.T) {
	for in, want := range map[string]string{
		"whois.radb.net":      "whois.radb.net:43",
		"whois.radb.net:4300": "whois.radb.net:4300",
		"192.0.2.1":           "192.0.2.1:43",
		"192.0.2.1:4300":      "192.0.2.1:4300",
		"2001:db8::1":         "[2001:db8::1]:43",
		"[2001:db8::1]":       "[2001:db8::1]:43",
		"[2001:db8::1]:4300":  "[2001:db8::1]:4300",
	} {
		if got := irrdAddr(in); got != want {
			t.Errorf("irrdAddr(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestTermText: a term without a filter reads as its peering alone.
func TestTermText(t *testing.T) {
	p, diags := policy.ParsePeering("AS64500")
	if len(diags) > 0 {
		t.Fatal(diags)
	}
	if got := termText("import", policy.Term{Peering: p}); got != "from AS64500" {
		t.Errorf("import, no filter: %q", got)
	}
	if got := termText("export", policy.Term{Peering: p}); got != "to AS64500" {
		t.Errorf("export, no filter: %q", got)
	}
	if got := termText("import", policy.Term{}); strings.Contains(got, "accept") {
		t.Errorf("empty term: %q", got)
	}
}

// TestRejectedHeaderNamesClause: the Rejected groups' header names the
// clause of the first Fail, not clause 1 by default.
func TestRejectedHeaderNamesClause(t *testing.T) {
	p := &printer{cfg: &config{mode: routecheck.ModeSession, routes: "none"}, x: 64500, l: 64496}
	rv := routecheck.RouteVerdict{
		Route:   verdict.Route{Prefix: prefix("192.0.2.0/24"), Path: []types.ASN{64500}, PathKnown: true, CommsKnown: true},
		Verdict: verdict.Verdict{Outcome: verdict.Rejected, Fails: []verdict.Fail{{Clause: 1, Test: verdict.FailPrefixNotIn}}},
	}
	p.report("import", routecheck.Report{Toward: 64500, Routes: []routecheck.RouteVerdict{rv}, Rejected: 1}, "import", "AS64496")
	wantContains(t, "report", p.b.String(), "rejected, by the first failing test of clause 2:")
}

// TestInputsOpenedOneAtATime: the inputs are opened lazily, each closed
// before the next is opened, so that many files need one descriptor.
func TestInputsOpenedOneAtATime(t *testing.T) {
	open, most := 0, 0
	orig := openInput
	t.Cleanup(func() { openInput = orig })
	openInput = func(name string) (io.ReadCloser, error) {
		f, err := orig(name)
		if err != nil {
			return nil, err
		}
		open++
		most = max(most, open)
		return closer{f, func() { open-- }}, nil
	}
	var args []string
	for range 20 {
		args = append(args, "-session", capture)
	}
	code, _, stderr := run(t, append(args, "-local", "AS64496", "-peer", "AS64500", "-dump", registry)...)
	if code != exitRejected {
		t.Fatalf("exit %d; stderr %s", code, stderr)
	}
	if most != 1 || open != 0 {
		t.Errorf("at most %d inputs open at once, %d left open; want 1 and 0", most, open)
	}
}

type closer struct {
	io.ReadCloser
	done func()
}

func (c closer) Close() error { c.done(); return c.ReadCloser.Close() }

// TestJSONView: the JSON is the view of routecheck.Result: every Result,
// Report, RouteVerdict, Verdict and Route field name, readable values
// (outcomes and RPKI states by name, clause and term text, communities as
// hi:lo, missing sets by name), and it decodes back into the view with no
// unknown field and re-encodes to the same bytes.
func TestJSONView(t *testing.T) {
	for _, g := range goldens {
		t.Run(g.name, func(t *testing.T) {
			_, out, stderr := run(t, append(slices.Clone(g.args), "-format", "json")...)
			if stderr != noneNote {
				t.Fatalf("stderr %s", stderr)
			}
			dec := json.NewDecoder(strings.NewReader(out))
			dec.DisallowUnknownFields()
			var view []jsonResult
			if err := dec.Decode(&view); err != nil {
				t.Fatalf("does not decode into the view: %v", err)
			}
			var again bytes.Buffer
			if err := encodeJSON(&again, view); err != nil {
				t.Fatal(err)
			}
			if again.String() != out {
				t.Errorf("re-encoded view differs:\n%s", again.String())
			}
		})
	}

	_, out, _ := run(t, session("-vrps", "testdata/rpki/vrps.json", "-format", "json")...)
	var doc []map[string]any
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatal(err)
	}
	keys := func(v any) []string {
		var ks []string
		for k := range v.(map[string]any) {
			ks = append(ks, k)
		}
		slices.Sort(ks)
		return ks
	}
	names := func(v any) []string {
		var ns []string
		rt := reflect.TypeOf(v)
		for i := range rt.NumField() {
			if rt.Field(i).IsExported() {
				ns = append(ns, rt.Field(i).Name)
			}
		}
		slices.Sort(ns)
		return ns
	}
	imp := doc[0]["Import"].(map[string]any)
	route := imp["Routes"].([]any)[3].(map[string]any) // 203.0.113.0/24, rejected
	for _, c := range []struct {
		label string
		got   any
		want  any
	}{
		{"Result", doc[0], routecheck.Result{}},
		{"Report", imp, routecheck.Report{}},
		{"Policy", imp["Policy"], peval.Policy{}},
		{"RouteVerdict", route, routecheck.RouteVerdict{}},
		{"Verdict", route["Verdict"], verdict.Verdict{}},
		{"Route", route["Route"], verdict.Route{}},
		{"Fail", route["Verdict"].(map[string]any)["Fails"].([]any)[0], verdict.Fail{}},
	} {
		if got, want := keys(c.got), names(c.want); !slices.Equal(got, want) {
			t.Errorf("%s keys %v, want %v", c.label, got, want)
		}
	}
	wantContains(t, "JSON", out,
		`"Outcome": "rejected"`, `"Outcome": "accepted"`, `"Outcome": "undecided"`,
		`"RPKI": "invalid"`, `"RPKI": "valid"`, `"RPKI": "not_found"`,
		`"Term": "from AS64500 accept <^AS64500 AS64501$>"`, `"Filter": "<^ AS64500 AS64501 $>"`,
		`"Term": "from AS64500 accept AS64500"`, `"Filter": "{192.0.2.0/24}"`)
	wantContains(t, "compact JSON", compact(t, out), `"Communities":["64500:100"]`)

	// Missing sets by name.
	reg := write(t, "reg.txt", []byte("aut-num: AS64496\nimport: from AS64500 accept AS-NOWHERE\nsource: TEST\n"))
	_, out, _ = run(t, "-local", "AS64496", "-peer", "AS64500", "-session", capture, "-dump", reg, "-direction", "import", "-af", "ipv4", "-format", "json")
	wantContains(t, "compact JSON", compact(t, out), `"Missing":["AS-NOWHERE"]`)
}

func compact(t *testing.T, s string) string {
	t.Helper()
	var b bytes.Buffer
	if err := json.Compact(&b, []byte(s)); err != nil {
		t.Fatal(err)
	}
	return b.String()
}

// noneNote is the stderr line of a run whose registry holds none of the
// default verified sources (the golden policy's source is TEST).
const noneNote = "routecheck: route objects: none of the verified sources (RIPE, APNIC, ARIN, AFRINIC, LACNIC) is present; answers are not marked\n"

func TestParseVerifiedSources(t *testing.T) {
	got, err := parseVerifiedSources(" ripe , arin ")
	if err != nil || !slices.Equal(got, []string{"RIPE", "ARIN"}) {
		t.Errorf(`parseVerifiedSources(" ripe , arin ") = %q, %v; want [RIPE ARIN]`, got, err)
	}
	for _, c := range []struct{ in, want string }{
		{"", "-verified-sources"},
		{",", "empty"},
		{"RIPE,ripe", "RIPE"},
		{"RIPE,,ARIN", "empty"},
		{"RIPE!", `"RIPE!"`},
		{"RIPE,AR IN", `"AR IN"`},
	} {
		got, err := parseVerifiedSources(c.in)
		if err == nil {
			t.Errorf("parseVerifiedSources(%q) = %q, want an error", c.in, got)
			continue
		}
		wantContains(t, fmt.Sprintf("parseVerifiedSources(%q)", c.in), err.Error(), c.want)
	}
}

// The verified-marking fixture: a RADB registry with the policies and two
// routes, and a RIPE one (its source: in lower case) holding one of them.
// AS64500 announces both, and a third with no route object.
const (
	verifiedRADB = `aut-num: AS64496
import: from AS64500 accept ANY
source: RADB

aut-num: AS64500
export: to AS64496 announce ANY
source: RADB

route: 192.0.2.0/24
origin: AS64500
source: RADB

route: 203.0.113.0/24
origin: AS64500
source: RADB
`
	verifiedRIPE = `route: 192.0.2.0/24
origin: AS64500
source: ripe
`
)

// verifiedCapture is AS64500 announcing 192.0.2.0/24 (in RIPE and RADB),
// 203.0.113.0/24 (in RADB alone) and 198.51.100.0/24 (in neither).
func verifiedCapture(t *testing.T) string {
	t.Helper()
	return write(t, "verified.mrt", gUpdate(gAt(1), gX, gL, "192.0.2.1", "192.0.2.2", nil,
		gNLRI("192.0.2.0/24", "203.0.113.0/24", "198.51.100.0/24"), gAttrs("192.0.2.1", gSeq(gX))))
}

// verifiedDumps writes the fixture's two dumps, RADB's first.
func verifiedDumps(t *testing.T) (radb, ripe string) {
	t.Helper()
	return write(t, "radb.txt", []byte(verifiedRADB)), write(t, "ripe.txt", []byte(verifiedRIPE))
}

// routeObjAnswers reads a -format json output's route-object answers, by
// prefix, as "RouteObj/RouteObjVerified" in JSON ("true/null"), from every
// report; two reports that disagree on a route are an error.
func routeObjAnswers(t *testing.T, out string) map[string]string {
	t.Helper()
	var doc []map[string]any
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	text := func(v any) string {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	got := map[string]string{}
	add := func(rep any) {
		m, _ := rep.(map[string]any)
		routes, _ := m["Routes"].([]any)
		for _, r := range routes {
			rv := r.(map[string]any)
			p := rv["Route"].(map[string]any)["Prefix"].(string)
			a := text(rv["RouteObj"]) + "/" + text(rv["RouteObjVerified"])
			if old, ok := got[p]; ok && old != a {
				t.Errorf("%s: %s in one report, %s in another", p, old, a)
			}
			got[p] = a
		}
	}
	for _, res := range doc {
		add(res["Import"])
		exps, _ := res["Export"].([]any)
		for _, e := range exps {
			add(e)
		}
	}
	return got
}

// wantDumpAnswers are the fixture's answers with RIPE the verified source.
var wantDumpAnswers = map[string]string{
	"192.0.2.0/24":    "true/true",
	"203.0.113.0/24":  "true/false",
	"198.51.100.0/24": "false/false",
}

// TestVerifiedNoneLoaded: a registry holding no verified source turns the
// marking off, with one stderr note: every answer's RouteObjVerified is null
// and the text never says "unverified only".
func TestVerifiedNoneLoaded(t *testing.T) {
	code, out, stderr := run(t, session("-format", "json")...)
	if code != exitRejected {
		t.Fatalf("exit %d; stderr %s", code, stderr)
	}
	if stderr != noneNote {
		t.Errorf("stderr %q, want %q", stderr, noneNote)
	}
	answers := routeObjAnswers(t, out)
	if len(answers) == 0 {
		t.Fatalf("no route-object answer:\n%s", out)
	}
	for p, a := range answers {
		if !strings.HasSuffix(a, "/null") {
			t.Errorf("%s: %s, want RouteObjVerified null", p, a)
		}
	}
	_, out, _ = run(t, session("-routes", "all")...)
	if strings.Contains(out, "unverified only") {
		t.Errorf("text says unverified only with the marking off:\n%s", out)
	}

	// A -policy draft's source does not make a verified source present: it
	// supplies no route object.
	draft := write(t, "draft.txt", []byte("aut-num: AS64496\nimport: from AS64500 accept ANY\nsource: RIPE\n"))
	_, out, stderr = run(t, session("-policy", draft, "-format", "json")...)
	wantContains(t, "stderr", stderr, strings.TrimSuffix(noneNote, "\n"))
	for p, a := range routeObjAnswers(t, out) {
		if !strings.HasSuffix(a, "/null") {
			t.Errorf("draft in RIPE: %s: %s, want RouteObjVerified null", p, a)
		}
	}
}

// TestVerifiedDump: with -dump the verified answer is over the dumps' own
// verified sources (compared without regard to case).
func TestVerifiedDump(t *testing.T) {
	radb, ripe := verifiedDumps(t)
	code, out, stderr := run(t, "-local", "AS64496", "-peer", "AS64500", "-session", verifiedCapture(t),
		"-dump", radb, "-dump", ripe, "-af", "ipv4", "-format", "json")
	if code != exitOK {
		t.Fatalf("exit %d; stderr %s\n%s", code, stderr, out)
	}
	if want := "routecheck: route objects: verified sources RIPE; absent: APNIC, ARIN, AFRINIC, LACNIC\n"; stderr != want {
		t.Errorf("stderr %q, want %q", stderr, want)
	}
	if got := routeObjAnswers(t, out); !reflect.DeepEqual(got, wantDumpAnswers) {
		t.Errorf("answers %v, want %v", got, wantDumpAnswers)
	}
}

// TestTextUnverifiedOnly: with the marking on, the text says "unverified
// only" on a route object only RADB holds, and the report line counts them.
func TestTextUnverifiedOnly(t *testing.T) {
	radb, ripe := verifiedDumps(t)
	code, out, stderr := run(t, "-local", "AS64496", "-peer", "AS64500", "-session", verifiedCapture(t),
		"-dump", radb, "-dump", ripe, "-af", "ipv4", "-direction", "import", "-routes", "all")
	if code != exitOK {
		t.Fatalf("exit %d; stderr %s\n%s", code, stderr, out)
	}
	wantContains(t, "text", out,
		"; route objects 2 yes (1 unverified only), 1 no\n",
		"192.0.2.0/24  AS64500  accepted by clause 1  route object yes\n",
		"203.0.113.0/24  AS64500  accepted by clause 1  route object yes (unverified only)\n",
		"198.51.100.0/24  AS64500  accepted by clause 1  route object no\n")

	// A dump with no verified source turns the marking off: no mention.
	code, out, stderr = run(t, "-local", "AS64496", "-peer", "AS64500", "-session", verifiedCapture(t),
		"-dump", radb, "-af", "ipv4", "-direction", "import", "-routes", "all")
	if code != exitOK {
		t.Fatalf("radb only: exit %d; stderr %s\n%s", code, stderr, out)
	}
	wantContains(t, "marking off", out, "; route objects 2 yes, 1 no\n", "203.0.113.0/24  AS64500  accepted by clause 1  route object yes\n")
	if strings.Contains(out, "unverified") {
		t.Errorf("marking off, but the text says unverified:\n%s", out)
	}
}

// TestJSONRouteObjVerified: the JSON holds RouteObjVerified per route and
// the report's three counts.
func TestJSONRouteObjVerified(t *testing.T) {
	radb, ripe := verifiedDumps(t)
	code, out, stderr := run(t, "-local", "AS64496", "-peer", "AS64500", "-session", verifiedCapture(t),
		"-dump", radb, "-dump", ripe, "-af", "ipv4", "-direction", "import", "-format", "json")
	if code != exitOK {
		t.Fatalf("exit %d; stderr %s\n%s", code, stderr, out)
	}
	var doc []struct{ Import map[string]any }
	if err := json.Unmarshal([]byte(out), &doc); err != nil || len(doc) != 1 {
		t.Fatalf("%v\n%s", err, out)
	}
	rep := doc[0].Import
	for k, want := range map[string]float64{"RouteObjYes": 2, "RouteObjUnverifiedOnly": 1, "RouteObjNo": 1} {
		if rep[k] != want {
			t.Errorf("%s = %v, want %v", k, rep[k], want)
		}
	}
	if got := routeObjAnswers(t, out); !reflect.DeepEqual(got, wantDumpAnswers) {
		t.Errorf("answers %v, want %v", got, wantDumpAnswers)
	}
}

// TestVerifiedIRRdPartial: a server serving only some verified sources. IRRd
// refuses a whole "!s" list naming one it does not serve, so each is probed
// alone: the run succeeds, names the absent ones, and answers as over the
// same registries' dumps.
func TestVerifiedIRRdPartial(t *testing.T) {
	srv := serveRegistries(t, registryText{"RADB", verifiedRADB}, registryText{"RIPE", verifiedRIPE})
	args := []string{"-local", "AS64496", "-peer", "AS64500", "-session", verifiedCapture(t), "-irrd", srv, "-af", "ipv4", "-format", "json"}
	code, out, stderr := run(t, args...)
	if code != exitOK {
		t.Fatalf("exit %d; stderr %s\n%s", code, stderr, out)
	}
	if want := "routecheck: route objects: verified sources RIPE; absent: APNIC, ARIN, AFRINIC, LACNIC\n"; stderr != want {
		t.Errorf("stderr %q, want %q", stderr, want)
	}
	if got := routeObjAnswers(t, out); !reflect.DeepEqual(got, wantDumpAnswers) {
		t.Errorf("answers %v, want %v", got, wantDumpAnswers)
	}

	// The verified sources are limited to -sources: RIPE left out turns the
	// marking off.
	code, out, stderr = run(t, append(slices.Clone(args), "-sources", "RADB")...)
	if code != exitOK {
		t.Fatalf("-sources RADB: exit %d; stderr %s\n%s", code, stderr, out)
	}
	if stderr != noneNote {
		t.Errorf("-sources RADB: stderr %q, want %q", stderr, noneNote)
	}
	for p, a := range routeObjAnswers(t, out) {
		if !strings.HasSuffix(a, "/null") {
			t.Errorf("-sources RADB: %s: %s, want RouteObjVerified null", p, a)
		}
	}

	// A probe that fails otherwise than by a refusal fails the run, naming
	// the source probed.
	dead := closedPort(t)
	code, _, stderr = run(t, "-local", "AS64496", "-peer", "AS64500", "-session", verifiedCapture(t), "-irrd", dead)
	if code != exitFailed {
		t.Errorf("unreachable: exit %d, want %d; stderr %s", code, exitFailed, stderr)
	}
	wantContains(t, "unreachable stderr", stderr, "RIPE", dead)
}

// TestVerifiedProbes: a source named in -sources that the server refuses is
// absent, and a context error during a probe fails the load (never
// "absent").
func TestVerifiedProbes(t *testing.T) {
	srv := serveRegistries(t, registryText{"RADB", verifiedRADB}, registryText{"RIPE", verifiedRIPE})
	defaults, err := parseVerifiedSources("RIPE,APNIC,ARIN,AFRINIC,LACNIC")
	if err != nil {
		t.Fatal(err)
	}

	cfg := &config{irrd: srv, sources: []string{"RIPE", "APNIC"}, verified: defaults}
	reg, err := loadPolicy(context.Background(), cfg, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	defer reg.close()
	if want := "route objects: verified sources RIPE; absent: APNIC, ARIN, AFRINIC, LACNIC"; reg.verifiedNote != want {
		t.Errorf("-sources RIPE,APNIC: note %q, want %q", reg.verifiedNote, want)
	}
	if reg.verified == nil {
		t.Error("-sources RIPE,APNIC: the marking is off, want it on over RIPE")
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	reg, err = loadPolicy(ctx, &config{irrd: srv, verified: defaults}, io.Discard)
	if err == nil {
		reg.close()
		t.Fatalf("cancelled: loaded with note %q, want an error", reg.verifiedNote)
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("cancelled: %v, want context.Canceled", err)
	}
	wantContains(t, "cancelled error", err.Error(), "probing the verified source RIPE")
}

// TestVerifiedSourcesFlag: -verified-sources replaces the list; the present
// ones are named in the order the dumps' sources first appear.
func TestVerifiedSourcesFlag(t *testing.T) {
	radb, ripe := verifiedDumps(t)
	args := []string{"-local", "AS64496", "-peer", "AS64500", "-session", verifiedCapture(t),
		"-dump", radb, "-dump", ripe, "-af", "ipv4", "-format", "json"}

	code, out, stderr := run(t, append(slices.Clone(args), "-verified-sources", "RADB")...)
	if code != exitOK {
		t.Fatalf("RADB: exit %d; stderr %s\n%s", code, stderr, out)
	}
	if want := "routecheck: route objects: verified sources RADB\n"; stderr != want {
		t.Errorf("RADB: stderr %q, want %q", stderr, want)
	}
	want := map[string]string{"192.0.2.0/24": "true/true", "203.0.113.0/24": "true/true", "198.51.100.0/24": "false/false"}
	if got := routeObjAnswers(t, out); !reflect.DeepEqual(got, want) {
		t.Errorf("RADB: answers %v, want %v", got, want)
	}

	_, _, stderr = run(t, append(slices.Clone(args), "-verified-sources", "ripe,JPIRR,radb")...)
	if want := "routecheck: route objects: verified sources RADB, RIPE; absent: JPIRR\n"; stderr != want {
		t.Errorf("ripe,JPIRR,radb: stderr %q, want %q", stderr, want)
	}

	for _, bad := range []string{"", "RIPE,ripe", "RIPE!"} {
		code, _, stderr = run(t, append(slices.Clone(args), "-verified-sources", bad)...)
		if code != exitUsage {
			t.Errorf("-verified-sources %q: exit %d, want %d; stderr %s", bad, code, exitUsage, stderr)
		}
	}
}
