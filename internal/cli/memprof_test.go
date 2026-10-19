package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/rkolesnichenko/routecheck/internal/memprof"
)

// TestMemProfileCommand profiles the heap of one run of the command, in
// process. It is opt-in: ROUTECHECK_MEMPROF_OUT=DIR names the directory the
// profiles, stdout.txt and stderr.txt go to, and ROUTECHECK_MEMPROF_ARGS the
// command line, separated by spaces (a path holds none). Exit 0 and 1 pass
// (rejected routes are a result); 2 and 3 fail the test.
func TestMemProfileCommand(t *testing.T) {
	dir, argv := os.Getenv("ROUTECHECK_MEMPROF_OUT"), os.Getenv("ROUTECHECK_MEMPROF_ARGS")
	if dir == "" || argv == "" {
		t.Skip("set ROUTECHECK_MEMPROF_OUT=DIR and ROUTECHECK_MEMPROF_ARGS to profile a command line")
	}
	args := strings.Fields(argv)
	if len(args) == 0 {
		t.Fatal("ROUTECHECK_MEMPROF_ARGS holds no argument")
	}
	if code := runProfiled(t, dir, args); code >= exitUsage {
		t.Fatalf("exit %d; stderr:\n%s", code, tail(filepath.Join(dir, "stderr.txt"), 2<<10))
	}
}

// TestMemProfileCommandSmoke runs the golden session through runProfiled.
func TestMemProfileCommandSmoke(t *testing.T) {
	var args []string
	for _, g := range goldens {
		if g.name == "session" {
			args = append(slices.Clone(g.args), "-format", "text")
		}
	}
	if args == nil {
		t.Fatal("no session golden")
	}
	dir := t.TempDir()
	if code := runProfiled(t, dir, args); code != exitRejected {
		t.Fatalf("exit %d, want %d; stderr:\n%s", code, exitRejected, tail(filepath.Join(dir, "stderr.txt"), 2<<10))
	}
	got, err := os.ReadFile(filepath.Join(dir, "stdout.txt"))
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile(filepath.Join("testdata", "golden", "session.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("stdout.txt differs from testdata/golden/session.txt")
	}
	for _, name := range []string{"series.tsv", "final.pb.gz"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Errorf("%v", err)
		}
	}
}

// runProfiled runs the command with args under a heap sampler on dir (every
// second), writing its output straight to dir/stdout.txt and dir/stderr.txt
// so that a killed run keeps what it printed, then marks "after-run" and
// stops the sampler. It returns the exit status.
func runProfiled(t *testing.T, dir string, args []string) int {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	stdout, err := os.Create(filepath.Join(dir, "stdout.txt"))
	if err != nil {
		t.Fatal(err)
	}
	defer stdout.Close()
	stderr, err := os.Create(filepath.Join(dir, "stderr.txt"))
	if err != nil {
		t.Fatal(err)
	}
	defer stderr.Close()
	s, err := memprof.Start(dir, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	code := Run(context.Background(), args, stdout, stderr)
	live := s.Mark("after-run")
	if err := s.Stop(); err != nil {
		t.Fatal(err)
	}
	t.Logf("exit %d", code)
	t.Logf("MEMPROF: after-run live %d MiB", live>>20)
	return code
}

// tail returns the last n bytes of the file name, or the error reading it.
func tail(name string, n int) string {
	b, err := os.ReadFile(name)
	if err != nil {
		return err.Error()
	}
	if len(b) > n {
		b = b[len(b)-n:]
	}
	return string(b)
}
