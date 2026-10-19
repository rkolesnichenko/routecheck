package memprof

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

// held keeps test allocations reachable so the GC cannot free them.
var held [][]byte

func hold(n int) {
	b := make([]byte, n)
	for i := 0; i < len(b); i += 4096 {
		b[i] = 1
	}
	held = append(held, b)
}

func release() { held = nil }

func readLines(t *testing.T, path string) []string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return strings.Split(strings.TrimRight(string(data), "\n"), "\n")
}

func TestSamplerWritesSeriesAndMarks(t *testing.T) {
	defer release()
	dir := filepath.Join(t.TempDir(), "prof")
	s, err := Start(dir, 10*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	hold(64 << 20)
	live := s.Mark("after alloc")
	runtime.KeepAlive(held)
	if live < 64<<20 {
		t.Errorf("Mark returned %d live bytes, want >= 64 MiB", live)
	}
	time.Sleep(30 * time.Millisecond)
	if err := s.Stop(); err != nil {
		t.Fatal(err)
	}
	lines := readLines(t, filepath.Join(dir, "series.tsv"))
	if lines[0] != "t_ms\theap_inuse\theap_alloc\tsys\tnext_gc\tnum_gc\tmark" {
		t.Errorf("header = %q", lines[0])
	}
	if len(lines) < 3 {
		t.Errorf("series has %d lines, want >= 3", len(lines))
	}
	found := false
	for _, l := range lines[1:] {
		f := strings.Split(l, "\t")
		if len(f) != 7 {
			t.Errorf("line %q has %d columns, want 7", l, len(f))
			continue
		}
		if f[6] == "after alloc" {
			found = true
		}
	}
	if !found {
		t.Errorf("no series line with mark %q", "after alloc")
	}
	for _, name := range []string{"mark-001-after_alloc.pb.gz", "final.pb.gz"} {
		if st, err := os.Stat(filepath.Join(dir, name)); err != nil || st.Size() == 0 {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestPeakProfilesAreRateLimited(t *testing.T) {
	defer release()
	dir := filepath.Join(t.TempDir(), "prof")
	s, err := Start(dir, 10*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 10; i++ {
		hold(8 << 20)
		time.Sleep(60 * time.Millisecond)
	}
	runtime.KeepAlive(held)
	if err := s.Stop(); err != nil {
		t.Fatal(err)
	}
	peaks, err := filepath.Glob(filepath.Join(dir, "peak-*.pb.gz"))
	if err != nil {
		t.Fatal(err)
	}
	if len(peaks) != 1 {
		t.Errorf("%d peak profiles %v, want exactly 1", len(peaks), peaks)
	}
}

func TestSeriesFlushedPerLine(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "prof")
	s, err := Start(dir, 10*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Stop()
	path := filepath.Join(dir, "series.tsv")
	size := func() int64 {
		st, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		return st.Size()
	}
	first := size()
	deadline := time.Now().Add(5 * time.Second)
	for size() <= first {
		if time.Now().After(deadline) {
			t.Fatalf("series.tsv stayed at %d bytes without Stop", first)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestSamplerNilAndDoubleStop(t *testing.T) {
	var n *Sampler
	if got := n.Mark("x"); got != 0 {
		t.Errorf("nil Mark = %d, want 0", got)
	}
	if err := n.Stop(); err != nil {
		t.Errorf("nil Stop = %v", err)
	}
	s, err := Start(filepath.Join(t.TempDir(), "prof"), 10*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Stop(); err != nil {
		t.Errorf("first Stop = %v", err)
	}
	if err := s.Stop(); err != nil {
		t.Errorf("second Stop = %v", err)
	}
	if got := s.Mark("late"); got != 0 {
		t.Errorf("Mark after Stop = %d, want 0", got)
	}
}

func TestSanitize(t *testing.T) {
	if got := sanitize("a b/c.d-e_é"); got != "a_b_c.d-e__" {
		t.Errorf("sanitize = %q", got)
	}
}

func TestNotInCommand(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go command not on PATH")
	}
	cmd := exec.Command("go", "list", "-deps", "./cmd/routecheck")
	cmd.Dir = filepath.Join("..", "..")
	cmd.Env = append(os.Environ(), "GOWORK=off")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go list: %v\n%s", err, out)
	}
	for _, l := range strings.Split(string(out), "\n") {
		if strings.HasSuffix(strings.TrimSpace(l), "/internal/memprof") {
			t.Errorf("cmd/routecheck depends on %s", l)
		}
	}
}

func TestSeriesOrderAndMarks(t *testing.T) {
	defer release()
	dir := filepath.Join(t.TempDir(), "prof")
	s, err := Start(dir, time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		hold(1 << 20)
		s.Mark("m\t" + strconv.Itoa(i) + "\nx")
		time.Sleep(3 * time.Millisecond)
	}
	if err := s.Stop(); err != nil {
		t.Fatal(err)
	}
	lines := readLines(t, filepath.Join(dir, "series.tsv"))[1:]
	var prevT, prevGC, marks int64
	for _, l := range lines {
		f := strings.Split(l, "\t")
		if len(f) != 7 {
			t.Fatalf("line %q has %d columns, want 7", l, len(f))
		}
		ms, _ := strconv.ParseInt(f[0], 10, 64)
		gc, _ := strconv.ParseInt(f[5], 10, 64)
		if ms < prevT {
			t.Errorf("t_ms went back: %d after %d", ms, prevT)
		}
		if f[6] != "" {
			marks++
			if gc < prevGC {
				t.Errorf("mark line num_gc %d below the previous line's %d", gc, prevGC)
			}
		}
		prevT, prevGC = ms, gc
	}
	if marks != 5 {
		t.Errorf("%d mark lines, want 5", marks)
	}
}

func TestTmpFilesAndStart(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "prof")
	s, err := Start(dir, 5*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	s.Mark("x")
	time.Sleep(20 * time.Millisecond)
	if err := s.Stop(); err != nil {
		t.Fatal(err)
	}
	tmp, _ := filepath.Glob(filepath.Join(dir, "*.tmp"))
	if len(tmp) != 0 {
		t.Errorf("leftover tmp files: %v", tmp)
	}
	data, err := os.ReadFile(filepath.Join(dir, "start.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(string(data))); err != nil {
		t.Errorf("start.txt %q: %v", data, err)
	}
}
