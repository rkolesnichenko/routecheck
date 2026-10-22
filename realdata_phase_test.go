package routecheck_test

import (
	"context"
	"fmt"
	"regexp"
	"runtime"
	"runtime/metrics"
	"runtime/pprof"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// phaseClock splits a real-data run into named phases: each runs under a
// pprof "phase" label, so a CPU profile divides by phase, and adds its CPU
// and wall time to its name. The CPU is the process's, read from the kernel
// (getrusage), so work on other goroutines counts and two spans running at
// once each count all of it. GC time and cycles come from runtime/metrics,
// which advance only when a cycle ends: a reading lags by at most one cycle,
// and the GC is read for top phases only, never split among the spans inside
// one. A name is used with top or with span, not both.
type phaseClock struct {
	mu    sync.Mutex
	order []string
	sums  map[string]*phaseSum
}

// phaseSum is what one name has accumulated.
type phaseSum struct {
	top       bool
	user, sys time.Duration
	wall      time.Duration
	gcSeconds float64
	gcCycles  uint64
}

// newPhaseClock returns a clock with no phases.
func newPhaseClock() *phaseClock {
	return &phaseClock{sums: map[string]*phaseSum{}}
}

// top runs fn as the phase name, counting its GC as well as its CPU.
func (c *phaseClock) top(ctx context.Context, name string, fn func(context.Context)) {
	c.run(ctx, name, true, fn)
}

// span runs fn as the phase name, counting its CPU but not its GC. A nil
// clock only calls fn.
func (c *phaseClock) span(ctx context.Context, name string, fn func(context.Context)) {
	if c == nil {
		fn(ctx)
		return
	}
	c.run(ctx, name, false, fn)
}

func (c *phaseClock) run(ctx context.Context, name string, top bool, fn func(context.Context)) {
	c.mu.Lock()
	s := c.sums[name]
	if s == nil {
		s = &phaseSum{top: top}
		c.sums[name] = s
		c.order = append(c.order, name)
	}
	c.mu.Unlock()

	user0, sys0 := rusage()
	gcSec0, gcCyc0 := gcReading()
	start := time.Now()
	pprof.Do(ctx, pprof.Labels("phase", name), fn)
	wall := time.Since(start)
	user1, sys1 := rusage()
	gcSec1, gcCyc1 := gcReading()

	c.mu.Lock()
	defer c.mu.Unlock()
	s.user += user1 - user0
	s.sys += sys1 - sys0
	s.wall += wall
	if top {
		s.gcSeconds += gcSec1 - gcSec0
		s.gcCycles += gcCyc1 - gcCyc0
	}
}

// lines reports the CPU of every name, then the GC of every top name, then
// the GC of the whole process so far.
func (c *phaseClock) lines() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []string
	for _, name := range c.order {
		s := c.sums[name]
		out = append(out, fmt.Sprintf("CPU: %s user %.3fs sys %.3fs wall %.3fs",
			name, s.user.Seconds(), s.sys.Seconds(), s.wall.Seconds()))
	}
	for _, name := range c.order {
		if s := c.sums[name]; s.top {
			out = append(out, fmt.Sprintf("GC: %s %.3fs over %d cycles", name, s.gcSeconds, s.gcCycles))
		}
	}
	sec, cycles := gcReading()
	return append(out, fmt.Sprintf("GC: run %.3fs over %d cycles", sec, cycles))
}

// rusage returns the process's user and system CPU time so far.
func rusage() (user, sys time.Duration) {
	var ru syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &ru); err != nil {
		panic(err)
	}
	return time.Duration(ru.Utime.Nano()), time.Duration(ru.Stime.Nano())
}

// gcReading returns the process's GC CPU seconds and GC cycles so far.
func gcReading() (seconds float64, cycles uint64) {
	s := []metrics.Sample{
		{Name: "/cpu/classes/gc/total:cpu-seconds"},
		{Name: "/gc/cycles/total:gc-cycles"},
	}
	metrics.Read(s)
	return s[0].Value.Float64(), s[1].Value.Uint64()
}

// TestPhaseClockLabels holds the pprof labels: a span adds "phase" to its
// parent's labels, and leaving it restores the parent's.
func TestPhaseClockLabels(t *testing.T) {
	c := newPhaseClock()
	ctx := context.Background()
	want := func(ctx context.Context, key, val string) {
		t.Helper()
		if got, _ := pprof.Label(ctx, key); got != val {
			t.Errorf("label %s = %q, want %q", key, got, val)
		}
	}
	c.top(ctx, "pairs", func(ctx context.Context) {
		pprof.Do(ctx, pprof.Labels("pair", "2"), func(ctx context.Context) {
			c.span(ctx, "check", func(ctx context.Context) {
				want(ctx, "phase", "check")
				want(ctx, "pair", "2")
			})
			want(ctx, "phase", "pairs")
			want(ctx, "pair", "2")
		})
	})

	calls := 0
	(*phaseClock)(nil).span(context.Background(), "check", func(ctx context.Context) {
		calls++
		if v, ok := pprof.Label(ctx, "phase"); ok {
			t.Errorf("nil clock set phase = %q", v)
		}
	})
	if calls != 1 {
		t.Errorf("nil clock called fn %d times, want 1", calls)
	}
}

// busy spins for d of wall time without sleeping.
func busy(d time.Duration) {
	for start := time.Now(); time.Since(start) < d; {
	}
}

// TestPhaseClockCPU holds that a name's spans add up, and that the CPU it
// reports is the kernel's.
func TestPhaseClockCPU(t *testing.T) {
	c := newPhaseClock()
	ctx := context.Background()
	for range 2 {
		c.span(ctx, "spin", func(context.Context) { busy(150 * time.Millisecond) })
	}
	re := regexp.MustCompile(`^CPU: spin user (\d+\.\d{3})s sys (\d+\.\d{3})s wall (\d+\.\d{3})s$`)
	var got []string
	for _, l := range c.lines() {
		if strings.HasPrefix(l, "CPU: spin ") {
			got = append(got, l)
		}
	}
	if len(got) != 1 {
		t.Fatalf("CPU: spin lines = %q, want exactly one", got)
	}
	m := re.FindStringSubmatch(got[0])
	if m == nil {
		t.Fatalf("line %q does not match %v", got[0], re)
	}
	f := func(s string) float64 {
		v, err := strconv.ParseFloat(s, 64)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	if wall := f(m[3]); wall < 0.300 {
		t.Errorf("wall = %.3f, want >= 0.300", wall)
	}
	if cpu := f(m[1]) + f(m[2]); cpu < 0.150 {
		t.Errorf("user+sys = %.3f, want >= 0.150", cpu)
	}
}

// TestPhaseClockGC holds that a top phase reports the GC cycles that ended in
// it, and that the run's line follows.
func TestPhaseClockGC(t *testing.T) {
	c := newPhaseClock()
	c.top(context.Background(), "x", func(context.Context) {
		runtime.GC()
		runtime.GC()
	})
	lines := c.lines()
	if len(lines) != 3 {
		t.Fatalf("lines = %q, want 3", lines)
	}
	if !regexp.MustCompile(`^CPU: x user `).MatchString(lines[0]) {
		t.Errorf("line 0 = %q", lines[0])
	}
	m := regexp.MustCompile(`^GC: x \d+\.\d{3}s over (\d+) cycles$`).FindStringSubmatch(lines[1])
	if m == nil {
		t.Fatalf("line 1 = %q", lines[1])
	}
	if n, _ := strconv.Atoi(m[1]); n < 2 {
		t.Errorf("cycles = %d, want >= 2", n)
	}
	if !regexp.MustCompile(`^GC: run \d+\.\d{3}s over \d+ cycles$`).MatchString(lines[2]) {
		t.Errorf("line 2 = %q", lines[2])
	}
}

// TestPhaseClockLines holds the order of the lines and that none of them can
// be taken for one of the run's own.
func TestPhaseClockLines(t *testing.T) {
	c := newPhaseClock()
	ctx := context.Background()
	empty := func(context.Context) {}
	for _, name := range []string{"load", "vrps", "pass1", "pass2"} {
		c.top(ctx, name, empty)
	}
	c.top(ctx, "pairs", func(ctx context.Context) {
		for _, name := range []string{"check", "recount", "output"} {
			c.span(ctx, name, empty)
		}
	})
	c.top(ctx, "totals", empty)

	order := []string{"load", "vrps", "pass1", "pass2", "pairs", "check", "recount", "output", "totals"}
	lines := c.lines()
	if len(lines) != 9+6+1 {
		t.Fatalf("got %d lines, want 16: %q", len(lines), lines)
	}
	for i, name := range order {
		if !strings.HasPrefix(lines[i], "CPU: "+name+" user ") {
			t.Errorf("line %d = %q, want CPU line of %s", i, lines[i], name)
		}
	}
	for i, name := range []string{"load", "vrps", "pass1", "pass2", "pairs", "totals"} {
		if !strings.HasPrefix(lines[9+i], "GC: "+name+" ") {
			t.Errorf("line %d = %q, want GC line of %s", 9+i, lines[9+i], name)
		}
	}
	if !strings.HasPrefix(lines[15], "GC: run ") {
		t.Errorf("last line = %q, want the run's GC line", lines[15])
	}
	own := regexp.MustCompile(`TOTALS|pass [12] |registry:|VRPs:|routes from|limits:|PAIRS:`)
	for _, l := range lines {
		if own.MatchString(l) {
			t.Errorf("line %q matches the run's own output", l)
		}
	}
}
