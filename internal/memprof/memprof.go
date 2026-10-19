// Package memprof is a heap sampler for the memory profile of routecheck's
// big runs. It is test support: the real-data test and an opt-in test in
// internal/cli import it, and the command (cmd/routecheck) must not, which
// TestNotInCommand holds.
//
// A Sampler writes dir/series.tsv (one line per sample, flushed per line so
// a killed run keeps all but the line being written), a heap profile
// peak-NNN.pb.gz when the in-use heap reaches a new high, a profile at each
// Mark of the live heap, and final.pb.gz at Stop. start.txt holds the
// wall-clock instant (RFC 3339, nanoseconds) that t_ms counts from, to line
// the series up with an external log.
//
// A peak profile (peak-NNN.pb.gz) shows the live heap as of the last
// completed GC, because pprof's heap profile does not force one; the series
// line written with it carries that GC's num_gc. Only mark profiles, and the
// live-heap figure Mark returns, follow a forced GC.
//
// A new high inside the 5 s cooldown since the last peak profile, or under
// 1.05 times the last profiled high, is in the series but gets no profile.
//
// Profiles are written to a .tmp name and renamed, so a killed run leaves
// only whole profiles.
package memprof

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"strings"
	"sync"
	"time"
)

const (
	header = "t_ms\theap_inuse\theap_alloc\tsys\tnext_gc\tnum_gc\tmark\n"

	// A peak profile needs a heap this much above the last profiled high
	// and this long since the last peak profile.
	peakGrowth   = 1.05
	peakInterval = 5 * time.Second
)

// Sampler samples the Go heap. The zero value is not usable: use Start. A
// nil *Sampler is valid and does nothing.
type Sampler struct {
	dir   string
	start time.Time

	mu       sync.Mutex // guards everything below and the series file
	series   *os.File
	stopped  bool
	err      error // the first error met while sampling
	marks    int
	peaks    int
	high     uint64    // HeapInuse at the last peak profile
	lastPeak time.Time // when the last peak profile was written

	quit chan struct{}
	done chan struct{}
}

// Start creates dir, writes the series header and starts sampling every
// `every`. It samples once at once, so the series is never empty.
func Start(dir string, every time.Duration) (*Sampler, error) {
	if every <= 0 {
		return nil, fmt.Errorf("memprof: sampling interval %v must be positive", every)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	f, err := os.Create(filepath.Join(dir, "series.tsv"))
	if err != nil {
		return nil, err
	}
	if _, err := f.WriteString(header); err != nil {
		f.Close()
		return nil, err
	}
	start := time.Now()
	if err := os.WriteFile(filepath.Join(dir, "start.txt"), []byte(start.Format(time.RFC3339Nano)+"\n"), 0o644); err != nil {
		f.Close()
		return nil, err
	}
	s := &Sampler{
		dir:    dir,
		start:  start,
		series: f,
		quit:   make(chan struct{}),
		done:   make(chan struct{}),
	}
	s.sample()
	go s.run(every)
	return s, nil
}

func (s *Sampler) run(every time.Duration) {
	defer close(s.done)
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-s.quit:
			return
		case <-t.C:
			s.sample()
		}
	}
}

// fail records the first error; callers hold s.mu.
func (s *Sampler) fail(err error) {
	if err != nil && s.err == nil {
		s.err = err
	}
}

// line appends one series line, written unbuffered; callers hold s.mu.
func (s *Sampler) line(elapsed time.Duration, m *runtime.MemStats, mark string) {
	_, err := fmt.Fprintf(s.series, "%d\t%d\t%d\t%d\t%d\t%d\t%s\n",
		elapsed.Milliseconds(), m.HeapInuse, m.HeapAlloc, m.Sys, m.NextGC, m.NumGC, mark)
	s.fail(err)
}

// sample reads the heap, appends a series line and, at a new high, writes a
// peak profile.
func (s *Sampler) sample() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stopped {
		return
	}
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	now := time.Now()
	s.line(now.Sub(s.start), &m, "")
	if float64(m.HeapInuse) >= peakGrowth*float64(s.high) && (s.peaks == 0 || now.Sub(s.lastPeak) >= peakInterval) {
		s.peaks++
		s.high = m.HeapInuse
		s.lastPeak = now
		s.fail(s.profile(fmt.Sprintf("peak-%03d.pb.gz", s.peaks)))
	}
}

// profile writes the heap profile to dir/name.
func (s *Sampler) profile(name string) error {
	path := filepath.Join(s.dir, name)
	f, err := os.Create(path + ".tmp")
	if err != nil {
		return err
	}
	err = pprof.Lookup("heap").WriteTo(f, 0)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(path+".tmp", path)
	}
	if err != nil {
		os.Remove(path + ".tmp")
	}
	return err
}

// Mark runs a garbage collection, writes mark-NNN-<label>.pb.gz, appends a
// series line whose mark column is label and returns the live heap in bytes
// (HeapAlloc after the collection). After Stop it does nothing and returns 0.
func (s *Sampler) Mark(label string) uint64 {
	if s == nil {
		return 0
	}
	runtime.GC()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stopped {
		return 0
	}
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	s.line(time.Since(s.start), &m, column(label))
	s.marks++
	s.fail(s.profile(fmt.Sprintf("mark-%03d-%s.pb.gz", s.marks, sanitize(label))))
	return m.HeapAlloc
}

// column makes label safe for a tab-separated line: tab, CR and LF become
// a space.
func column(label string) string {
	return strings.Map(func(r rune) rune {
		if r == '\t' || r == '\r' || r == '\n' {
			return ' '
		}
		return r
	}, label)
}

// sanitize maps every rune outside [A-Za-z0-9._-] to '_'.
func sanitize(label string) string {
	out := make([]rune, 0, len(label))
	for _, r := range label {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '_', r == '-':
			out = append(out, r)
		default:
			out = append(out, '_')
		}
	}
	return string(out)
}

// Stop ends sampling, writes final.pb.gz and closes the series file. It
// returns the first error met while sampling or here. Calling it again does
// nothing and returns nil.
func (s *Sampler) Stop() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	if s.stopped {
		s.mu.Unlock()
		return nil
	}
	s.stopped = true
	s.mu.Unlock()

	close(s.quit)
	<-s.done

	s.mu.Lock()
	defer s.mu.Unlock()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	s.line(time.Since(s.start), &m, "")
	s.fail(s.profile("final.pb.gz"))
	s.fail(s.series.Close())
	return s.err
}
