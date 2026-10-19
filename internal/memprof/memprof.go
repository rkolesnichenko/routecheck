// Package memprof is a heap sampler for the memory profile of routecheck's
// big runs. It is test support: the real-data test and an opt-in test in
// internal/cli import it, and the command (cmd/routecheck) must not, which
// TestNotInCommand holds.
//
// A Sampler writes dir/series.tsv (one line per sample, flushed per line so
// a killed run keeps all but the line being written), a heap profile
// peak-NNN.pb.gz when the in-use heap reaches a new high, a profile at each
// Mark of the live heap, and final.pb.gz at Stop.
package memprof

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"runtime/pprof"
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
	s := &Sampler{
		dir:    dir,
		start:  time.Now(),
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
func (s *Sampler) line(m *runtime.MemStats, mark string) {
	_, err := fmt.Fprintf(s.series, "%d\t%d\t%d\t%d\t%d\t%d\t%s\n",
		time.Since(s.start).Milliseconds(), m.HeapInuse, m.HeapAlloc, m.Sys, m.NextGC, m.NumGC, mark)
	s.fail(err)
}

// sample reads the heap, appends a series line and, at a new high, writes a
// peak profile.
func (s *Sampler) sample() {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stopped {
		return
	}
	s.line(&m, "")
	now := time.Now()
	if float64(m.HeapInuse) >= peakGrowth*float64(s.high) && (s.peaks == 0 || now.Sub(s.lastPeak) >= peakInterval) {
		s.peaks++
		s.high = m.HeapInuse
		s.lastPeak = now
		s.fail(s.profile(fmt.Sprintf("peak-%03d.pb.gz", s.peaks)))
	}
}

// profile writes the heap profile to dir/name.
func (s *Sampler) profile(name string) error {
	f, err := os.Create(filepath.Join(s.dir, name))
	if err != nil {
		return err
	}
	err = pprof.Lookup("heap").WriteTo(f, 0)
	if cerr := f.Close(); err == nil {
		err = cerr
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
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stopped {
		return 0
	}
	s.marks++
	s.fail(s.profile(fmt.Sprintf("mark-%03d-%s.pb.gz", s.marks, sanitize(label))))
	s.line(&m, label)
	return m.HeapAlloc
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
	s.fail(s.profile("final.pb.gz"))
	s.fail(s.series.Close())
	return s.err
}
