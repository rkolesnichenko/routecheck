package routecheck_test

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/rkolesnichenko/routecheck/internal/memprof"
	"github.com/rkolesnichenko/rpsl/object"
	"github.com/rkolesnichenko/rpsl/resolve"
	"github.com/rkolesnichenko/rpsl/types"
)

// markingSource wraps the PolicySource handed to peval.Evaluator in checkPair
// when ROUTECHECK_REALDATA_MEMPROF is set. It marks the heap (a forced GC and
// a heap profile) on an AutNum call for one of the pair's two policy owners,
// before delegating, and only for those two: peval may fetch other aut-nums,
// and a mark over a multi-GB heap is not free. Every other method, and every
// answer, is the inner source's.
type markingSource struct {
	resolve.PolicySource
	s    *memprof.Sampler
	idx  int  // the pair's 1-based index, as ROUTECHECK_REALDATA_PAIRS selects it
	p    pair // the pair whose L and X are marked
	logf func(string, ...any)

	mu sync.Mutex
	n  int           // marked calls so far
	d  time.Duration // wall time spent in those marks
}

func (m *markingSource) AutNum(ctx context.Context, as types.ASN, source string) (*object.AutNum, error) {
	if as == m.p.L || as == m.p.X {
		m.mu.Lock()
		m.n++
		t0 := time.Now()
		markHeap(m.s, m.logf, fmt.Sprintf("pair-%d-autnum-%d-%s", m.idx, m.n, as))
		m.d += time.Since(t0)
		m.mu.Unlock()
	}
	return m.PolicySource.AutNum(ctx, as, source)
}

// spent reports how many marks the source made and the wall time they took:
// they run inside the pair's timeout, so a pair's log says what they cost.
func (m *markingSource) spent() (int, time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.n, m.d
}

// markHeap marks s under label and logs the live heap, if logf is set. A nil
// s does nothing, not even log.
func markHeap(s *memprof.Sampler, logf func(string, ...any), label string) {
	if s == nil {
		return
	}
	live := s.Mark(label)
	if logf != nil {
		logf("MEMPROF: %s live %d MiB", label, live>>20)
	}
}

// policySourceFor is the source checkPair's Evaluator reads: reg.src itself
// when prof is nil, else reg.src behind a markingSource for pair p (the idx-th).
func policySourceFor(reg *irrRegistry, prof *memprof.Sampler, idx int, p pair, logf func(string, ...any)) resolve.PolicySource {
	if prof == nil {
		return reg.src
	}
	return &markingSource{PolicySource: reg.src, s: prof, idx: idx, p: p, logf: logf}
}
