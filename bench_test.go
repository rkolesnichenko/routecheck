package routecheck_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"

	"github.com/rkolesnichenko/routecheck/observe"
	"github.com/rkolesnichenko/routecheck/verdict"
	"github.com/rkolesnichenko/rpsl/resolve/peval"
	"github.com/rkolesnichenko/rpsl/types"
)

// The real-data benchmarks read the data TestRealData reads
// (ROUTECHECK_REALDATA) and skip without it. They need the session to
// measure, which a TestRealData run names in its log ("largest import
// prefix filter"):
//
//	ROUTECHECK_BENCH_LOCAL  L, whose import policy BenchmarkDecide decides
//	ROUTECHECK_BENCH_PEER   X, whose routes both benchmarks read
//	ROUTECHECK_BENCH_AF     ipv4 (default) or ipv6, BenchmarkDecide's family
//	ROUTECHECK_BENCH_ROUTES BenchmarkDecide only: decide the routes of this
//	                        AS instead of X's (default X), when X has too few
//	                        routes to exercise the filter
//
// Run each alone, under a memory guard with an 8 GB cap (each loads the
// registries or reads a full RIB), as the published figures were. They load
// every registry the MANIFEST pins; add ROUTECHECK_REALDATA_REGISTRIES=ripe to
// the environment to compare with 0.2.0's figures, which loaded RIPE alone:
//
//	GOMAXPROCS=4 memguard.sh 8 1800 env GOWORK=off GOMAXPROCS=4 GOMEMLIMIT=6GiB \
//	  ROUTECHECK_REALDATA=$PWD/.data/realdata ROUTECHECK_BENCH_LOCAL=AS… ROUTECHECK_BENCH_PEER=AS… [ROUTECHECK_BENCH_ROUTES=AS…] \
//	  go test -count=1 -timeout 30m -run '^$' -bench BenchmarkDecide -benchtime 5s -benchmem .
//	GOMAXPROCS=4 memguard.sh 8 2400 env GOWORK=off GOMAXPROCS=4 GOMEMLIMIT=6GiB \
//	  ROUTECHECK_REALDATA=$PWD/.data/realdata ROUTECHECK_BENCH_LOCAL=AS… ROUTECHECK_BENCH_PEER=AS… \
//	  go test -count=1 -timeout 40m -run '^$' -bench BenchmarkCollector -benchtime 2x -benchmem .

// benchSession reads the benchmark's session from the environment.
func benchSession(b *testing.B) (local, peer types.ASN, af types.AddrFamily) {
	b.Helper()
	read := func(name string) types.ASN {
		s := os.Getenv(name)
		if s == "" {
			b.Skipf("%s is not set: take it from TestRealData's log (largest import prefix filter)", name)
		}
		as, err := types.ParseASN(s)
		if err != nil {
			b.Fatalf("%s=%q is not an AS number (AS64496)", name, s)
		}
		return as
	}
	local, peer = read("ROUTECHECK_BENCH_LOCAL"), read("ROUTECHECK_BENCH_PEER")
	af = types.AddrFamily{AFI: types.AFIv4, SAFI: types.SAFIUnicast}
	switch s := os.Getenv("ROUTECHECK_BENCH_AF"); s {
	case "", "ipv4":
	case "ipv6":
		af.AFI = types.AFIv6
	default:
		b.Fatalf("ROUTECHECK_BENCH_AF=%q is not ipv4 or ipv6", s)
	}
	return local, peer, af
}

// decideSetup is BenchmarkDecide's policy and routes, built once for every
// b.N the benchmark is run with.
var decideSetup struct {
	once   sync.Once
	cp     *verdict.Compiled
	routes []verdict.Route
	ranges int
	// memoBound is the most key bytes the path memo could hold for these
	// routes: every path test against every distinct known path.
	memoBound int
	err       error
}

// BenchmarkDecide decides X's routes (or ROUTECHECK_BENCH_ROUTES's), read
// from that AS's TestRealData filtered file, else from the RIBs, against
// L's real import policy toward X, compiled once: ns/op is per route. The
// routes are cycled over b.N, so from the second pass on every (path test,
// path) answer is in the path memo: the figure is for a warm memo. A check
// decides each route once, where the memo helps only routes sharing a path,
// so its cost per route can be higher.
func BenchmarkDecide(b *testing.B) {
	rd := openRealData(b)
	local, peer, af := benchSession(b)
	from := peer
	if v := os.Getenv("ROUTECHECK_BENCH_ROUTES"); v != "" {
		as, err := types.ParseASN(v)
		if err != nil {
			b.Fatalf("ROUTECHECK_BENCH_ROUTES=%q is not an AS number (AS64496)", v)
		}
		from = as
	}
	s := &decideSetup
	s.once.Do(func() {
		reg := loadRegistry(b, rd.dumps, "")
		ev := peval.Evaluator{Src: reg.src}
		p, err := ev.Import(context.Background(), peval.Session{Local: local, Peer: peer, AF: af})
		if err != nil {
			s.err = err
			return
		}
		tests := 0
		for _, c := range p.Clauses {
			for _, cj := range c.Filter.Conjuncts {
				s.ranges += cj.Prefixes.Len() + cj.NotPrefixes.Len()
				tests += len(cj.Paths)
			}
		}
		s.cp = verdict.Compile(p)
		inputs := rd.ribs
		if f := filepath.Join(rd.dir, "filtered", fmt.Sprintf("AS%d.mrt", from)); fileExists(f) {
			inputs = []string{f}
		}
		seq, _ := observe.Collector(readMRT(inputs...), from)
		for _, o := range drain(b, seq) {
			if a, ok := addrFamily(o.Family); ok && a == af {
				s.routes = append(s.routes, o.Route)
			}
		}
		paths := map[string]bool{}
		for _, r := range s.routes {
			if k := fmt.Sprint(r.Path); r.PathKnown && !paths[k] {
				paths[k] = true
				s.memoBound += tests * (4 + 4*len(r.Path))
			}
		}
	})
	if s.err != nil {
		b.Fatal(s.err)
	}
	if len(s.routes) == 0 {
		b.Skipf("AS%d has no %s routes", from, af)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.cp.Decide(s.routes[i%len(s.routes)])
	}
	b.StopTimer()
	b.ReportMetric(float64(len(s.routes)), "routes")
	b.ReportMetric(float64(s.ranges), "ranges")
	b.ReportMetric(float64(s.memoBound), "memo-key-bytes-bound")
}

// BenchmarkCollector reads the first RIB of MANIFEST (route-views2) for X
// with observe.Collector, as collector mode does, the RIB as downloaded
// (bzip2 included). Besides time per pass it reports the observations, the
// collector peers per observation, and the heap they retain per
// observation once the pass is over.
func BenchmarkCollector(b *testing.B) {
	rd := openRealData(b)
	_, peer, _ := benchSession(b)
	rib := rd.ribs[0]
	var obs []observe.Observation
	var retained uint64
	var peers int
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		obs = nil
		var m0, m1 runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&m0)
		b.StartTimer()
		seq, _ := observe.Collector(readMRT(rib), peer)
		obs = drain(b, seq)
		b.StopTimer()
		runtime.GC()
		runtime.ReadMemStats(&m1)
		retained = 0
		if m1.HeapAlloc > m0.HeapAlloc { // the heap may have shrunk
			retained = m1.HeapAlloc - m0.HeapAlloc
		}
		peers = 0
		for _, o := range obs {
			peers += o.Evidence.CollectorPeers
		}
		b.StartTimer()
	}
	b.StopTimer()
	if len(obs) == 0 {
		b.Skipf("AS%d is on no path of %s", peer, filepath.Base(rib))
	}
	b.ReportMetric(float64(len(obs)), "obs")
	b.ReportMetric(float64(peers)/float64(len(obs)), "peers/obs")
	b.ReportMetric(float64(retained)/float64(len(obs)), "retained-B/obs")
	runtime.KeepAlive(obs)
}

func fileExists(name string) bool {
	st, err := os.Stat(name)
	return err == nil && st.Mode().IsRegular()
}
