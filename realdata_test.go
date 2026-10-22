package routecheck_test

import (
	"bufio"
	"bytes"
	"cmp"
	"compress/gzip"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"iter"
	"maps"
	"math/rand/v2"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"runtime/pprof"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rkolesnichenko/mrt"
	"github.com/rkolesnichenko/mrt/bgp"
	"github.com/rkolesnichenko/routecheck"
	"github.com/rkolesnichenko/routecheck/internal/memprof"
	"github.com/rkolesnichenko/routecheck/internal/mrtgen"
	"github.com/rkolesnichenko/routecheck/observe"
	"github.com/rkolesnichenko/routecheck/verdict"
	"github.com/rkolesnichenko/rpsl"
	"github.com/rkolesnichenko/rpsl/object"
	"github.com/rkolesnichenko/rpsl/policy"
	"github.com/rkolesnichenko/rpsl/resolve"
	"github.com/rkolesnichenko/rpsl/resolve/peval"
	"github.com/rkolesnichenko/rpsl/resolve/rpki"
	"github.com/rkolesnichenko/rpsl/types"
)

// TestRealData is the opt-in real-data run (spec §10): RIPE's database
// dumps, the newest route-views2 RIB and RIS rrc00 bview, and NTT's VRPs when
// scripts/fetch-data.sh could fetch them, all pinned in
// $ROUTECHECK_REALDATA/MANIFEST. Run it alone, under a memory guard (8 GB
// cap), as the published figures were (memguard.sh LIMIT_GB TIMEOUT_S CMD,
// rpsl's tool). At the guard's normal priority, as below, the 0.2 run (a
// RIPE-only load) took 3m7s by the test's TOTALS line (188 s and 4.2 GB peak
// RSS by the guard, over the whole go test command); 0.1.0's (RIPE only too),
// whose command did not ask for normal priority, took 15m8s by TOTALS (909 s
// and 2.6 GB by the guard). On 2026-10-18 with every registry it took 3m25s
// and 6,215 MB (.data/realdata-every-registry.log), and with
// ROUTECHECK_REALDATA_REGISTRIES=ripe 3m31s and 4,741 MB
// (.data/realdata-ripe-only.log):
//
//	scripts/fetch-data.sh
//	MEMGUARD_NORMAL_PRIORITY=1 GOMAXPROCS=4 memguard.sh 8 6000 env GOWORK=off GOMAXPROCS=4 GOMEMLIMIT=6GiB \
//	  ROUTECHECK_REALDATA=$PWD/.data/realdata \
//	  go test -count=1 -timeout 100m -run TestRealData -v .
//
// It loads every registry dump MANIFEST pins as the command does (one Corpus
// keeping policy, behind a resolve.Cache), in this precedence order, first
// wins: RIPE, APNIC, ARIN, AFRINIC, LACNIC, RADB, then RADB's mirrors (ALTDB,
// BBOI, BELL, CANARIE, JPIRR, NESTEGG, NTTCOM, PANIX, REACH, TC); a source's
// precedence is that of the first object read with it. The sampled pairs come
// from RIPE's files only (only its aut-nums are candidates for L and X), so
// loading more registries changes what the checks resolve, never which pairs
// are checked. It then reads the RIBs once to learn which ASes appear on a
// path, and picks a seeded sample of aut-nums L that name an AS X in a
// literal "import: from X" (or mp-import), X on some path and X's own
// aut-num in RIPE (the export direction reads it). A second read writes,
// for each X, the RIB entries whose path holds X into
// $ROUTECHECK_REALDATA/filtered/AS<X>.mrt (the same attribute bytes, each
// RIB's PEER_INDEX_TABLE first), so that each check reads its own X's share
// instead of 5 GB; that the filter loses nothing is checked twice: the
// smallest X's observations over the whole RIBs equal those over its file,
// and every check's Through equals the first read's count of entries
// through X.
//
// Each (L, X) is checked in collector mode, both directions, ipv4 and ipv6
// unicast, under its own timeout (ROUTECHECK_CHECK_TIMEOUT, a Go duration,
// default 600s, covering the read of X's file and the decisions: the
// largest real check, AS9086 from AS6762, took 61-69 s across the 0.1.0
// runs, so a 60 s default would count it as a timeout and a default run
// would not reproduce the published figures; 8.7 s in 0.2's). A timeout is
// counted; any other error fails the test, a *resolve.SetTooLargeError from
// Check included (ruling R27: a set over one of rpsl's limits makes only its
// report unevaluable, tallied with the others below; the error is still
// counted so the totals show it). A policy peval cannot evaluate because it
// names AS-ANY or RS-ANY in filter position (ruling R19) is not an error:
// its report's routes are Undecided with the reason "unevaluable", tallied
// with the others and listed per pair. A set reaching AS-ANY named in an
// AS-path regexp is evaluated (any one AS there): the Accepted routes whose
// Verdict.AnySets names one are counted per direction and listed by
// (report, set). It logs per pair the observations, the outcomes per direction, the
// Undecided reasons tallied, the Rejected routes whose failing clause names
// a missing set, examples of Rejected routes, the hygiene reads and the wall
// time; then the totals, the largest import prefix filter (the policy
// BenchmarkDecide takes), the bound on the verdict path memo, and every
// path-too-expensive verdict.
//
// ROUTECHECK_REALDATA_REGISTRIES (comma-separated, case-insensitive; default
// every registry in MANIFEST) loads only those registries' dumps, still in
// the order above; naming one MANIFEST does not hold fails the test.
// ROUTECHECK_REALDATA_LOAD_ONLY=1 loads the registries, logs a LOAD: line
// (registries, sources in order, objects per source, the RIPE aut-nums
// selectable, the load time and the heap in use after a GC) and returns before
// reading VRPs or RIBs.
//
// ROUTECHECK_REALDATA_MAX_PREFIXES (a positive integer; unset means rpsl's
// default) sets Expander.MaxPrefixes, as the command's -max-prefixes does; the
// value is logged in a limits: line before the pairs.
//
// ROUTECHECK_REALDATA_OUT=DIR writes DIR/missing-sets.tsv (dir, set, routes:
// the missing-set counts the TOTALS lines show, sorted) and
// DIR/rejected-missing.tsv (key, outcome, undecided reasons, sets: one line per
// Rejected route whose failing clauses name a missing set). A key is
// pair|direction|family|neighbour|prefix|path, see routeKey.
// ROUTECHECK_REALDATA_TRACK=FILE (a rejected-missing.tsv; needs OUT) also
// writes DIR/tracked.tsv: a line for each key in FILE, in FILE's order, with
// this run's outcome for it, or "none" when its pair was not checked (or timed
// out) in this run.
// OUT also writes DIR/routes.tsv.gz (gzip; key, outcome, route object
// "yes"/"no"/"unknown", RPKI state or "none", the Undecided reason kinds: one
// line for every route of every report with a policy, pairs in PAIRS order,
// one pair's lines together; a pair that timed out or failed writes none) and
// DIR/pairs.tsv (pair, status "checked", "timeout", "error" or "not
// selected": every pair of PAIRS, in its order), which an offline comparison
// of runs reads. While the i-th pair is checked, its routes.tsv.gz and
// rejected-missing.tsv lines are written, as each report is read, to
// DIR/.pair-<i>.routes and DIR/.pair-<i>.rejected, and held nowhere in
// memory; they are appended to the outputs once the pair is checked, and
// removed whatever its status.
//
// ROUTECHECK_REALDATA_EXTRA=FILE is an RPSL dump (gzip or plain) loaded after
// every MANIFEST dump, as the registry "extra": its objects keep their own
// source:, so a source not seen before ranks last, and it never feeds the
// selection maps (the pairs stay those of RIPE's files).
// ROUTECHECK_REALDATA_ROUTES_FROM (comma-separated, case-insensitive registry
// names; default every registry) keeps route and route6 objects only from
// those registries' dumps: every other registry still supplies its sets,
// aut-nums and the rest, but its routes (and their member-of: claims) are
// dropped, and a routes from: line logs the count dropped. It can be used with
// ROUTECHECK_REALDATA_EXTRA: the "extra" registry is never in the list, so the
// extra dump's routes are dropped and its sets and other objects load.
// ROUTECHECK_REALDATA_PAIRS=SEL (1-based indices into the PAIRS: list, such as
// 1-20,31; default all) checks only those pairs; the others are logged as
// "not selected", added to no total and written as "none" in tracked.tsv.
//
// ROUTECHECK_REALDATA_MEMPROF=DIR profiles the heap (internal/memprof) into
// DIR: a series.tsv sampled every second, a profile at each new high of the
// heap in use, and a mark (a forced GC, then a profile of the live heap, and a
// "MEMPROF: <label> live <MiB> MiB" log line) at "load" (after the registry
// load), "pair-<i>-start" and "pair-<i>-end" around each checked pair (i is
// the pair's 1-based index, as PAIRS selects it) and, within a pair, at each
// fetch of the aut-num of its L or of its X ("pair-<i>-autnum-<n>-AS<asn>").
// Those run per address family (IPv4, then IPv6): L's import report first,
// then X's export report toward each neighbour in ascending ASN order, and
// each report starts with exactly one marked fetch, of its policy owner's
// aut-num (peval fetches it once per evaluation). The marks run inside the
// pair's timeout and count against ROUTECHECK_CHECK_TIMEOUT: raise it when
// profiling a large pair. A "MEMPROF: pair-<i> marks <n> in <duration>" line
// says what they took. Unset, nothing is sampled or marked and the run is as
// before.
//
// ROUTECHECK_REALDATA_SAMPLE (default 50), ROUTECHECK_REALDATA_REGEXP_SAMPLE
// (default 10: the pairs added whose import term has an AS-path regexp,
// which the plain sample may not draw at all) and ROUTECHECK_REALDATA_SEED
// (default 1) choose the sample.
//
// Each phase runs under a pprof "phase" label (load, vrps, pass1, pass2, pairs,
// check, recount, output, totals), and each checked pair under a "pair" label
// (its 1-based index). After the TOTALS the test logs a CPU: line per phase
// (the process's CPU, user and system, and the wall time) and a GC: line per
// top-level phase (GC time and cycles, which advance only when a cycle ends:
// a reading lags by at most one cycle). To profile, add -cpuprofile FILE -o BIN
// to the command above, and GODEBUG=gctrace=1 to the environment for a line per
// GC cycle. On macOS the profile's samples land on threads in system calls or
// asleep (measured, see the CHANGELOG), so it ranks functions at best; the CPU:
// lines are the phase figures.
func TestRealData(t *testing.T) {
	rd := openRealData(t)
	timeout := envDuration(t, "ROUTECHECK_CHECK_TIMEOUT", 600*time.Second)
	sample := envInt(t, "ROUTECHECK_REALDATA_SAMPLE", 50)
	reSample := envInt(t, "ROUTECHECK_REALDATA_REGEXP_SAMPLE", 10)
	seed := envInt(t, "ROUTECHECK_REALDATA_SEED", 1)
	maxPrefixes, err := parseMaxPrefixes(os.Getenv("ROUTECHECK_REALDATA_MAX_PREFIXES"))
	if err != nil {
		t.Fatal(err)
	}
	outDir := os.Getenv("ROUTECHECK_REALDATA_OUT")
	trackFile := os.Getenv("ROUTECHECK_REALDATA_TRACK")
	if trackFile != "" && outDir == "" {
		t.Fatal("ROUTECHECK_REALDATA_TRACK needs ROUTECHECK_REALDATA_OUT")
	}
	var out *realOut
	if outDir != "" {
		var err error
		if out, err = openRealOut(outDir, trackFile); err != nil {
			t.Fatal(err)
		}
		defer out.abort()
	}
	var prof *memprof.Sampler
	if dir := os.Getenv("ROUTECHECK_REALDATA_MEMPROF"); dir != "" {
		var err error
		if prof, err = memprof.Start(dir, time.Second); err != nil {
			t.Fatalf("ROUTECHECK_REALDATA_MEMPROF: %v", err)
		}
		defer func() {
			if err := prof.Stop(); err != nil {
				t.Errorf("ROUTECHECK_REALDATA_MEMPROF: %v", err)
			}
		}()
	}
	ctx := context.Background()
	clock := newPhaseClock()
	start := time.Now()

	var (
		extra      string
		routesFrom map[string]bool
		reg        *irrRegistry
		loadOnly   bool
	)
	clock.top(ctx, "load", func(context.Context) {
		t0 := time.Now()
		extra = os.Getenv("ROUTECHECK_REALDATA_EXTRA")
		var err error
		routesFrom, err = parseRoutesFrom(os.Getenv("ROUTECHECK_REALDATA_ROUTES_FROM"))
		if err != nil {
			t.Fatalf("ROUTECHECK_REALDATA_ROUTES_FROM: %v", err)
		}
		reg = loadRegistry(t, rd.dumps, extra, routesFrom)
		loadTime := since(t0)
		var per []string
		for _, s := range reg.sources {
			per = append(per, fmt.Sprintf("%s=%d", s, reg.perSource[s]))
		}
		nDumps := len(rd.dumps)
		if extra != "" {
			nDumps++
		}
		t.Logf("registry: %d objects from %d dumps of %d registries (%s), sources in precedence order %s, objects per source %s; %d RIPE aut-nums, %d naming a literal import peer (%d with an AS-path regexp toward one), in %s (heap in use %s)",
			reg.objects, nDumps, len(reg.registries), strings.Join(reg.registries, ","), strings.Join(reg.sources, ","), strings.Join(per, ", "), len(reg.autnums), len(reg.imports), len(reg.reImports), loadTime, heapInUse())
		markHeap(prof, t.Logf, "load")
		if routesFrom == nil {
			t.Logf("routes from: every registry")
		} else {
			var names, dropped []string
			for _, n := range append(slices.Clone(registryOrder), "extra") {
				if routesFrom[n] {
					names = append(names, n)
				}
				if reg.droppedRoutes[n] > 0 {
					dropped = append(dropped, fmt.Sprintf("%s=%d", n, reg.droppedRoutes[n]))
				}
			}
			t.Logf("routes from: %s; dropped route objects per registry %s; dropped member-of claimants %d",
				strings.Join(names, ","), strings.Join(dropped, ", "), reg.droppedClaims)
		}
		if maxPrefixes == 0 {
			t.Logf("limits: MaxPrefixes rpsl's default")
		} else {
			t.Logf("limits: MaxPrefixes %d", maxPrefixes)
		}
		if os.Getenv("ROUTECHECK_REALDATA_LOAD_ONLY") == "1" {
			runtime.GC()
			t.Logf("LOAD: registries %s; sources %s; objects per source %s; %d RIPE aut-nums selectable; loaded in %s; heap in use after GC %s",
				strings.Join(reg.registries, ","), strings.Join(reg.sources, ","), strings.Join(per, ", "), len(reg.autnums), loadTime, heapInUse())
			loadOnly = true
		}
	})
	if loadOnly {
		return
	}
	var vrps *rpki.VRPs
	clock.top(ctx, "vrps", func(context.Context) {
		if rd.vrps == "" {
			t.Logf("VRPs: none in MANIFEST (fetch-data.sh could not fetch them): RPKI states not checked")
		} else {
			t0 := time.Now()
			vrps = loadVRPs(t, rd.vrps)
			t.Logf("VRPs: %s read in %s", filepath.Base(rd.vrps), since(t0))
		}
	})

	var (
		seen  *asCounts
		pairs []pair
	)
	clock.top(ctx, "pass1", func(context.Context) {
		t0 := time.Now()
		seen = countASes(t, rd.ribs)
		t.Logf("pass 1 (ASes on paths): %s; %d entries, %d distinct ASes on paths, %d entries with an attribute Warning or worse, %d record errors",
			since(t0), seen.total(), len(seen.all), seen.unclean, seen.recErrs)
		for i, f := range rd.ribs {
			t.Logf("  %s: %d entries", filepath.Base(f), seen.entries[i])
		}

		var candidates, reCandidates int
		pairs, candidates, reCandidates = pickPairs(reg, seen, sample, reSample, uint64(seed))
		t.Logf("sample: %d pairs: %d of %d candidate aut-nums, then %d of %d more whose import from X has an AS-path regexp (seed %d)",
			len(pairs), min(sample, candidates), candidates, len(pairs)-min(sample, candidates), reCandidates, seed)
		ids := make([]string, len(pairs))
		for i, p := range pairs {
			ids[i] = fmt.Sprintf("AS%d-AS%d", p.L, p.X)
		}
		t.Logf("PAIRS: %s", strings.Join(ids, " "))
		if len(pairs) == 0 {
			t.Fatal("no candidate aut-num: nothing to check")
		}
	})

	// Pass 2: each X's share of the RIBs, and the lossless check on the
	// smallest X.
	var files map[bgp.ASN]string
	clock.top(ctx, "pass2", func(context.Context) {
		t0 := time.Now()
		xs := map[bgp.ASN]bool{}
		for _, p := range pairs {
			xs[bgp.ASN(p.X)] = true
		}
		small := slices.MinFunc(slices.Collect(maps.Keys(xs)), func(a, b bgp.ASN) int {
			return cmp.Or(cmp.Compare(seen.all[a], seen.all[b]), cmp.Compare(a, b))
		})
		var fstats filterStats
		files, fstats = filterRIBs(t, rd, xs, types.ASN(small))
		t.Logf("pass 2 (filter to %d files): %s; %d PEER_INDEX_TABLEs copied, %d RIB_GENERIC records dropped, %d entry errors, %d record errors",
			len(files), since(t0), fstats.peerTables, fstats.generic, fstats.entryErrs, fstats.recErrs)
		t.Logf("lossless: AS%d's %d observations over the whole RIBs equal those over its file", small, fstats.smallObs)
		for _, p := range pairs {
			x := bgp.ASN(p.X)
			var per []string
			for i, f := range rd.ribs {
				per = append(per, fmt.Sprintf("%s %d", filepath.Base(f), seen.perFile[i][x]))
			}
			t.Logf("  AS%d: %d entries through it (%s); file %s", x, seen.all[x], strings.Join(per, ", "), sizeOf(files[x]))
		}
	})

	tot := totals{reasons: [2]tally{{}, {}}, tooExp: tally{}, unevaluable: tally{}, anySets: tally{},
		missingSets: [2]tally{{}, {}}, routeObj: [2]tally{{}, {}}}
	clock.top(ctx, "pairs", func(ctx context.Context) {
		selected, err := parsePairSelection(os.Getenv("ROUTECHECK_REALDATA_PAIRS"), len(pairs))
		if err != nil {
			t.Fatalf("ROUTECHECK_REALDATA_PAIRS: %v", err)
		}
		for i, p := range pairs {
			if !selected[i+1] {
				t.Logf("pair %d/%d: not selected", i+1, len(pairs))
				out.setStatus(p, "not selected")
				continue
			}
			pprof.Do(ctx, pprof.Labels("pair", strconv.Itoa(i+1)), func(ctx context.Context) {
				markHeap(prof, t.Logf, fmt.Sprintf("pair-%d-start", i+1))
				sp, err := out.spool(i + 1)
				if err != nil {
					t.Fatal(err)
				}
				r := checkPair(ctx, t, clock, reg, vrps, p, files[bgp.ASN(p.X)], timeout, resolve.Expander{MaxPrefixes: maxPrefixes}, out.trackSet(), out.internSets(), sp, prof, i+1)
				markHeap(prof, t.Logf, fmt.Sprintf("pair-%d-end", i+1))
				r.log(t, i+1, len(pairs))
				if r.dupKeys > 0 {
					t.Errorf("AS%d from AS%d: %d routes share a key with another route of their report", p.L, p.X, r.dupKeys)
				}
				clock.span(ctx, "output", func(context.Context) {
					if err := out.addPair(&r); err != nil {
						t.Errorf("AS%d from AS%d: %v", p.L, p.X, err)
					}
				})
				if r.err == nil && seen.unclean == 0 && r.through != seen.all[bgp.ASN(p.X)] {
					t.Errorf("AS%d from AS%d: Through %d, but pass 1 counted %d entries through AS%d", p.L, p.X, r.through, seen.all[bgp.ASN(p.X)], p.X)
				}
				tot.add(&r)
			})
		}
	})
	clock.top(ctx, "totals", func(context.Context) {
		tot.log(t, since(start))
		if out != nil {
			if err := out.finish(&tot, t.Errorf); err != nil {
				t.Error(err)
			}
		}
	})
	for _, l := range clock.lines() {
		t.Log(l)
	}
}

// realOut writes the files ROUTECHECK_REALDATA_OUT and _TRACK ask for. A nil
// *realOut does nothing.
type realOut struct {
	dir     string
	rejF    *os.File
	rej     *bufio.Writer
	routesF *os.File // routes.tsv.gz; routes buffers routesZ, which gzips into it
	routesZ *gzip.Writer
	routes  *bufio.Writer
	status  []pairStatus    // every pair of the loop, in PAIRS order
	track   []string        // TRACK's keys, in its order; nil without TRACK
	trackIn map[string]bool // the same keys
	got     map[string]trackedResult
	intern  map[string]string // the comma-joined set lists of tracked lines, one string per distinct list
	checked map[string]bool   // pairs that completed
	cur     *pairSpool        // the spool of the pair being checked; abort removes it
	closed  bool
}

// pairSpool holds one pair's lines while it is checked, in two files of the
// OUT directory: .pair-<i>.routes (its routes.tsv.gz lines, uncompressed) and
// .pair-<i>.rejected (its rejected-missing.tsv lines), each written as the
// pair's reports are read. addPair appends them to the outputs for a checked
// pair, or drops them for one that timed out or failed, and removes them. A
// nil *pairSpool (no OUT) writes nothing.
type pairSpool struct {
	paths  [2]string // routes, rejected
	files  [2]*os.File
	w      [2]*bufio.Writer
	err    error // the first error writing or closing either file
	closed bool
}

// writeRoute adds a routes.tsv.gz line (without its newline).
func (s *pairSpool) writeRoute(line string) { s.write(0, line) }

// writeRejected adds a rejected-missing.tsv line (without its newline).
func (s *pairSpool) writeRejected(line string) { s.write(1, line) }

func (s *pairSpool) write(k int, line string) {
	if s == nil || s.err != nil {
		return
	}
	if _, err := s.w[k].WriteString(line); err != nil {
		s.err = err
		return
	}
	s.err = s.w[k].WriteByte('\n')
}

// close flushes and closes both files, once, and returns the spool's first
// error.
func (s *pairSpool) close() error {
	if s == nil {
		return nil
	}
	if !s.closed {
		s.closed = true
		for k, f := range s.files {
			if f == nil {
				continue
			}
			if err := s.w[k].Flush(); err != nil && s.err == nil {
				s.err = err
			}
			if err := f.Close(); err != nil && s.err == nil {
				s.err = err
			}
		}
	}
	return s.err
}

// remove closes and deletes both files.
func (s *pairSpool) remove() error {
	if s == nil {
		return nil
	}
	s.close()
	var first error
	for _, p := range s.paths {
		if p == "" {
			continue
		}
		if err := os.Remove(p); err != nil && !errors.Is(err, fs.ErrNotExist) && first == nil {
			first = err
		}
	}
	return first
}

// pairStatus is one line of pairs.tsv.
type pairStatus struct{ pair, status string }

// readTrackKeys is the first column of each non-empty line of a TSV file.
func readTrackKeys(file string) ([]string, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var keys []string
	sc := bufio.NewScanner(f)
	sc.Buffer(nil, 1<<20)
	for sc.Scan() {
		// Copy only the key: sc.Text() would allocate the whole line, and a
		// substring of it keeps all of it alive.
		if k, _, _ := bytes.Cut(sc.Bytes(), []byte{'\t'}); len(k) > 0 {
			keys = append(keys, string(k))
		}
	}
	return keys, sc.Err()
}

// openRealOut makes dir, opens rejected-missing.tsv in it and reads the keys
// of trackFile ("" for none).
func openRealOut(dir, trackFile string) (*realOut, error) {
	o := &realOut{dir: dir, got: map[string]trackedResult{}, intern: map[string]string{}, checked: map[string]bool{}}
	if trackFile != "" {
		keys, err := readTrackKeys(trackFile)
		if err != nil {
			return nil, fmt.Errorf("ROUTECHECK_REALDATA_TRACK: %w", err)
		}
		o.track, o.trackIn = keys, make(map[string]bool, len(keys))
		for _, k := range keys {
			o.trackIn[k] = true
		}
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("ROUTECHECK_REALDATA_OUT: %w", err)
	}
	f, err := os.Create(filepath.Join(dir, "rejected-missing.tsv"))
	if err != nil {
		return nil, fmt.Errorf("ROUTECHECK_REALDATA_OUT: %w", err)
	}
	o.rejF, o.rej = f, bufio.NewWriter(f)
	if o.routesF, err = os.Create(filepath.Join(dir, "routes.tsv.gz")); err != nil {
		f.Close()
		return nil, fmt.Errorf("ROUTECHECK_REALDATA_OUT: %w", err)
	}
	o.routesZ = gzip.NewWriter(o.routesF)
	o.routes = bufio.NewWriter(o.routesZ)
	return o, nil
}

// spool creates the spool of the idx-th pair of PAIRS; nil for a nil
// *realOut. Call it once per checked pair, then addPair.
func (o *realOut) spool(idx int) (*pairSpool, error) {
	if o == nil {
		return nil, nil
	}
	s := &pairSpool{}
	for k, ext := range [2]string{"routes", "rejected"} {
		s.paths[k] = filepath.Join(o.dir, fmt.Sprintf(".pair-%d.%s", idx, ext))
		f, err := os.Create(s.paths[k])
		if err != nil {
			s.remove()
			return nil, fmt.Errorf("ROUTECHECK_REALDATA_OUT: %w", err)
		}
		s.files[k], s.w[k] = f, bufio.NewWriter(f)
	}
	o.cur = s
	return s, nil
}

// appendSpool copies a checked pair's spooled lines to routes.tsv.gz and
// rejected-missing.tsv.
func (o *realOut) appendSpool(s *pairSpool) error {
	if s == nil {
		return nil
	}
	for k, dst := range [2]*bufio.Writer{o.routes, o.rej} {
		name := [2]string{"routes.tsv.gz", "rejected-missing.tsv"}[k]
		f, err := os.Open(s.paths[k])
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		_, err = io.Copy(dst, f)
		f.Close()
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
	}
	return nil
}

// setStatus records a pair's pairs.tsv status; call it once per pair, in
// PAIRS order.
func (o *realOut) setStatus(p pair, status string) {
	if o != nil {
		o.status = append(o.status, pairStatus{p.id(), status})
	}
}

// trackSet is the keys checkPair keeps lines for: TRACK's, or nil.
func (o *realOut) trackSet() map[string]bool {
	if o == nil {
		return nil
	}
	return o.trackIn
}

// internSets is the intern map checkPair shares across the run's pairs: equal
// set lists of tracked lines share one string. nil without OUT.
func (o *realOut) internSets() map[string]string {
	if o == nil {
		return nil
	}
	return o.intern
}

// trackedResult is the kept part of a tracked route's rejected-missing.tsv line:
// the outcome, the Undecided reason kinds and the comma-joined missing sets
// (shared through the run's intern map).
type trackedResult struct {
	Outcome, Detail, Sets string
}

// line is the TSV line of the route with this key.
func (t trackedResult) line(key string) string {
	return key + "\t" + t.Outcome + "\t" + t.Detail + "\t" + t.Sets
}

// addPair records a pair's status. For a checked pair it appends the spooled
// routes.tsv.gz and rejected-missing.tsv lines and keeps its tracked lines; a
// pair that timed out or failed adds none. Either way it removes the pair's
// spool and frees its lines.
func (o *realOut) addPair(r *pairResult) error {
	if o == nil {
		return nil
	}
	sp := r.spool
	defer func() { r.lines, r.spool = nil, nil }()
	if o.cur == sp {
		o.cur = nil
	}
	switch {
	case r.timeout:
		o.setStatus(r.p, "timeout")
	case r.err != nil:
		o.setStatus(r.p, "error")
	default:
		o.setStatus(r.p, "checked")
	}
	if r.err != nil {
		return sp.remove()
	}
	err := sp.close()
	if err != nil {
		err = fmt.Errorf("pair spool: %w", err)
	} else {
		err = o.appendSpool(sp)
	}
	if rerr := sp.remove(); err == nil {
		err = rerr
	}
	if err != nil {
		return err
	}
	o.checked[r.p.id()] = true
	maps.Copy(o.got, r.lines)
	return nil
}

// abort closes the files of a run that did not reach finish, and removes the
// spool of a pair addPair did not get.
func (o *realOut) abort() {
	if o != nil && !o.closed {
		o.closed = true
		o.cur.remove()
		o.cur = nil
		o.rejF.Close()
		o.routesF.Close()
	}
}

// finish closes rejected-missing.tsv and writes missing-sets.tsv and, with
// TRACK, tracked.tsv. A tracked key of a completed pair that the run did not
// produce is reported through errorf (the RIBs are the same: it must exist).
func (o *realOut) finish(tot *totals, errorf func(string, ...any)) error {
	o.closed = true
	if err := o.rej.Flush(); err != nil {
		o.rejF.Close()
		return err
	}
	if err := o.rejF.Close(); err != nil {
		o.routesF.Close()
		return err
	}
	if err := o.routes.Flush(); err != nil {
		o.routesF.Close()
		return fmt.Errorf("routes.tsv.gz: %w", err)
	}
	if err := o.routesZ.Close(); err != nil {
		o.routesF.Close()
		return fmt.Errorf("routes.tsv.gz: %w", err)
	}
	if err := o.routesF.Close(); err != nil {
		return fmt.Errorf("routes.tsv.gz: %w", err)
	}
	var ps strings.Builder
	for _, s := range o.status {
		ps.WriteString(s.pair + "\t" + s.status + "\n")
	}
	if err := writeFileChecked(filepath.Join(o.dir, "pairs.tsv"), func(w *bufio.Writer) error {
		_, err := w.WriteString(ps.String())
		return err
	}); err != nil {
		return err
	}
	var ms strings.Builder
	for d, name := range [2]string{"import", "export"} {
		for _, k := range slices.Sorted(maps.Keys(tot.missingSets[d])) {
			fmt.Fprintf(&ms, "%s\t%s\t%d\n", name, k, tot.missingSets[d][k])
		}
	}
	if err := writeFileChecked(filepath.Join(o.dir, "missing-sets.tsv"), func(w *bufio.Writer) error {
		_, err := w.WriteString(ms.String())
		return err
	}); err != nil {
		return err
	}
	if o.trackIn == nil {
		return nil
	}
	return writeFileChecked(filepath.Join(o.dir, "tracked.tsv"), func(w *bufio.Writer) error {
		for _, k := range o.track {
			tr, ok := o.got[k]
			var line string
			if ok {
				line = tr.line(k)
			} else {
				pair, _, _ := strings.Cut(k, "|")
				if o.checked[pair] {
					errorf("tracked key %q: its pair was checked, but the run has no route with this key", k)
				}
				line = k + "\tnone\t\t"
			}
			if _, err := w.WriteString(line + "\n"); err != nil {
				return err
			}
		}
		return nil
	})
}

// writeFileChecked creates file, runs write on a buffered writer of it and
// checks the write, the flush and the close.
func writeFileChecked(file string, write func(*bufio.Writer) error) error {
	f, err := os.Create(file)
	if err != nil {
		return err
	}
	w := bufio.NewWriter(f)
	if err := write(w); err != nil {
		f.Close()
		return err
	}
	if err := w.Flush(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// realData is MANIFEST's files by role.
type realData struct {
	dir   string
	dumps []string // <registry>.db*.gz, in precedence order, the chosen registries only
	ribs  []string // route-views2 RIBs, then RIS bviews
	vrps  string   // "" when MANIFEST has none
}

// openRealData reads $ROUTECHECK_REALDATA/MANIFEST (name, URL, size,
// sha256 per line) and checks each file is there at its size. It skips the
// test when ROUTECHECK_REALDATA is not set.
func openRealData(tb testing.TB) realData {
	tb.Helper()
	dir := os.Getenv("ROUTECHECK_REALDATA")
	if dir == "" {
		tb.Skip("ROUTECHECK_REALDATA is not set (scripts/fetch-data.sh, then ROUTECHECK_REALDATA=$PWD/.data/realdata)")
	}
	if st, err := os.Stat(dir); err != nil || !st.IsDir() {
		tb.Fatalf("ROUTECHECK_REALDATA=%s is not a directory", dir)
	}
	b, err := os.ReadFile(filepath.Join(dir, "MANIFEST"))
	if err != nil {
		tb.Fatalf("%v (run scripts/fetch-data.sh)", err)
	}
	rd := realData{dir: dir}
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		f := strings.Fields(line)
		if len(f) != 4 {
			tb.Fatalf("MANIFEST: %q is not name, URL, size, sha256", line)
		}
		path := filepath.Join(dir, f[0])
		size, err := strconv.ParseInt(f[2], 10, 64)
		if err != nil {
			tb.Fatalf("MANIFEST: %q: size %q", line, f[2])
		}
		if st, err := os.Stat(path); err != nil || st.Size() != size {
			tb.Fatalf("MANIFEST names %s at %d bytes; it is missing or another size (run scripts/fetch-data.sh)", f[0], size)
		}
		switch {
		case strings.HasPrefix(f[0], "rv2-"), strings.HasPrefix(f[0], "rrc"):
			rd.ribs = append(rd.ribs, path)
		case strings.HasPrefix(f[0], "vrps-"):
			rd.vrps = path
		default:
			if _, ok := dumpRegistry(f[0]); !ok {
				tb.Fatalf("MANIFEST: %s is neither a dump of a known registry, a RIB nor VRPs", f[0])
			}
			rd.dumps = append(rd.dumps, path)
		}
	}
	// route-views2 first, then RIS ("rrc" would sort before "rv2").
	rank := func(name string) int {
		if strings.HasPrefix(filepath.Base(name), "rv2-") {
			return 0
		}
		return 1
	}
	slices.SortStableFunc(rd.ribs, func(a, b string) int { return cmp.Compare(rank(a), rank(b)) })
	rd.dumps = orderDumps(rd.dumps)
	dumps, err := chooseDumps(rd.dumps, os.Getenv("ROUTECHECK_REALDATA_REGISTRIES"))
	if err != nil {
		tb.Fatalf("ROUTECHECK_REALDATA_REGISTRIES: %v", err)
	}
	rd.dumps = dumps
	if len(rd.dumps) == 0 || len(rd.ribs) == 0 {
		tb.Fatalf("MANIFEST names %d dumps and %d RIBs; it needs both", len(rd.dumps), len(rd.ribs))
	}
	return rd
}

// registryOrder is the precedence of the registries a run can load, first
// wins: RIPE, the other RIRs, RADB, then RADB's mirrors.
var registryOrder = []string{"ripe", "apnic", "arin", "afrinic", "lacnic", "radb", "altdb", "bboi", "bell", "canarie", "jpirr", "nestegg", "nttcom", "panix", "reach", "tc"}

// dumpRegistry returns the registry a dump's base name belongs to: the part
// before the first ".db." or ".db.gz". ok is false when that registry is not
// in registryOrder or the name has neither form.
func dumpRegistry(name string) (string, bool) {
	reg, _, found := strings.Cut(name, ".db.")
	if !found || !slices.Contains(registryOrder, reg) {
		return "", false
	}
	return reg, true
}

// registryIndex is a dump's registry's place in registryOrder.
func registryIndex(name string) int {
	reg, ok := dumpRegistry(filepath.Base(name))
	if !ok {
		panic("realdata: " + name + " is not a dump of a known registry")
	}
	return slices.Index(registryOrder, reg)
}

// orderDumps returns the dumps stably sorted by registryOrder, keeping their
// given order within a registry. Every name must pass dumpRegistry.
func orderDumps(dumps []string) []string {
	out := slices.Clone(dumps)
	slices.SortStableFunc(out, func(a, b string) int { return cmp.Compare(registryIndex(a), registryIndex(b)) })
	return out
}

// chooseDumps keeps the dumps of the registries want names
// (ROUTECHECK_REALDATA_REGISTRIES: comma-separated, case-insensitive); ""
// keeps every dump. A name that is not in registryOrder, or that has no dump
// in dumps, is an error naming it. The result keeps dumps' order.
func chooseDumps(dumps []string, want string) ([]string, error) {
	if want == "" {
		return slices.Clone(dumps), nil
	}
	chosen := map[string]bool{}
	for _, w := range strings.Split(want, ",") {
		w = strings.ToLower(strings.TrimSpace(w))
		if !slices.Contains(registryOrder, w) {
			return nil, fmt.Errorf("%q is not a registry (one of %s)", w, strings.Join(registryOrder, ", "))
		}
		chosen[w] = true
	}
	var out []string
	has := map[string]bool{}
	for _, d := range dumps {
		if reg, ok := dumpRegistry(filepath.Base(d)); ok && chosen[reg] {
			out = append(out, d)
			has[reg] = true
		}
	}
	for _, w := range registryOrder {
		if chosen[w] && !has[w] {
			return nil, fmt.Errorf("registry %q has no dump in MANIFEST", w)
		}
	}
	return out, nil
}

// irrRegistry is the chosen registries loaded as the command loads them. The
// pairs' selection maps (imports, reImports, autnums) hold RIPE's aut-nums
// only; the Corpus holds every registry.
type irrRegistry struct {
	src     resolve.PolicySource      // a resolve.Cache over the Corpus's source
	imports map[types.ASN][]types.ASN // RIPE aut-num → the ASes it names as "from ASn" in import:/mp-import:, sorted
	// reImports is imports restricted to the terms whose filter has an
	// AS-path regexp.
	reImports  map[types.ASN][]types.ASN
	autnums    map[types.ASN]bool // the aut-nums RIPE's dumps hold
	objects    int                // objects kept by the Corpus
	sources    []string           // the precedence passed to Corpus.Source: first appearance of source: in file order
	perSource  map[string]int     // objects kept per source (upper case)
	registries []string           // the registries loaded, in order
	// droppedRoutes counts, per registry, the route and route6 objects
	// loadRegistry skipped because routesFrom did not name it; droppedClaims
	// counts those carrying member-of:. Both are empty without routesFrom.
	droppedRoutes map[string]int
	droppedClaims int
}

// parseRoutesFrom reads ROUTECHECK_REALDATA_ROUTES_FROM: comma-separated,
// case-insensitive registry names, each in registryOrder. "" is nil, meaning
// route objects are kept from every registry. A name not in registryOrder,
// or an empty item, is an error naming it.
func parseRoutesFrom(s string) (map[string]bool, error) {
	if strings.TrimSpace(s) == "" {
		return nil, nil
	}
	set := map[string]bool{}
	for _, w := range strings.Split(s, ",") {
		w = strings.ToLower(strings.TrimSpace(w))
		if !slices.Contains(registryOrder, w) {
			return nil, fmt.Errorf("%q is not a registry (one of %s)", w, strings.Join(registryOrder, ", "))
		}
		set[w] = true
	}
	return set, nil
}

// parsePairSelection reads ROUTECHECK_REALDATA_PAIRS: comma-separated 1-based
// indices or ranges "a-b" into a list of n pairs, such as "1-20,31". The empty
// string selects all n. An empty item, a non-number, an index below 1 or
// above n and a reversed range are errors naming the item.
func parsePairSelection(s string, n int) (map[int]bool, error) {
	sel := map[int]bool{}
	if strings.TrimSpace(s) == "" {
		for i := 1; i <= n; i++ {
			sel[i] = true
		}
		return sel, nil
	}
	for _, item := range strings.Split(s, ",") {
		item = strings.TrimSpace(item)
		lo, hi, isRange := strings.Cut(item, "-")
		if !isRange {
			hi = lo
		}
		a, errA := strconv.Atoi(strings.TrimSpace(lo))
		b, errB := strconv.Atoi(strings.TrimSpace(hi))
		switch {
		case errA != nil || errB != nil:
			return nil, fmt.Errorf("pair selection item %q is not a number or a range", item)
		case a < 1 || b < 1 || a > n || b > n:
			return nil, fmt.Errorf("pair selection item %q is outside 1-%d", item, n)
		case a > b:
			return nil, fmt.Errorf("pair selection item %q is a reversed range", item)
		}
		for i := a; i <= b; i++ {
			sel[i] = true
		}
	}
	return sel, nil
}

// loadRegistry parses the dumps (rpsl.Parse, rpsl.Decode) into one
// resolve.Corpus keeping policy, source precedence by first appearance, and
// wraps its source in a resolve.Cache, as internal/cli's loadPolicy does. The
// dumps are given in precedence order (orderDumps). Only the files of RIPE
// feed the selection maps, so adding registries never changes the pairs. A
// non-empty extra is one more dump (gzip or plain, any file name) read last as
// the registry "extra": its objects keep their own source:, and it never feeds
// the selection maps either. A non-nil routesFrom keeps route and route6
// objects only from the registries it names (parseRoutesFrom): any other
// route object is skipped before the Corpus sees it, so its member-of: claim
// goes too, and is counted in droppedRoutes and droppedClaims.
func loadRegistry(tb testing.TB, dumps []string, extra string, routesFrom map[string]bool) *irrRegistry {
	tb.Helper()
	c := &resolve.Corpus{KeepPolicy: true}
	reg := &irrRegistry{imports: map[types.ASN][]types.ASN{}, reImports: map[types.ASN][]types.ASN{}, autnums: map[types.ASN]bool{}, perSource: map[string]int{}, droppedRoutes: map[string]int{}}
	var order []string
	families := []types.AddrFamily{{AFI: types.AFIv4, SAFI: types.SAFIUnicast}, {AFI: types.AFIv6, SAFI: types.SAFIUnicast}}
	files := slices.Clone(dumps)
	if extra != "" {
		files = append(files, extra)
	}
	for i, name := range files {
		regName, ok := "extra", true
		if i < len(dumps) {
			regName, ok = dumpRegistry(filepath.Base(name))
		}
		if !ok {
			tb.Fatalf("%s is not a dump of a known registry", name)
		}
		if !slices.Contains(reg.registries, regName) {
			reg.registries = append(reg.registries, regName)
		}
		fromRIPE := regName == "ripe"
		f, err := os.Open(name)
		if err != nil {
			tb.Fatal(err)
		}
		r, cancel, err := decompressFile(f, true)
		if err != nil {
			tb.Fatalf("%s: %v", name, err)
		}
		tb.Cleanup(cancel)
		for o, ds := range rpsl.Parse(r) {
			for _, d := range ds {
				if d.Rule == "rpsl/read-error" {
					tb.Fatalf("%s: reading: %s", name, d.Message)
				}
			}
			if o == nil {
				continue
			}
			obj, _ := rpsl.Decode(o)
			if obj == nil {
				continue
			}
			var source string
			for _, a := range o.Attributes() {
				if fs := strings.Fields(a.Value); strings.EqualFold(a.Name, "source") && len(fs) > 0 {
					source = strings.ToUpper(fs[0])
					if !slices.Contains(order, source) {
						order = append(order, source)
					}
					break
				}
			}
			if routesFrom != nil && !routesFrom[regName] {
				var isRoute bool
				switch obj.(type) {
				case *object.Route, *object.Route6:
					isRoute = true
				}
				if isRoute {
					reg.droppedRoutes[regName]++
					for _, a := range o.Attributes() {
						if strings.EqualFold(a.Name, "member-of") {
							reg.droppedClaims++
							break
						}
					}
					continue
				}
			}
			if !c.Put(obj) {
				continue
			}
			reg.objects++
			reg.perSource[source]++
			an, ok := obj.(*object.AutNum)
			if !ok || !fromRIPE {
				continue
			}
			reg.autnums[an.AS] = true
			var peers, rePeers []types.ASN
			for _, imp := range an.Imports {
				for _, af := range families {
					if !imp.AppliesTo(af) {
						continue
					}
					terms, err := imp.Terms(af)
					if err != nil {
						continue
					}
					for _, tm := range terms {
						if as, ok := literalPeer(tm); ok && as != an.AS {
							peers = append(peers, as)
							if tm.Filter != nil && strings.Contains(fmt.Sprint(tm.Filter), "<") {
								rePeers = append(rePeers, as)
							}
						}
					}
				}
			}
			if len(peers) > 0 {
				slices.Sort(peers)
				reg.imports[an.AS] = slices.Compact(peers)
			}
			if len(rePeers) > 0 {
				slices.Sort(rePeers)
				reg.reImports[an.AS] = slices.Compact(rePeers)
			}
		}
		cancel()
		f.Close()
	}
	reg.sources = order
	reg.src = resolve.NewCache(c.Source(order...), 0)
	return reg
}

// literalPeer returns the AS of a term whose peering is a single literal AS
// ("from AS1", with or without routers) and that has no via.
func literalPeer(tm policy.Term) (types.ASN, bool) {
	if tm.Via != nil {
		return 0, false
	}
	var as policy.ASExpr
	switch p := tm.Peering.(type) {
	case policy.PeeringAS:
		as = p.AS
	case *policy.PeeringAS:
		as = p.AS
	default:
		return 0, false
	}
	switch n := as.(type) {
	case policy.ASNum:
		return n.AS, true
	case *policy.ASNum:
		return n.AS, true
	}
	return 0, false
}

func loadVRPs(tb testing.TB, name string) *rpki.VRPs {
	tb.Helper()
	f, err := os.Open(name)
	if err != nil {
		tb.Fatal(err)
	}
	defer f.Close()
	v, err := rpki.ReadJSON(bufio.NewReaderSize(f, 1<<20))
	if err != nil {
		tb.Fatalf("%s: %v", name, err)
	}
	return v
}

// readMRT reads MRT files one after another, each through gzip or bzip2
// when compressed, as the command reads its inputs; errors name the file.
func readMRT(names ...string) iter.Seq2[mrt.Record, error] {
	return func(yield func(mrt.Record, error) bool) {
		for _, name := range names {
			f, err := os.Open(name)
			if err != nil {
				yield(nil, err)
				return
			}
			r, cancel, err := decompressFile(bufio.NewReaderSize(f, 1<<20), false)
			if err != nil {
				f.Close()
				yield(nil, fmt.Errorf("%s: %w", name, err))
				return
			}
			for rec, err := range mrt.Records(r) {
				if err != nil {
					err = fmt.Errorf("%s: %w", name, err)
				}
				if !yield(rec, err) {
					cancel()
					f.Close()
					return
				}
			}
			cancel()
			f.Close()
		}
	}
}

// asCounts is pass 1: for each AS, the RIB entries whose AS path holds it
// (in any segment, counted once per entry), per RIB and in all.
type asCounts struct {
	perFile []map[bgp.ASN]int
	all     map[bgp.ASN]int
	entries []int // entries per RIB
	unclean int   // entries whose attributes decoded with a Warning or worse
	recErrs int   // *mrt.RecordErrors, and entries whose framing is broken
}

func (c *asCounts) total() int {
	n := 0
	for _, e := range c.entries {
		n += e
	}
	return n
}

// unclean reports whether attribute diagnostics hold a Warning or worse, the
// entries observe may count Malformed.
func unclean(ds []bgp.Diagnostic) bool {
	for _, d := range ds {
		if d.Severity >= bgp.SeverityWarning {
			return true
		}
	}
	return false
}

func countASes(tb testing.TB, ribs []string) *asCounts {
	tb.Helper()
	c := &asCounts{all: map[bgp.ASN]int{}, entries: make([]int, len(ribs))}
	var on []bgp.ASN
	count := func(i int, attrs bgp.Attrs) {
		c.entries[i]++
		p, ds := attrs.Decode()
		if unclean(ds) {
			c.unclean++
		}
		on = on[:0]
		for _, s := range p.ASPath.Segments {
			for _, a := range s.ASNs {
				if !slices.Contains(on, a) {
					on = append(on, a)
				}
			}
		}
		for _, a := range on {
			c.perFile[i][a]++
			c.all[a]++
		}
	}
	for i, name := range ribs {
		c.perFile = append(c.perFile, map[bgp.ASN]int{})
		for rec, err := range readMRT(name) {
			if err != nil {
				var re *mrt.RecordError
				if errors.As(err, &re) {
					c.recErrs++
					continue
				}
				tb.Fatal(err)
			}
			switch r := rec.(type) {
			case mrt.RIB:
				for e, err := range r.Entries() {
					if err != nil {
						c.recErrs++
						break
					}
					count(i, e.Attrs)
				}
			case mrt.TableDump:
				count(i, r.Attrs)
			}
		}
	}
	return c
}

// pair is one check: L's import from X, X's export.
type pair struct{ L, X types.ASN }

// pickPairs takes a seeded sample of n aut-nums L that name, in a literal
// import peering, an AS X seen on a path whose own aut-num RIPE holds, and
// one such X for each (seeded too); then, with the same generator, m more
// aut-nums not in the first sample whose import term from such an X has an
// AS-path regexp in its filter (few policies have one, and only they
// exercise pathre and the path memo). It returns the pairs, the first
// sample's first, and the number of candidates of each kind.
func pickPairs(reg *irrRegistry, seen *asCounts, n, m int, seed uint64) (pairs []pair, candidates, reCandidates int) {
	rng := rand.New(rand.NewPCG(seed, 0))
	sample := func(peersOf map[types.ASN][]types.ASN, n int, skip map[types.ASN]bool) int {
		usable := func(l types.ASN) []types.ASN {
			var xs []types.ASN
			for _, x := range peersOf[l] {
				if seen.all[bgp.ASN(x)] > 0 && reg.autnums[x] {
					xs = append(xs, x)
				}
			}
			return xs
		}
		var ls []types.ASN
		for l := range peersOf {
			if !skip[l] && len(usable(l)) > 0 {
				ls = append(ls, l)
			}
		}
		slices.Sort(ls)
		rng.Shuffle(len(ls), func(i, j int) { ls[i], ls[j] = ls[j], ls[i] })
		for _, l := range ls[:min(n, len(ls))] {
			xs := usable(l)
			pairs = append(pairs, pair{L: l, X: xs[rng.IntN(len(xs))]})
		}
		return len(ls)
	}
	candidates = sample(reg.imports, n, nil)
	picked := map[types.ASN]bool{}
	for _, p := range pairs {
		picked[p.L] = true
	}
	reCandidates = sample(reg.reImports, m, picked)
	return pairs, candidates, reCandidates
}

// filterStats is what pass 2 found besides the files.
type filterStats struct {
	peerTables, generic, entryErrs, recErrs int
	smallObs                                int // the smallest X's observations
}

// filterRIBs writes, for each X, the RIB entries whose AS path holds X
// (their attribute bytes unchanged) to <dir>/filtered/AS<X>.mrt: each RIB's
// PEER_INDEX_TABLE as it was read, then for each RIB record with such
// entries a record of them alone, with the record's time, subtype, sequence
// and prefix. An entry whose attributes decode with a Warning or worse goes
// to every file, since observe counts it Malformed whatever its path. It
// reads the RIBs through observe.Collector for the smallest X at the same
// time, and fails unless that X's file gives the same observations and the
// same counts of entries through X.
func filterRIBs(tb testing.TB, rd realData, xs map[bgp.ASN]bool, small types.ASN) (map[bgp.ASN]string, filterStats) {
	tb.Helper()
	dir := filepath.Join(rd.dir, "filtered")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		tb.Fatal(err)
	}
	files := map[bgp.ASN]string{}
	out := map[bgp.ASN]*bufio.Writer{}
	var closers []*os.File
	for x := range xs {
		files[x] = filepath.Join(dir, fmt.Sprintf("AS%d.mrt", x))
		f, err := os.Create(files[x])
		if err != nil {
			tb.Fatal(err)
		}
		closers = append(closers, f)
		out[x] = bufio.NewWriterSize(f, 1<<20)
	}
	var st filterStats
	var werr error
	write := func(x bgp.ASN, b []byte) {
		if _, err := out[x].Write(b); err != nil && werr == nil {
			werr = err
		}
	}
	groups := map[bgp.ASN][]mrtgen.Entry{}
	split := func(rec mrt.Record) {
		switch r := rec.(type) {
		case mrt.PeerIndexTable:
			st.peerTables++
			for x := range out {
				write(x, r.Raw())
			}
		case mrt.RIB:
			sub := r.Header().Subtype
			if sub == mrt.SubRIBGeneric || sub == mrt.SubRIBGenericAddPath {
				st.generic++
				return
			}
			for x := range groups {
				groups[x] = groups[x][:0]
			}
			for e, err := range r.Entries() {
				if err != nil {
					st.entryErrs++
					break
				}
				ent := mrtgen.Entry{PeerIndex: e.PeerIndex, Originated: e.Originated, PathID: e.PathID, Attrs: e.Attrs.Raw()}
				p, ds := e.Attrs.Decode()
				for x := range out {
					if unclean(ds) || holds(p.ASPath, x) {
						groups[x] = append(groups[x], ent)
					}
				}
			}
			for x, ents := range groups {
				if len(ents) > 0 {
					write(x, mrtgen.Header(mrt.TypeTableDumpV2, sub, r.Header().Time, mrtgen.RIB(sub, r.Sequence, r.Prefix, ents)))
				}
			}
		case mrt.TableDump:
			p, ds := r.Attrs.Decode()
			for x := range out {
				if unclean(ds) || holds(p.ASPath, x) {
					write(x, r.Raw())
				}
			}
		}
	}
	tee := func(yield func(mrt.Record, error) bool) {
		for rec, err := range readMRT(rd.ribs...) {
			if err == nil {
				split(rec)
			} else {
				st.recErrs++
			}
			if !yield(rec, err) {
				return
			}
		}
	}
	wholeSeq, wholeInfo := observe.Collector(tee, small)
	whole := drain(tb, wholeSeq)
	for x, w := range out {
		if err := w.Flush(); err != nil && werr == nil {
			werr = fmt.Errorf("AS%d: %w", x, err)
		}
	}
	for _, f := range closers {
		if err := f.Close(); err != nil && werr == nil {
			werr = err
		}
	}
	if werr != nil {
		tb.Fatalf("writing the filtered files: %v", werr)
	}
	partSeq, partInfo := observe.Collector(readMRT(files[bgp.ASN(small)]), small)
	part := drain(tb, partSeq)
	if !reflect.DeepEqual(whole, part) {
		tb.Fatalf("AS%d: %d observations over the whole RIBs, %d over its filtered file, not equal: the filter loses routes", small, len(whole), len(part))
	}
	w, p := wholeInfo(), partInfo()
	if w.Through != p.Through || w.Direct != p.Direct || w.NotSequence != p.NotSequence || w.NoNeighbour != p.NoNeighbour || w.Malformed != p.Malformed {
		tb.Fatalf("AS%d: collector counts over the whole RIBs %+v, over its filtered file %+v", small, w, p)
	}
	st.smallObs = len(whole)
	return files, st
}

// holds reports whether x is on path, in any segment.
func holds(path bgp.ASPath, x bgp.ASN) bool {
	for _, s := range path.Segments {
		if slices.Contains(s.ASNs, x) {
			return true
		}
	}
	return false
}

// drain collects a Collector's observations, failing on its error.
func drain(tb testing.TB, seq iter.Seq2[observe.Observation, error]) []observe.Observation {
	tb.Helper()
	var obs []observe.Observation
	for o, err := range seq {
		if err != nil {
			tb.Fatal(err)
		}
		obs = append(obs, o)
	}
	return obs
}

// countingSource counts the route-object reads hygiene makes: it sits
// between the Checker's Routes and the registry's cache.
type countingSource struct {
	resolve.Source
	mu    sync.Mutex
	calls int
	keys  map[originKey]bool
}

type originKey struct {
	as  types.ASN
	afi types.AFI
}

func (c *countingSource) OriginatedRoutes(ctx context.Context, as types.ASN, afi types.AFI) ([]netip.Prefix, error) {
	c.mu.Lock()
	c.calls++
	if c.keys == nil {
		c.keys = map[originKey]bool{}
	}
	c.keys[originKey{as, afi}] = true
	c.mu.Unlock()
	return c.Source.OriginatedRoutes(ctx, as, afi)
}

// tally counts strings.
type tally map[string]int

func (t tally) String() string {
	keys := slices.Collect(maps.Keys(t))
	slices.SortFunc(keys, func(a, b string) int { return cmp.Or(cmp.Compare(t[b], t[a]), cmp.Compare(a, b)) })
	var b strings.Builder
	for i, k := range keys {
		if i > 0 {
			b.WriteString(", ")
		}
		fmt.Fprintf(&b, "%s=%d", k, t[k])
	}
	if b.Len() == 0 {
		return "none"
	}
	return b.String()
}

func (t tally) addAll(o tally) {
	for k, v := range o {
		t[k] += v
	}
}

// outcomes counts verdicts.
type outcomes struct{ acc, rej, und int }

func (o *outcomes) add(r *routecheck.Report) {
	o.acc += r.Accepted
	o.rej += r.Rejected
	o.und += r.Undecided
}
func (o outcomes) String() string {
	return fmt.Sprintf("%d accepted / %d rejected / %d undecided", o.acc, o.rej, o.und)
}
func (o *outcomes) sum(p outcomes) { o.acc += p.acc; o.rej += p.rej; o.und += p.und }

// famResult is one family of one pair.
type famResult struct {
	af             types.AddrFamily
	obs            int // -1: not known from the import report (it had no policy)
	impNoPolicy    bool
	imp            outcomes
	neighbours     int
	expNoPolicy    int
	exp            outcomes
	directNotCheck int
	routeObj       [2]int // found, of routes with a single origin (import report)
	rpki           tally  // import report's routes by RPKI state
}

// pairResult is one pair's check.
type pairResult struct {
	p        pair
	elapsed  time.Duration
	countDur time.Duration // the extra observation count, when the import had no policy
	err      error
	timeout  bool
	tooLarge bool
	info     observe.CollectorInfo
	through  int
	fams     []famResult
	reasons  [2]tally // Undecided reasons: import, export
	// Rejected routes for which a failing clause names a set the registry
	// does not hold: import, export.
	rejMissing [2]int
	// missingSets counts, per direction, the Rejected routes whose failing
	// clauses name each missing set (a set once per route).
	missingSets [2]tally
	// routeObj counts, per direction and report, the routes by the route-object
	// answer: "yes", "no", "unknown" (RouteVerdict.RouteObj true, false, nil).
	routeObj [2]tally
	examples []string
	tooExp   tally // ReasonPathTooExpensive terms
	// unevaluable counts the routes of each unevaluable report, by report
	// and peval's error (ReasonUnevaluable).
	unevaluable tally
	// anySetRoutes counts the Accepted routes whose Verdict.AnySets is not
	// empty (an AS-path test naming a set reaching AS-ANY let them
	// through): import, export. anySets counts those routes by report and
	// set; its keys are the distinct (report, set) pairs.
	anySetRoutes [2]int
	anySets      tally
	hygCalls     int
	hygKeys      int
	heap         string

	// The largest import prefix filter and the path-memo bound this pair saw.
	maxFilter      int
	maxFilterLabel string
	memoBound      int
	memoLabel      string
	pathRoutes     int // routes decided under a policy with an AS-path test

	// track holds the keys whose lines lines keeps (nil: none). lines is key to
	// TSV line, for the tracked keys only. dupKeys counts routes whose key an
	// earlier route of the pair had.
	track   map[string]bool
	lines   map[string]trackedResult
	intern  map[string]string // joined set list to its one shared string (nil: not shared)
	dupKeys int

	// spool takes, as report reads each route, its routes.tsv.gz line and,
	// for a Rejected route whose sets are not empty, its rejected-missing.tsv
	// line (nil: no OUT). addPair appends them, for a checked pair only.
	spool *pairSpool
}

// checkPair runs one collector-mode check and summarizes each report as
// CheckEach hands it over, keeping none: its lines go to sp (nil: none). The
// summarizing runs inside the pair's timeout.
func checkPair(ctx context.Context, tb testing.TB, clock *phaseClock, reg *irrRegistry, vrps *rpki.VRPs, p pair, file string, timeout time.Duration, exp resolve.Expander, track map[string]bool, intern map[string]string, sp *pairSpool, prof *memprof.Sampler, idx int) pairResult {
	tb.Helper()
	r := pairResult{p: p, reasons: [2]tally{{}, {}}, tooExp: tally{}, unevaluable: tally{}, anySets: tally{},
		missingSets: [2]tally{{}, {}}, routeObj: [2]tally{{}, {}}, track: track, intern: intern, spool: sp}
	counter := &countingSource{Source: reg.src}
	src := policySourceFor(reg, prof, idx, p, tb.Logf)
	c := &routecheck.Checker{Eval: peval.Evaluator{Src: src, Expander: exp}, Routes: counter}
	tctx, cancel := context.WithTimeout(ctx, timeout)
	fams := map[types.AddrFamily]*famResult{}
	var res []routecheck.Result
	var err error
	clock.span(ctx, "check", func(context.Context) {
		start := time.Now()
		res, err = c.CheckEach(tctx, routecheck.ModeCollector, readMRT(file), routecheck.Options{Local: p.L, Peer: p.X, VRPs: vrps},
			func(res *routecheck.Result, dir routecheck.Direction, rep *routecheck.Report) error {
				fr := fams[res.AF]
				if fr == nil {
					fr = newFamResult(res)
					fams[res.AF] = fr
				}
				r.summarize(fr, res.AF, dir, rep)
				return nil
			})
		r.elapsed = time.Since(start)
	})
	cancel()
	if ms, ok := src.(*markingSource); ok {
		n, d := ms.spent()
		tb.Logf("MEMPROF: pair-%d marks %d in %s", idx, n, d)
	}
	r.heap = heapInUse()
	r.hygCalls, r.hygKeys = counter.calls, len(counter.keys)
	var tooLarge *resolve.SetTooLargeError
	switch {
	case err == nil:
	case errors.Is(err, context.DeadlineExceeded):
		r.err, r.timeout = err, true
		return r
	case errors.As(err, &tooLarge):
		r.err, r.tooLarge = err, true
		tb.Errorf("AS%d from AS%d: Check returned a SetTooLargeError, which R27 makes a report's: %v", p.L, p.X, err)
		return r
	default:
		r.err = err
		tb.Errorf("AS%d from AS%d: %v", p.L, p.X, err)
		return r
	}
	if len(res) > 0 && res[0].Coverage.Collector != nil {
		r.info = *res[0].Coverage.Collector
		r.through = r.info.Through
	}
	unknown := false
	for i := range res {
		fr := fams[res[i].AF]
		if fr == nil { // a family with no report
			fr = newFamResult(&res[i])
		}
		unknown = unknown || fr.obs < 0
		r.fams = append(r.fams, *fr)
	}
	if unknown {
		// Without an import policy the family's observations are in no
		// report: count them with observe itself (not part of the check's time).
		clock.span(ctx, "recount", func(context.Context) {
			t0 := time.Now()
			seq, _ := observe.Collector(readMRT(file), p.X)
			obs := drain(tb, seq)
			for i := range r.fams {
				if r.fams[i].obs >= 0 {
					continue
				}
				n := 0
				for _, o := range obs {
					if a, ok := addrFamily(o.Family); ok && a == r.fams[i].af {
						n++
					}
				}
				r.fams[i].obs = n
			}
			r.countDur = time.Since(t0)
		})
	}
	return r
}

func addrFamily(f bgp.Family) (types.AddrFamily, bool) {
	var a types.AddrFamily
	switch f.AFI {
	case bgp.AFIIPv4:
		a.AFI = types.AFIv4
	case bgp.AFIIPv6:
		a.AFI = types.AFIv6
	default:
		return a, false
	}
	switch f.SAFI {
	case bgp.SAFIUnicast:
		a.SAFI = types.SAFIUnicast
	case bgp.SAFIMulticast:
		a.SAFI = types.SAFIMulticast
	default:
		return a, false
	}
	return a, true
}

// newFamResult is a family's summary before its reports: what its Result
// holds besides them.
func newFamResult(res *routecheck.Result) *famResult {
	return &famResult{af: res.AF, obs: -1, rpki: tally{}, directNotCheck: res.Coverage.DirectNotChecked}
}

// summarize adds one report of family af to fr: the import report (dir
// DirImport) or one export report.
func (r *pairResult) summarize(fr *famResult, af types.AddrFamily, dir routecheck.Direction, rep *routecheck.Report) {
	if dir == routecheck.DirImport {
		fr.impNoPolicy = rep.NoPolicy
		if !rep.NoPolicy {
			fr.obs = len(rep.Routes)
			fr.imp.add(rep)
			for _, rv := range rep.Routes {
				if rv.RouteObj != nil {
					fr.routeObj[1]++
					if *rv.RouteObj {
						fr.routeObj[0]++
					}
				}
				if rv.RPKI != nil {
					fr.rpki[rv.RPKI.String()]++
				}
			}
		}
		r.report(rep, 0, fmt.Sprintf("AS%d import from AS%d %s", r.p.L, r.p.X, af),
			reportCtx{pair: r.p.id(), family: af.String(), neighbour: fmt.Sprintf("AS%d", r.p.X)})
		return
	}
	fr.neighbours++
	if rep.NoPolicy {
		fr.expNoPolicy++
		return
	}
	fr.exp.add(rep)
	r.report(rep, 1, fmt.Sprintf("AS%d export to AS%d %s", r.p.X, rep.Toward, af),
		reportCtx{pair: r.p.id(), family: af.String(), neighbour: fmt.Sprintf("AS%d", rep.Toward)})
}

// reportCtx is what a report's route keys are made of besides the route: the
// pair ("AS<L>-AS<X>"), the family and the neighbour ("AS<n>"). The direction
// is report's own.
type reportCtx struct{ pair, family, neighbour string }

// routeKey names one route of one report: pair, direction ("import" or
// "export"), family, neighbour, prefix and path, joined by "|". The path is
// the ASNs ("AS1 AS2"), with " ?" appended when it is not known.
func routeKey(pair, dir, family, neighbour string, r verdict.Route) string {
	var b strings.Builder
	b.WriteString(pair + "|" + dir + "|" + family + "|" + neighbour + "|" + r.Prefix.String() + "|")
	for i, a := range r.Path {
		if i > 0 {
			b.WriteByte(' ')
		}
		b.WriteString("AS" + strconv.FormatUint(uint64(a), 10))
	}
	if !r.PathKnown {
		b.WriteString(" ?")
	}
	return b.String()
}

// id is the pair as routeKey names it.
func (p pair) id() string { return fmt.Sprintf("AS%d-AS%d", p.L, p.X) }

// missingSetNames is the sets the failing clauses of v name as missing,
// sorted and deduplicated; nil when there are none.
func missingSetNames(v *verdict.Verdict) []string {
	var sets []string
	for _, f := range v.Fails {
		for _, m := range f.Missing {
			sets = append(sets, m.String())
		}
	}
	slices.Sort(sets)
	return slices.Compact(sets)
}

// internSets joins sets with commas and returns the run's one string for that
// list: the joined copy is garbage as soon as it is looked up, so no tracked
// key holds a list of its own.
func (r *pairResult) internSets(sets []string) string {
	if len(sets) == 0 {
		return ""
	}
	joined := strings.Join(sets, ",")
	if r.intern == nil {
		return joined
	}
	if s, ok := r.intern[joined]; ok {
		return s
	}
	r.intern[joined] = joined
	return joined
}

// undecidedKinds is the reason kinds of an Undecided verdict, sorted,
// deduplicated and comma-joined; empty for any other outcome.
func undecidedKinds(v *verdict.Verdict) string {
	var kinds []string
	if v.Outcome == verdict.Undecided {
		for _, rs := range v.Reasons {
			kinds = append(kinds, rs.Kind)
		}
		slices.Sort(kinds)
		kinds = slices.Compact(kinds)
	}
	return strings.Join(kinds, ",")
}

// routeLineV2 is the routes.tsv.gz line of one route: key, outcome, the
// route-object answer ("yes", "no", "unknown"), the RPKI state ("none"
// without VRPs) and the Undecided reason kinds.
func routeLineV2(key string, rv *routecheck.RouteVerdict) string {
	obj := "unknown"
	if rv.RouteObj != nil {
		obj = map[bool]string{true: "yes", false: "no"}[*rv.RouteObj]
	}
	state := "none"
	if rv.RPKI != nil {
		state = rv.RPKI.String()
	}
	return key + "\t" + rv.Verdict.Outcome.String() + "\t" + obj + "\t" + state + "\t" + undecidedKinds(&rv.Verdict)
}

// report tallies one report's Undecided reasons, path-too-expensive terms,
// Rejected examples, filter size and path-memo bound, keeps the lines of the
// tracked routes, and spools every route's routes.tsv.gz line and the
// rejected-missing.tsv lines of the Rejected ones that name a missing set.
func (r *pairResult) report(rep *routecheck.Report, dir int, label string, rc reportCtx) {
	if rep.NoPolicy {
		return
	}
	examples := 0
	dirName := [2]string{"import", "export"}[dir]
	keys := make(map[string]struct{}, len(rep.Routes)) // dies with this report: keys differ across reports
	for i := range rep.Routes {
		rv := &rep.Routes[i]
		key := routeKey(rc.pair, dirName, rc.family, rc.neighbour, rv.Route)
		if _, dup := keys[key]; dup {
			r.dupKeys++
		}
		keys[key] = struct{}{}
		if r.spool != nil {
			r.spool.writeRoute(routeLineV2(key, rv))
		}
		tracked := r.track[key]
		var sets []string
		if rv.Verdict.Outcome == verdict.Rejected {
			sets = missingSetNames(&rv.Verdict)
		}
		if tracked || len(sets) > 0 {
			var joined string
			if tracked {
				joined = r.internSets(sets) // only a tracked key's list is kept, so only it is interned
			} else {
				joined = strings.Join(sets, ",")
			}
			tr := trackedResult{Outcome: rv.Verdict.Outcome.String(), Detail: undecidedKinds(&rv.Verdict), Sets: joined}
			if tracked {
				if r.lines == nil {
					r.lines = map[string]trackedResult{}
				}
				r.lines[key] = tr
			}
			if len(sets) > 0 {
				r.spool.writeRejected(tr.line(key))
			}
		}
		if rv.Verdict.Outcome == verdict.Undecided {
			seen := map[string]bool{}
			for _, rs := range rv.Verdict.Reasons {
				k := rs.Kind
				if k == verdict.ReasonPeval {
					k = "peval: " + rs.Why
				}
				if !seen[k] {
					seen[k] = true
					r.reasons[dir][k]++
				}
				if rs.Kind == verdict.ReasonPathTooExpensive {
					r.tooExp[label+": "+rs.Term]++
				}
				if rs.Kind == verdict.ReasonUnevaluable {
					r.unevaluable[label+": "+rs.Why]++
				}
			}
		}
		if rv.Verdict.Outcome == verdict.Accepted && len(rv.Verdict.AnySets) > 0 {
			r.anySetRoutes[dir]++
			for _, s := range rv.Verdict.AnySets {
				r.anySets[label+": "+s]++
			}
		}
		switch {
		case rv.RouteObj == nil:
			r.routeObj[dir]["unknown"]++
		case *rv.RouteObj:
			r.routeObj[dir]["yes"]++
		default:
			r.routeObj[dir]["no"]++
		}
		if rv.Verdict.Outcome == verdict.Rejected {
			named := map[string]bool{}
			for _, f := range rv.Verdict.Fails {
				for _, m := range f.Missing {
					named[m.String()] = true
				}
			}
			if len(named) > 0 {
				r.rejMissing[dir]++
			}
			for k := range named {
				r.missingSets[dir][k]++
			}
		}
		if rv.Verdict.Outcome == verdict.Rejected && examples < 2 && len(r.examples) < 6 {
			examples++
			var fails []string
			for k, f := range rv.Verdict.Fails {
				if k == 3 {
					fails = append(fails, fmt.Sprintf("and %d more clauses", len(rv.Verdict.Fails)-k))
					break
				}
				s := fmt.Sprintf("clause %d {%s}: %s", f.Clause, clip(rep.Policy.Clauses[f.Clause].Term.String(), 200), f.Test)
				if n := len(f.Missing); n > 0 {
					s += fmt.Sprintf(" (%d missing sets: %v", n, f.Missing[:min(n, 5)])
					if n > 5 {
						s += " …"
					}
					s += ")"
				}
				fails = append(fails, s)
			}
			r.examples = append(r.examples, fmt.Sprintf("rejected, %s: %s path %v: %s", label, rv.Route.Prefix, rv.Route.Path, strings.Join(fails, "; ")))
		}
	}
	size, tests := 0, 0
	for _, c := range rep.Policy.Clauses {
		for _, cj := range c.Filter.Conjuncts {
			size += cj.Prefixes.Len() + cj.NotPrefixes.Len()
			tests += len(cj.Paths)
		}
	}
	if dir == 0 && size > r.maxFilter {
		r.maxFilter, r.maxFilterLabel = size, label
	}
	if tests > 0 {
		r.pathRoutes += len(rep.Routes)
		// Each (path test, path) the memo could hold is 4 + 4 bytes per AS:
		// the bound takes every test against every distinct known path.
		paths := map[string]bool{}
		bytes := 0
		var key []byte
		for i := range rep.Routes {
			rt := &rep.Routes[i].Route
			if !rt.PathKnown {
				continue
			}
			key = key[:0]
			for _, a := range rt.Path {
				key = binary.BigEndian.AppendUint32(key, uint32(a))
			}
			if !paths[string(key)] {
				paths[string(key)] = true
				bytes += 4 + len(key)
			}
		}
		if b := tests * bytes; b > r.memoBound {
			r.memoBound, r.memoLabel = b, fmt.Sprintf("%s: %d path tests × %d distinct paths", label, tests, len(paths))
		}
	}
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func (r *pairResult) log(tb testing.TB, i, n int) {
	tb.Helper()
	head := fmt.Sprintf("pair %d/%d: AS%d import from AS%d", i, n, r.p.L, r.p.X)
	switch {
	case r.timeout:
		tb.Logf("%s: TIMEOUT after %s (heap in use %s)", head, r.elapsed.Round(time.Millisecond), r.heap)
		return
	case r.tooLarge:
		tb.Logf("%s: SET TOO LARGE after %s: %v", head, r.elapsed.Round(time.Millisecond), r.err)
		return
	case r.err != nil:
		tb.Logf("%s: ERROR after %s: %v", head, r.elapsed.Round(time.Millisecond), r.err)
		return
	}
	extra := ""
	if r.countDur > 0 {
		extra = fmt.Sprintf(" (+%s counting observations)", r.countDur.Round(time.Millisecond))
	}
	tb.Logf("%s: %s%s, heap in use %s; through %d, direct %d, not sequence %d, no neighbour %d, malformed %d, skipped %d",
		head, r.elapsed.Round(time.Millisecond), extra, r.heap, r.info.Through, r.info.Direct, r.info.NotSequence, r.info.NoNeighbour, r.info.Malformed, r.info.Skipped)
	for _, f := range r.fams {
		imp := f.imp.String()
		if f.impNoPolicy {
			imp = "no policy"
		}
		tb.Logf("  %s: %d observations; import: %s; export: %d neighbours (%d no policy): %s; direct not checked %d; route objects %d of %d; rpki %s",
			f.af, f.obs, imp, f.neighbours, f.expNoPolicy, f.exp, f.directNotCheck, f.routeObj[0], f.routeObj[1], f.rpki)
	}
	tb.Logf("  rejected with a missing set in a failing clause: import %d, export %d", r.rejMissing[0], r.rejMissing[1])
	tb.Logf("  undecided reasons, import: %s", r.reasons[0])
	tb.Logf("  undecided reasons, export: %s", r.reasons[1])
	for _, e := range r.examples {
		tb.Logf("  %s", e)
	}
	tb.Logf("  hygiene: %d OriginatedRoutes reads, %d distinct (origin, family)", r.hygCalls, r.hygKeys)
	if len(r.unevaluable) > 0 {
		tb.Logf("  unevaluable reports (routes): %s", r.unevaluable)
	}
	if len(r.anySets) > 0 {
		tb.Logf("  accepted with AnySets: import %d, export %d; by (report, set): %s", r.anySetRoutes[0], r.anySetRoutes[1], r.anySets)
	}
	if len(r.tooExp) > 0 {
		tb.Logf("  path-too-expensive: %s", r.tooExp)
	}
}

// totals sums the pairs.
type totals struct {
	pairs, ok, timeouts, tooLarge, errs int
	obs                                 int
	imp, exp                            outcomes
	impNoPolicy, expReports, expNoPol   int
	reasons                             [2]tally
	rejMissing                          [2]int
	missingSets, routeObj               [2]tally
	tooExp                              tally
	unevaluable                         tally
	anySetRoutes                        [2]int
	anySets                             tally
	hygCalls, hygKeys                   int
	examples                            int
	maxFilter                           int
	maxFilterLabel                      string
	memoBound                           int
	memoLabel                           string
	pathRoutes                          int
	slowest                             time.Duration
	slowestLabel                        string
	checkTime                           time.Duration
}

func (t *totals) add(r *pairResult) {
	t.pairs++
	t.checkTime += r.elapsed
	if r.elapsed > t.slowest {
		t.slowest, t.slowestLabel = r.elapsed, fmt.Sprintf("AS%d from AS%d", r.p.L, r.p.X)
	}
	switch {
	case r.timeout:
		t.timeouts++
		return
	case r.tooLarge:
		t.tooLarge++
		return
	case r.err != nil:
		t.errs++
		return
	}
	t.ok++
	for _, f := range r.fams {
		t.obs += f.obs
		t.imp.sum(f.imp)
		t.exp.sum(f.exp)
		if f.impNoPolicy {
			t.impNoPolicy++
		}
		t.expReports += f.neighbours
		t.expNoPol += f.expNoPolicy
	}
	t.rejMissing[0] += r.rejMissing[0]
	t.rejMissing[1] += r.rejMissing[1]
	for d := range 2 {
		t.missingSets[d].addAll(r.missingSets[d])
		t.routeObj[d].addAll(r.routeObj[d])
	}
	t.reasons[0].addAll(r.reasons[0])
	t.reasons[1].addAll(r.reasons[1])
	t.tooExp.addAll(r.tooExp)
	t.unevaluable.addAll(r.unevaluable)
	t.anySetRoutes[0] += r.anySetRoutes[0]
	t.anySetRoutes[1] += r.anySetRoutes[1]
	t.anySets.addAll(r.anySets)
	t.hygCalls += r.hygCalls
	t.hygKeys += r.hygKeys
	t.examples += len(r.examples)
	if r.maxFilter > t.maxFilter {
		t.maxFilter, t.maxFilterLabel = r.maxFilter, r.maxFilterLabel
	}
	if r.memoBound > t.memoBound {
		t.memoBound, t.memoLabel = r.memoBound, r.memoLabel
	}
	t.pathRoutes += r.pathRoutes
}

func (t *totals) log(tb testing.TB, wall time.Duration) {
	tb.Helper()
	tb.Logf("TOTALS: %d pairs: %d checked, %d timed out, %d set too large, %d other errors; wall %s, of it checks %s (slowest %s, %s)",
		t.pairs, t.ok, t.timeouts, t.tooLarge, t.errs, wall.Round(time.Second), t.checkTime.Round(time.Second), t.slowestLabel, t.slowest.Round(time.Millisecond))
	tb.Logf("TOTALS: %d observations (family × pair); import: %s (%d families with no policy); export: %d neighbour reports (%d no policy): %s",
		t.obs, t.imp, t.impNoPolicy, t.expReports, t.expNoPol, t.exp)
	tb.Logf("TOTALS: rejected with a missing set in a failing clause: import %d, export %d", t.rejMissing[0], t.rejMissing[1])
	tb.Logf("TOTALS: missing sets left: import %d distinct, export %d distinct", len(t.missingSets[0]), len(t.missingSets[1]))
	tb.Logf("TOTALS: missing sets by routes, import: %s", topN(t.missingSets[0], 20))
	tb.Logf("TOTALS: missing sets by routes, export: %s", topN(t.missingSets[1], 20))
	for d, name := range [2]string{"import", "export"} {
		tb.Logf("TOTALS: route objects, %s: yes %d, no %d, unknown %d", name, t.routeObj[d]["yes"], t.routeObj[d]["no"], t.routeObj[d]["unknown"])
	}
	tb.Logf("TOTALS: undecided reasons, import: %s", t.reasons[0])
	tb.Logf("TOTALS: undecided reasons, export: %s", t.reasons[1])
	tb.Logf("TOTALS: path-too-expensive verdicts: %d; routes decided under a policy with an AS-path test: %d", sumTally(t.tooExp), t.pathRoutes)
	tb.Logf("TOTALS: unevaluable reports: %d, %d routes", len(t.unevaluable), sumTally(t.unevaluable))
	if len(t.unevaluable) > 0 {
		tb.Logf("TOTALS: unevaluable reports (routes): %s", t.unevaluable)
	}
	tb.Logf("TOTALS: accepted with AnySets: import %d, export %d; %d distinct (report, set) pairs",
		t.anySetRoutes[0], t.anySetRoutes[1], len(t.anySets))
	if len(t.anySets) > 0 {
		tb.Logf("TOTALS: accepted with AnySets by (report, set) (routes): %s", t.anySets)
	}
	if len(t.tooExp) > 0 {
		tb.Logf("TOTALS: path-too-expensive terms: %s", t.tooExp)
	}
	tb.Logf("TOTALS: hygiene: %d OriginatedRoutes reads for %d distinct (origin, family) over the pairs", t.hygCalls, t.hygKeys)
	tb.Logf("TOTALS: largest import prefix filter: %d ranges (%s)", t.maxFilter, t.maxFilterLabel)
	tb.Logf("TOTALS: path-memo key bytes, upper bound: %d (%s); the cap is %d", t.memoBound, t.memoLabel, 64<<20)
	if t.hygCalls != t.hygKeys {
		tb.Errorf("hygiene read an (origin, family) more than once: %d reads for %d keys", t.hygCalls, t.hygKeys)
	}
}

// topN is the n largest entries of t as "key count", comma-separated, by count
// descending then key ascending; "" for an empty tally.
func topN(t tally, n int) string {
	keys := slices.Collect(maps.Keys(t))
	slices.SortFunc(keys, func(a, b string) int { return cmp.Or(cmp.Compare(t[b], t[a]), cmp.Compare(a, b)) })
	var b strings.Builder
	for i, k := range keys[:min(n, len(keys))] {
		if i > 0 {
			b.WriteString(", ")
		}
		fmt.Fprintf(&b, "%s %d", k, t[k])
	}
	return b.String()
}

func sumTally(t tally) int {
	n := 0
	for _, v := range t {
		n += v
	}
	return n
}

func since(t time.Time) time.Duration { return time.Since(t).Round(time.Millisecond) }

func heapInUse() string {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return fmt.Sprintf("%d MB", m.HeapInuse>>20)
}

func sizeOf(name string) string {
	st, err := os.Stat(name)
	if err != nil {
		return "?"
	}
	return fmt.Sprintf("%d MB", st.Size()>>20)
}

// parseMaxPrefixes reads ROUTECHECK_REALDATA_MAX_PREFIXES: "" is 0 (rpsl's
// default), otherwise a positive integer (rpsl treats a negative limit as
// unlimited, so none is accepted).
func parseMaxPrefixes(s string) (int, error) {
	if s == "" {
		return 0, nil
	}
	n, err := strconv.Atoi(s)
	if err != nil || n <= 0 {
		return 0, fmt.Errorf("ROUTECHECK_REALDATA_MAX_PREFIXES=%q is not a positive number of prefixes", s)
	}
	return n, nil
}

func envInt(tb testing.TB, name string, def int) int {
	tb.Helper()
	s := os.Getenv(name)
	if s == "" {
		return def
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 0 {
		tb.Fatalf("%s=%q is not a count", name, s)
	}
	return n
}

func envDuration(tb testing.TB, name string, def time.Duration) time.Duration {
	tb.Helper()
	s := os.Getenv(name)
	if s == "" {
		return def
	}
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 {
		tb.Fatalf("%s=%q is not a duration such as 60s", name, s)
	}
	return d
}

func TestParseMaxPrefixes(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want int
		bad  bool
	}{
		{"", 0, false},
		{"2097152", 2097152, false},
		{"1099511627776", 1099511627776, false},
		{"0", 0, true},
		{"-1", 0, true},
		{"x", 0, true},
		{"1.5", 0, true},
	} {
		got, err := parseMaxPrefixes(tc.in)
		if tc.bad {
			if err == nil || !strings.Contains(err.Error(), "ROUTECHECK_REALDATA_MAX_PREFIXES") {
				t.Errorf("parseMaxPrefixes(%q) = %d, %v; want an error naming the variable", tc.in, got, err)
			}
			continue
		}
		if err != nil || got != tc.want {
			t.Errorf("parseMaxPrefixes(%q) = %d, %v; want %d, nil", tc.in, got, err, tc.want)
		}
	}
}
