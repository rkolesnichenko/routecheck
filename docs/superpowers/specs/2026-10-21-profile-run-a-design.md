# Where run A's time goes — design

Status: approved 2026-10-22; decision 5 revised after approval, on a measured probe. This is an
investigation. It changes
test code only, and names the next target without building it.

## Intent

The 60-pair real-data run A took 3m49s wall in `.data/pd-A.log`: every registry, `-max-prefixes`
2097152, with OUT, GOMAXPROCS=4, GOMEMLIMIT=6GiB. That run was at f0f3767, which still read RPSL
dumps in parallel. v0.7.1 reads them serially, and run A has not been measured on it. Its log
gives each phase's wall time:

| phase | wall (`.data/pd-A.log`) | what it does |
|---|---|---|
| registry load | 36.567 s | parses 32 gzip RPSL dumps of 16 registries into a `resolve.Corpus` |
| VRPs | 1.713 s | reads NTT's VRP JSON |
| pass 1 | 17.968 s | counts the ASes on every path of both RIBs |
| pass 2 | 1m5.449s | filters both RIBs into 55 per-neighbour MRT files |
| checks | 1m34s | `CheckEach` over 60 pairs; pair 2 alone takes 31.016 s |
| re-counts | 10.868 s | the test's own re-count of each report's observations, logged as "+N counting observations" (49 entries); not part of the checks' time |
| output | not timed | appending each pair's routes and rejected lines to the OUT spools (gzip, and a 516 MB rejected-missing file) |

The phases run one after another (realdata_test.go:208–338). Only pass 1 and pass 2 run work in
parallel, through mrt's decompression workers.

Which of these deserves work is **not measured**. The phases differ in where their time could go:

- parsing RPSL in rpsl itself;
- decoding BGP attributes in mrt;
- writing the filtered files and the spools;
- garbage collection near the 6 GiB limit (run A peaked at 6,311 MB);
- waiting on I/O;
- the check's own work: policy expansion, verdicts, the hygiene lookups.

A profile tells them apart. Without one, any change is a guess.

## Goals

1. A CPU profile of one run A on the current code, split by phase exactly, including the goroutines
   each phase starts (mrt's decompression workers in pass 1 and pass 2).
   - The load reads serially (`Workers` 0) and the checks read uncompressed files, so those two
     phases start no mrt goroutines. A check's CPU close to its wall time follows from that, and
     does not by itself mean the phase is healthy.
2. For each phase:
   - its CPU seconds against its wall seconds. A phase using far less CPU than wall is waiting (I/O,
     or a single goroutine) rather than computing;
   - the top functions by cumulative CPU;
   - the module each belongs to: routecheck, rpsl, mrt, Go's runtime (GC and allocation), or the
     standard library.
3. The GC's share of the whole run's CPU, and of each top-level phase's (the pairs loop counts as
   one; see decision 5).
4. A short findings section naming the one or two targets the profile supports.
   - Each target's expected payoff is stated as a bound from the profile, for example: "phase X
     spends N s CPU in function F; removing it entirely would save at most M s wall".
   - The section also names what the profile cannot tell.
5. The run's output is unchanged: its four output files are byte-identical to `.data/stream/A`,
   which also shows the labels and the CPU readings change nothing.
6. As a by-product, this run fills the gap the CHANGELOG records: a real-data run A of the current
   code (serial RPSL), with the profiler on.

## Non-goals

- **Making anything faster.** Any optimisation is a separate design, chosen from this one's
  findings. That includes optimisation in rpsl or mrt, which are separate repositories with their
  own release process.
- **Memory.** Memory profiling exists already (`ROUTECHECK_REALDATA_MEMPROF`, R29) and is not
  repeated.
- **The command's own runs.** Run A runs the library code the command uses for collector mode; the
  command's flag handling and output are not profiled.
- **Wall-clock tracing.** `go test -trace` is out unless the profile leaves a phase's wall time
  unexplained; see decision 6.

## Anti-goals

- A figure in the findings that does not come from the profile, the CPU readings or a log named
  beside it.
- Treating a function's CPU share as its wall-clock saving. In pass 1 and pass 2, CPU is spread over
  up to 4 cores, so the findings state bounds, not promises.
- Absolute CPU seconds taken from the profile's sample count alone; see decision 5.
- A run that crosses the 8 GB guard.

## Decisions

Each decision below is marked either as one the user made or as my call.

1. **Scope** (user): profile run A, design first.
2. **How to profile** (my call): `go test -cpuprofile FILE` on the existing `TestRealData`, with the
   same settings as `.data/parallel-decompress-runs.zsh A`. No new flag or profiler code is needed.
3. **Phase labels** (my call). The test wraps each phase in
   `pprof.Do(ctx, pprof.Labels("phase", NAME), …)`.
   - **The names:** `load`, `vrps`, `pass1`, `pass2`, `check`, `recount`, `output` and `totals`.
   - **Inside the pairs loop:** `check` covers only `CheckEach` (what `r.elapsed` times),
     `recount` covers the observe re-count (what `countDur` times), and `output` covers `addPair` and
     its spool appends. Each pair also gets a `pair=N` label, so pair 2 can be split out.
   - **Goroutines** inherit their creator's labels when they start. That covers every goroutine a
     phase starts: mrt's gzip readahead (started in `DecompressWith`), its bzip2 workers (started
     from the reading goroutine's `Read`), and nothing else. routecheck's library starts none.
   - **Runtime goroutines.** The GC's background workers carry no label and appear as their own
     unlabelled share. Allocation assists run on the allocating goroutine and count to its phase.
   - **Cost.** Test code only. Labels cost almost nothing, so they are always on.
4. **The `output` phase's wall time** (my call). It is not timed today. The test sums the time
   spent in `addPair` over the pairs and logs it in one line beside the TOTALS, so the table has a
   wall figure for every labelled phase. This is a few lines of test code.
5. **CPU readings that do not rest on the profiler** (my call; revised after approval, see the
   last bullet).
   - **Why.** On macOS (Go 1.27.2) the CPU profiler samples with one process-wide timer, not
     per-thread timers as on Linux. A process-wide timer is known to undercount on Linux above
     about 2.5 busy cores. Whether macOS undercounts is unknown, and pass 1 and pass 2 run up to 5
     busy goroutines.
   - **Absolute CPU: the kernel's.** At each phase boundary, and around each pair's `check`,
     `recount` and `output` spans, the test calls `getrusage(RUSAGE_SELF)` and keeps user and
     system CPU apart. It logs one line per phase, the pairs' spans summed over the pairs:
     `CPU: <phase> user Ns sys Ns wall Ns`.
     - The figure is the whole process's, so a phase's CPU includes the GC's background workers
       and the profiler's own thread. The profile's labelled share is what separates the phase's
       own goroutines from the rest.
   - **GC: the runtime's, at the top-level boundaries only.** At the boundaries of `load`,
     `vrps`, `pass1`, `pass2`, the pairs loop as a whole, and `totals`, the test reads
     `/cpu/classes/gc/total:cpu-seconds` and `/gc/cycles/total:gc-cycles` and logs
     `GC: <phase> Ns over N cycles`. The whole run's figure is read once after the last phase.
     - These counters advance only when a GC cycle ends, so each reading lags by at most one
       cycle. The cycle count beside it shows how much that can be.
     - GC is not split among `check`, `recount` and `output`: their spans alternate per pair, and
       a reading lagging one cycle would land in the wrong one.
     - No `runtime.GC()` is forced at a boundary. On a heap of about 5 GB it would cost seconds and
       land in the wrong phase.
     - The run also sets `GODEBUG=gctrace=1`, which logs each cycle's CPU with its time since the
       process started. If a phase's GC figure looks wrong, its cycles can be attributed offline.
   - **How they are used.** The phase table takes CPU seconds from the `CPU:` lines and GC seconds
     from the `GC:` lines. The profile is used for proportions within a phase: which functions take
     the phase's CPU.
   - **The cross-check.** The run compares each phase's profile samples (× 10 ms) with its
     user + sys reading; the profiler's signal counts both. A gap names the undercount.
   - **Why it changed.** The approved version read `/cpu/classes/user` and `/cpu/classes/gc` at
     every boundary. A probe on Go 1.27.2, darwin/arm64 (`.data/cpu-probe/probe.log`) showed that
     every `/cpu/classes` counter read 0 across 1 s of busy CPU on 1 and on 3 goroutines with no
     allocation, while `getrusage` read 0.997 s and 2.976 s user over the same spans: the runtime
     counters move only at a GC cycle.
6. **A trace only if needed** (my call).
   - If a phase's CPU is well under its wall time and the profile cannot say why, one more run with
     `-trace` is proposed to the user. It is not run without their go-ahead.
   - The likely cases are pass 2's and `output`'s writing.
7. **Baseline** (my call). There is no extra unprofiled run A. This run is itself the measurement of
   the current code.
   - Its wall times are reported as measured with the profiler on, at 100 Hz.
   - They are set beside `.data/pd-A.log` only with the difference stated: that run read RPSL in
     parallel and had no profiler.
   - The profiler's own cost is not measured, and the findings say so.
8. **Where the findings go** (my call):
   - a `### Measured, where run A's time goes` section in the CHANGELOG's Unreleased part, with the
     table and the targets;
   - one line in CLAUDE.md's Commands → Real data on how to take the profile, which also replaces
     its note that the serial-RPSL run A was not measured;
   - the profile itself stays in `.data/` and is not committed.

## Tests

- **The labels and readings change nothing.** The run's four output files are byte-identical to
  `.data/stream/A`, and its summary lines match once timings are stripped. This is the same check as
  `.data/pd-compare.log`; the new `CPU:`, `GC:` and output-time lines, and gctrace's `gc N @`
  lines, are left out of the comparison.
- **The labels are present.**
  - In the profile, every phase name has samples (`go tool pprof -tags`).
  - The unlabelled share is only the runtime's own goroutines: the GC's workers and the profiler.
  - If a phase's goroutines show up unlabelled, a goroutine was started outside its `pprof.Do`, and
    that is fixed before the findings are written.
- **check.sh** passes. The test changes are behind `ROUTECHECK_REALDATA`, like the rest of the
  real-data test.

## Running it

- One run A with `-cpuprofile` and `GODEBUG=gctrace=1`, alone, under the 8 GB guard, with the same
  settings as before. It
  peaked at 6,311 MB last time, over the 6,144 MB threshold, so ask before running it.
- Then the offline pprof step (`go tool pprof -tags`, and `-top -cum -tagfocus=phase=X` per phase),
  which is light.
- The trace run of decision 6 needs its own go-ahead.

## Left to the builder

- Where exactly each `pprof.Do` sits.
- How the `CPU:` and `GC:` numbers are rounded, and how the helpers that read them are shaped.
- The script that runs it (git-ignored, under `.data/`), modelled on
  `.data/parallel-decompress-runs.zsh`.
- The findings' wording, and how deep the per-function tables go: the top 10 to 15 per phase, by
  cumulative CPU.
