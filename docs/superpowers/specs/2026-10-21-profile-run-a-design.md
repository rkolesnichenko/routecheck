# Where run A's time goes — design

Status: draft, 2026-10-21. This is an investigation. It changes test code only, and names the next
target without building it.

## Intent

Since v0.7.1, the 60-pair real-data run A takes 3m49s wall (`.data/pd-A.log`; every registry,
`-max-prefixes` 2097152, with OUT; GOMAXPROCS=4, GOMEMLIMIT=6GiB). Its log gives each phase's wall
time:

| phase | wall | what it does |
|---|---|---|
| registry load | 36.567 s | parses 32 gzip RPSL dumps of 16 registries into a `resolve.Corpus` (serial gzip) |
| VRPs | 1.713 s | reads NTT's VRP JSON |
| pass 1 | 17.968 s | counts the ASes on every path of both RIBs |
| pass 2 | 1m5.449s | filters both RIBs into 55 per-neighbour MRT files |
| checks | 1m34s | 60 pairs; pair 2 alone takes 31.016 s |

The rest of the wall time, about 13 s, is pair selection, logging and the totals. That figure is
arithmetic on the rows above, not a measurement.

Which of these deserves work is **not measured**. The phases differ in where their time could go:

- parsing RPSL in rpsl itself;
- decoding BGP attributes in mrt;
- writing the filtered files;
- garbage collection near the 6 GiB limit (run A peaked at 6,311 MB);
- waiting on I/O;
- the check's own work: policy expansion, verdicts, the hygiene lookups.

A profile tells them apart. Without one, any change is a guess.

## Goals

1. A CPU profile of one run A, split by phase exactly, including the goroutines each phase starts.
   mrt's decompression workers are among them.
2. For each phase:
   - its CPU seconds against its wall seconds. A phase that uses far less CPU than wall is waiting
     (I/O, or a single goroutine) rather than computing;
   - the top functions by cumulative CPU;
   - the module each belongs to: routecheck, rpsl, mrt, Go's runtime (GC and allocation), or the
     standard library.
3. The GC's share of the whole run's CPU.
4. A short findings section naming the one or two targets the profile supports, each with its
   expected payoff stated as a bound from the profile. One example: "phase X spends N s CPU in
   function F; removing it entirely would save at most M s wall". The section also names what the
   profile cannot tell.
5. The run's output is unchanged: its four output files are byte-identical to `.data/stream/A`,
   which also shows the labels change nothing.

## Non-goals

- **Making anything faster.** Any optimisation is a separate design, chosen from this one's
  findings. That includes optimisation in rpsl or mrt, which are separate repositories with their
  own release process.
- **Memory.** Memory profiling exists already (`ROUTECHECK_REALDATA_MEMPROF`, R29) and is not
  repeated.
- **The command's own runs.** Run A runs the same library code the command uses for collector
  mode. The command's flag handling and output are not profiled.
- **Wall-clock tracing.** `go test -trace` is out unless the CPU profile leaves a phase's wall time
  unexplained; see decision 5.

## Anti-goals

- A figure in the findings that does not come from the profile or a log named beside it.
- Treating a function's CPU share as its wall-clock saving. The phases run concurrently in places,
  and a parallel phase's CPU is spread over 4 cores. The findings state bounds, not promises.
- A profile that perturbs the run enough to change the answer. Go's CPU profiler samples at 100 Hz;
  its cost is expected to be small, and the run's wall times are compared with `.data/pd-A.log`.
- A run that crosses the 8 GB guard.

## Decisions

Each decision below is marked either as one the user made or as my call.

1. **Scope** (user): profile run A, design first.
2. **How to profile** (my call): `go test -cpuprofile FILE` on the existing `TestRealData`, with the
   same settings as `.data/parallel-decompress-runs.zsh A`. It needs no new flag or profiler code.
3. **Phase labels** (my call):
   - The test wraps each phase in `pprof.Do(ctx, pprof.Labels("phase", NAME), …)`. The names are
     `load`, `vrps`, `pass1`, `pass2`, `check` and `totals`.
   - Goroutines inherit their creator's labels when they start, so mrt's decompression workers and
     anything `CheckEach` starts are counted to their phase. A pprof filter of `-tagfocus=phase=X`
     then gives each phase's profile.
   - Test code only. Labels cost almost nothing, so they are always on; no environment switch.
   - The GC's background workers belong to the runtime and carry no label, so they appear as their
     own unlabelled share. Allocation assists run on the allocating goroutine, so they are counted
     to its phase.
4. **Per-phase CPU against wall** (my call):
   - The per-phase CPU comes from the profile: the samples under each label, at 10 ms each.
   - The wall time comes from the log lines the test already writes. The `check` phase's wall time
     is the TOTALS line's "of it checks".
   - A small offline step (a `go tool pprof -tags` or `-top -tagfocus` run per phase) writes the
     table. No new Go code is needed for it.
5. **A trace only if needed** (my call). If a phase's CPU is well under its wall time and the
   profile cannot say why, one more run with `-trace` on that phase alone is proposed to the user,
   and not run without their go-ahead. The likely case is pass 2's writing, or a single goroutine.
6. **Where the findings go** (my call):
   - a `### Measured, where run A's time goes` section in the CHANGELOG's Unreleased part, with the
     table and the targets;
   - one line in CLAUDE.md's Commands → Real data on how to take the profile;
   - the profile itself stays in `.data/` and is not committed.

## Tests

- **The labels change nothing.** The run's four output files are byte-identical to `.data/stream/A`,
  and its summary lines match once timings are stripped. This is the same check as
  `.data/pd-compare.log`.
- **The labels are present.** In the profile, every phase name has samples (`go tool pprof -tags`),
  and the unlabelled share is only the runtime's own goroutines (the GC's workers, the profiler).
  If a phase's goroutines show up unlabelled, a goroutine was started outside its `pprof.Do`, and
  that is fixed before the findings are written.
- **check.sh** passes. The test change is behind `ROUTECHECK_REALDATA`, like the rest of the
  real-data test.

## Running it

- One run A with `-cpuprofile`, alone, under the 8 GB guard, with the same settings as before. It
  peaked at 6,311 MB last time, over the 6,144 MB threshold, so ask before running it.
- Then the offline pprof step, which is light.
- The trace run of decision 5 needs its own go-ahead.

## Left to the builder

- Where exactly each `pprof.Do` sits.
  - Around the existing calls `loadRegistry`, the VRP read, `countASes`, `filterRIBs`, the pairs
    loop, and the totals.
  - Whether the pairs loop is one `check` label, or `check` plus a `pair=N` label. `pair` would let
    pair 2 be split out; it is cheap.
- The script that runs it (git-ignored, under `.data/`), modelled on `.data/parallel-decompress-runs.zsh`.
- The findings' wording, and how deep the per-function tables go: the top 10 to 15 per phase, by
  cumulative CPU.
