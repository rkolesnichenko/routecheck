# routecheck: lower the memory peak of the big runs — design

Status: draft, 2026-10-19. First a measurement, then reductions chosen from it.

## Why

Memory has limited every recent piece of work. The guard's cap is 8 GB and stays there, and the large runs sit
close to it or go over:

| run | peak RSS | log |
|---|---|---|
| the command, AS9086 from AS6762, every registry, `-max-prefixes 2097152` (v0.5.0) | 6,421 MB | `.data/verified-counts-2097152.log` |
| the same at `-max-prefixes 4194304` (v0.4.0) | stopped by the guard at 8,411 MB | `.data/max-prefixes-cli-4194304.log` |
| real-data test, 60 pairs, every registry (run A, missing-sets outputs) | 6,991 MB | `.data/missing-sets-A.log` |
| real-data test, pair 2 (AS9086–AS6762) alone, route objects only from the RIRs (run R) | stopped at 8,255 MB | `.data/provenance-R2.log` |
| the same, the five RIRs only (run V) | stopped at 8,249 MB | `.data/provenance-V2.log` |
| loading every registry alone (load-only mode) | 3,534 MB | `.data/load-all.log` |

Runs R and V hold *less* data than A, yet pair 2 needs more memory there. That is unexplained. The likely cause,
not measured, is set expansions that A gave up on (over the limit) fitting in R and V, and so being built in full.

The maintainer wants **the peak lowered so that the big runs fit**. Nobody knows yet where the memory goes, so the
work starts by measuring.

## Goals

1. **Profile, phase 1.** For each of three runs, say where the memory is at its peak:
   - the command run on AS9086 from AS6762, every registry, `-max-prefixes 2097152`;
   - pair 2 alone in the real-data test, run V;
   - pair 2 alone in the real-data test, run R.

   For each run:
   - **Breakdown at the peak:** the live heap, split by owner. The owners are:
     - the registry (`resolve.Corpus` and its `MemSource` views, including v0.5.0's verified view);
     - set expansion (prefix sets and ranges inside `resolve`/`peval`);
     - caches (`resolve.NewCache`, `FilterMemo`);
     - the observations read from the RIBs or the capture;
     - the reports and verdicts held for output;
     - anything else over 5% of the peak.
   - **Over time:** heap in use after loading, and after each report or pair. That shows whether the peak is one
     report's expansion or an accumulation.
   - **The R/V question:** for pair 2, which report or set expansion drives the peak, and why it is larger in R and
     V than in A.
2. **A checkpoint after phase 1.**
   - The findings, with the reductions they suggest, each with an estimated saving and where the change lives
     (routecheck or rpsl), go to the maintainer as a short addendum to this design.
   - The maintainer chooses which reductions to build. Phase 2 does not start before that.
   - If the peak turns out to be inherent, for example one set's 2,097,152 prefixes stored as compactly as they
     can be, the addendum says so and recommends stopping.
3. **Reduce, phase 2**, held to these targets:
   - pair 2 completes in runs R and V of the real-data test under the 8 GB guard;
   - the command run above peaks at or below 5,120 MB (it is 6,421 MB today);
   - the 60-pair run A, with `ROUTECHECK_REALDATA_OUT`, peaks at or below 6,144 MB (it is 7,148 MB, `.data/provenance-A.log`).
   - If the checkpoint shows a target cannot be reached, the maintainer may lower it there. It is never changed
     silently.
4. **Published.** The profile's findings and the before/after figures go into docs/routecheck.md (the memory
   figures it already gives) and the CHANGELOG. Every figure names its log.

## Constraints

- **Results never change.** A reduction must leave every verdict, route-object answer and output byte as it is:
  - the goldens;
  - the command run's report lines and route lists, identical to v0.5.0's, apart from timing and memory lines;
  - the 60-pair run A compared route by route with the existing `TestProvenanceCompare` machinery, no route moving.
- **No approximation to save memory.** No truncation, sampling or lossy prefix storage. A set over a limit stays
  unevaluable (R27), as today.
- **The guard as always:** 8 GB cap (never raised), normal priority, `GOMAXPROCS=4`, `GOMEMLIMIT=6GiB`, one heavy
  run at a time, never beside check.sh, with no network.
  - When a profiled run is stopped by the guard, the profile taken before the stop still counts as a finding.
- **Profiling stays out of the shipped command:** no new flag and no environment variable in the binary.
  - The command run is profiled through an opt-in test that calls `internal/cli`'s `Run` in-process with the same
    arguments.
  - The real-data test gains an opt-in profile output.
  - Both are test code.
- **A change to rpsl** goes through rpsl's own rules: its check.sh, its API goldens and its release flow. routecheck
  then requires the new rpsl release. Releases happen only when the maintainer asks.
- The usual: no local home-directory paths in anything pushed. Figures come from commands run, each naming its log.

## Non-goals

- Speed, unless a reduction also changes it. Times are reported but are not a target.
- Changing defaults (the MaxPrefixes default, the registries loaded, their precedence).
- Replacing the in-memory registry with a store on disk.
- Making `-max-prefixes 4194304` fit. It is measured after phase 2, but it is not a target.
- Pairs other than pair 2 and the 60-pair sample.

## Anti-goals

- Memory saved by holding less than the command needs, so that a later step re-reads or recomputes something and
  the result could differ.
- A profile hook that ships in the binary, or that changes the command's behaviour when unused.
- Figures from a run that was not under the guard.

## Decided by me (the maintainer can overrule while reading)

- **Three runs are profiled** (a fourth was added after the builder check, below):
  - the command run, because it is the user-facing big run;
  - pair 2 in V, because it is the most puzzling (the least data and over 8 GB);
  - pair 2 in R, because it isolates the route-object effect.
- **The heap is measured with Go's own heap profiles** (`runtime/pprof`, in-use space) and periodic
  `runtime.MemStats`. RSS from the guard stays the headline figure, since that is what the cap is on.
- **A checkpoint between the phases**, because the reductions, and whether rpsl must change, are unknown until
  the profile exists.
- **The targets:** 5,120 MB for the command run (about 20% lower), and 6,144 MB for run A, the projection threshold
  CLAUDE.md already uses.

## Settled after the builder check *(my calls)*

1. **RSS and the live heap are reported apart.**
   - Every published figure runs under `GOMEMLIMIT=6GiB`, which is 6,144 MiB; the guard's "MB" is MiB. The command
     run and run A peaked at that limit, so their RSS hides their live heap.
   - So phase 1 reports, at the peak, the live heap after a forced GC, split by owner, and the GC headroom (RSS minus
     live heap) as an owner of its own.
   - The targets stay RSS under the unchanged guard command, so they compare with every earlier figure.
   - Changing the guard's settings (GOGC, GOMEMLIMIT) is not a reduction.
   - A GC setting inside the binary is a candidate the checkpoint may offer, with its CPU cost measured. The
     maintainer decides it there, like any other reduction.
2. **Report boundaries without a library hook.**
   - In the real-data test, a test-only wrapper around the `PolicySource` that `checkPair` passes to peval marks
     each report (one aut-num fetch per report). Profiles and `MemStats` are taken at those marks.
   - The command run is profiled by calling `internal/cli`'s `Run` unchanged, with a time series only: `MemStats`
     every second, plus a heap profile at each new high. It is not split by report.
   - "Which report drives the peak" is answered from the real-data runs.
   - No variable, hook or flag is added to library or command code in phase 1.
3. **Run A's "before" figure is 7,148 MB** (`.data/provenance-A.log`). That is what the current code does with
   `ROUTECHECK_REALDATA_OUT`: it also writes `routes.tsv.gz`, which the no-route-moves check needs. The target of
   6,144 MB stands, measured the same way.
4. **"Pair 2 completes in R and V" means pair 2 alone, with `ROUTECHECK_REALDATA_OUT`.** That is the configuration
   that was stopped (`.data/provenance-shards.zsh`).
   - The whole 60-pair R and V runs are measured too, but are not a target.
   - There is no earlier result for pair 2 in R or V to compare with, so its results are checked by the rule that
     holds everywhere: the change must not move any route that does have an earlier result.
   - Redoing the registry-provenance figures with pair 2 included is out of scope. The docs say pair 2 now fits, and
     redoing them is a follow-up.
5. **A fourth profiled run: pair 2 alone in run A.** The R/V question needs the same code path, and the command run
   is a different one (cache, verified view, results held for printing). Pair 2 fits in A, so the run is cheap.
6. **A constraint for phase 2:** the JSON output prints each clause's full `Filter.String()`. So `Report.Policy`
   keeps its expanded filters until output, and a routecheck-side reduction cannot drop them before printing.

## Left to the builder

- How to take a heap profile near the peak. One option is a sampler that writes a profile whenever the heap reaches
  a new high, rate-limited. Another is profiles at fixed points (after load, after each report or pair). Either
  works, as long as the peak is covered.
- How to attribute heap to the owners above. pprof's call stacks, grouped by package and function, are expected to
  be enough.
- The names of the opt-in test and of its environment variables, following the existing `ROUTECHECK_REALDATA_*`
  pattern.
- Phase 2's tasks, which the addendum and its own plan define.

## Addendum: phase 1 findings (2026-10-19)

**Runs.** Four runs on head 2343eae, one at a time under the guard, with the runner `.data/memprof-runs.zsh`; its
summary is `.data/memprof-runs.log`, each run's log is `.data/memprof-<run>.log`, and its files are in
`.data/memprof/<run>/`.

| run | result | peak RSS (guard, MiB) | live heap after load | live heap at the last report mark |
|---|---|---|---|---|
| cmd: the command, AS9086 from AS6762, every registry, 2,097,152 | completed, exit 1 as before | 6,557 | (no mark) | (no marks inside `Run`); in-use heap peaked at 5,881 MiB, 61 s into a 65 s run |
| A2: pair 2 alone, every registry | completed | 6,462 | 1,365 MiB | 4,232 MiB |
| R2: pair 2 alone, route objects from the RIRs only | stopped by the guard at 8,207 | 8,207 | 1,207 MiB | 6,301 MiB |
| V2: pair 2 alone, the RIRs only | stopped by the guard at 8,209 | 8,209 | 775 MiB | 5,866 MiB |

**Units.** The guard's MB and the series (`series.tsv`) are MiB. pprof's MB in the owner table below is 10^6 bytes.

**Results unchanged.**
- cmd's `stdout.txt` equals the v0.5.0 run's output (`.data/verified-counts-2097152.log`) line for line, except the
  two header lines that print the input paths: this run passed them as absolute paths.
- A2's pair-2 lines equal `.data/provenance-A.log`'s.

**R2 and V2 finished their checks.** All 77 report marks were logged, and so was the per-pair mark-cost line, which
is written after `Check` returns. The guard stopped them afterwards, while the test was writing its outputs, with
every report still held.

### Where the memory is

**The heap grows across the reports, as a climb, not one spike.** Each report keeps what it allocated until the
whole check ends, because `Check` returns every `Report` together and each `Report` holds:
- its `Policy`, with the expanded prefix sets of its filters;
- its `RouteVerdict`s.

In A2 the live heap went from 1,859 MiB at the first report mark to 4,232 MiB at the last. In R2 it went from
1,702 to 6,301 MiB.

**The owners.** pprof in-use space, attributed by the plan's owner patterns:
- cmd: the highest peak profile, `cmd/peak-011.pb.gz`;
- A2, R2, V2: the highest mark profile (taken right after a forced GC), `mark-077-…-autnum-75` for A2 and
  `mark-079-…-autnum-77` for R2 and V2.

| owner (pprof MB) | cmd | A2 | R2 | V2 |
|---|---|---|---|---|
| set expansion (`resolve.(*RangeSet).add`; held by `Report.Policy`) | 1,258 (28%) | 1,481 (35%) | 3,824 (61%) | 3,847 (65%) |
| reports and verdicts (`famRun.report`, `unevaluable`, `verdict`) | 1,136 (25%) | 869 (21%) | 839 (13%) | 845 (14%) |
| registry (`ast`, `object`, `lexer`, `Corpus.build`, parsing) | 1,351 (30%) | 1,145 (27%) | 1,007 (16%) | 641 (11%) |
| route-object cache (`hygiene`) | 390 (9%) | 253 (6%) | 144 (2%) | 135 (2%) |
| RPKI VRPs | 0 | 148 (4%) | 149 (2%) | 144 (2%) |
| caches (`resolve.Cache`), observations | 48 | 48 | 26 | 29 |
| other (largest: `strings.Builder` 108–131) | 224 (5%) | 129 (3%) | 131 (2%) | 109 (2%) |
| **profile total** | 4,496 | 4,187 | 6,286 | 5,896 |

- **GC headroom.** In A2 the peak RSS (6,462 MiB) is 2,230 MiB above the largest live heap measured (4,232 MiB).
- **The largest single report** is L's IPv4 import: 978,368 route verdicts. It added 641 MiB in A2 and 504 MiB in R2
  (live heap from mark 1 to mark 2).
- **RangeSet's cost per entry.** rpsl's `RangeSet` is a `map[types.PrefixRange]struct{}`, about 60 bytes per range.
  A frozen, sorted form would be several times smaller (estimate, not measured).

### Why pair 2 needs more memory without RADB

- **In A2, 21 of the 77 reports are unevaluable.** Their set (`AS-SEABONE` beside each neighbour) reached
  2,097,154 prefixes, over the limit, so each keeps an empty `Policy`. Those 21 reports added 154 MiB in all.
- **In R2 and V2 the same 21 reports fit under the limit** once RADB's route objects are gone, so each keeps its
  full expansion: 124 to 134 MiB per report, 2,491 MiB in R2 and 2,510 MiB in V2.
- **The other 55 reports retain about the same** in all three runs: 2,219 MiB in A2, 2,108 in R2 and 2,086 in V2.
- So the extra memory is the limit no longer stopping 21 expansions, each held until the end. The added data is
  not the cause.
- The same `AS-SEABONE` expansion is built once per report, 21 times in R2. That costs time, not retained memory.
- Method: the reports were mapped to marks through the order the command prints them (cmd's `stdout.txt`).
  Report k retains the live heap from mark k to mark k+1.

### Candidate reductions

1. **Stream the reports (routecheck, an API change: v0.6.0).**
   - `Check` hands each finished `Report` to the caller, through a callback or an iterator, and keeps none. The
     CLI writes each report as it arrives, as text or JSON, so every output byte stays the same. The real-data
     test consumes reports the same way.
   - **Estimated saving:** everything retained across reports. That is 2,373 MiB in A2 and about 4,600 MiB in R2
     and V2 (live heap from the first to the last report mark), less the one report in flight, which is at most
     641 MiB here.
   - **Risk:** an API change, and the CLI's output must be byte-identical (the goldens and the cmd comparison
     above hold it). It touches only routecheck.
2. **A compact `RangeSet` (rpsl, a release).**
   - The set is frozen into a sorted slice once its expansion is done; `Has` becomes a binary search.
   - **Estimated saving:** part of the set-expansion owner. With candidate 1 in place, only the sets of the report
     in flight remain to save.
   - **Risk:** an rpsl-wide change under its own model and fuzz tests, then an rpsl release, then routecheck
     requiring it.
3. **A smaller `RouteVerdict`** (about 600 bytes per route today: 641 MiB for 978,368 routes, which includes that
   report's own expansion). With candidate 1 only one report's verdicts are held at a time, so it matters less.
4. **A GC setting inside the binary** (for example a lower `GOGC`). It trades CPU for headroom. It is not
   recommended before candidate 1 has been measured.

### The targets

- **Pair 2 completes in runs R and V under 8 GB:** reachable with candidate 1. The live heap would be about the
  registry and caches (1.2–1.7 GiB) plus one report.
- **The 60-pair run A at or below 6,144 MB:** likely with candidate 1. Pair 2 alone peaks at 6,462 MiB today, and
  almost all of its live growth is retained reports.
- **The command run at or below 5,120 MB:** uncertain with candidate 1 alone.
  - The live heap would fall to about the registry, the route-object cache and one report, roughly 2.5–3 GB
    (estimate).
  - But with GOGC=100 the heap may still grow to twice that between collections, under the guard's
    `GOMEMLIMIT=6GiB`.
  - It must be measured after candidate 1. If it is missed, candidate 2 or 4 is the next step.

### Recommendation

Build candidate 1 first, in routecheck alone, and measure all three targets. Decide on candidate 2 (rpsl) or 4 only
if the command target is still missed.
