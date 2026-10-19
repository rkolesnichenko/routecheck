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
