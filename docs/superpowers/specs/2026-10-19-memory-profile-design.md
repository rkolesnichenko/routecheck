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
summary is `.data/memprof-runs.log`, each run's log `.data/memprof-<run>.log`, its files `.data/memprof/<run>/`.
All figures are MiB: the guard's "MB" and pprof's "MB" are MiB (pprof's 298.58 "MB" of verdicts in report 1 is
978,368 × 320 B = 298.57 MiB).

| run | result | peak RSS (guard) | live after load (`series.tsv`) | live at the last report mark |
|---|---|---|---|---|
| cmd: the command, AS9086 from AS6762, every registry, 2,097,152 | completed, exit 1 as before | 6,557 | (no marks) | (no marks); in use peaked at 5,881, 61 s into 65 s |
| A2: pair 2 alone, every registry | completed | 6,462 | 1,365 | 4,232 |
| R2: pair 2 alone, route objects from the RIRs only | stopped by the guard | 8,207 | 1,207 | 6,301 |
| V2: pair 2 alone, the RIRs only | stopped by the guard | 8,209 | 775 | 5,866 |

- **cmd ran as a `go test`**, and the guard sums RSS over the process tree, so its 6,557 includes the test driver
  and does not compare with v0.5.0's binary (6,421, `.data/verified-counts-2097152.log`).
- **A2 ran under profiling:** 80 forced GCs (its mark lines), 13.65 s spent on the 77 report marks (`memprof-runs.log`), and a 40 s check
  against 27.239 s unprofiled (`.data/provenance-A.log`).
- **Shapes** (`series.tsv`, in use): cmd climbs for 40 s, then swings between 3,561 and 5,881 to the end, with 22
  GCs in 24 s. A2, R2, V2 load, run the RIB passes (at most 3,573, 3,150, 2,256), climb report by report (to
  5,315, 7,017, 6,437), then rise again after the last report mark (to 5,564, 7,423, 7,639).

**Results unchanged.** cmd's `stdout.txt` equals the v0.5.0 output line for line, apart from the two header lines
that print the input paths (absolute here) and the log's stderr and guard lines. A2's pair-2 lines equal
`.data/provenance-A.log`'s, apart from the time and heap figures on the pair line.

### Where the memory is

**During the check, the heap climbs across the reports** (live 1,859 to 4,232 in A2, 1,702 to 6,301 in R2, first
to last report mark): `Check` returns every `Report` together, each holding its `Policy` (the expanded prefix sets
of its filters) and its `RouteVerdict`s.

**After the check, the real-data test adds its own owner.** `pairResult.report` (realdata_test.go ~1590–1606)
builds a `routeLine` for each Rejected route that names missing sets and keeps them all in `r.rejLines` until
`addPair`. Each line repeats the whole set list: A2's `out/rejected-missing.tsv` is 33,968 lines, 400,398,974
bytes, all naming the same 748 sets, which make 397,221,792 of the bytes. This is what grew when R2 and V2 were
stopped:
- Both had finished `Check` (all 77 report marks and the mark-cost line written after it are in their logs).
  `pprof -base mark-079 peak-020` (R2): `routeLine` +682, `missingSetNames` +36, `pairResult.report` +93; V2's
  `mark-079`→`peak-018`: +1,166, +52, +96. Every report was still held.
- The pass had written at least 1,059,363 of the pair's 2,607,757 routes to R2's `out/routes.tsv.gz` (into report
  7, AS6762 to AS2914, IPv4; 35,915 Rejected), and at least 1,159,369 to V2's (into report 12, AS3333; 92,334
  Rejected). The total is A2's complete `routes.tsv.gz`.
- The whole of `rejLines` is unknown; at the rate seen it would be roughly 3–4 GiB (estimate, over the 21
  reports' 400,748 routes in `memprof-A2.log` and about A2's 33,968 IPv6 lines).

**The owners.** pprof in-use space with `-nodefraction=0`, so rows sum to the total: cmd's highest peak profile
`peak-011.pb.gz` (as of the last GC), and the last report mark of A2, R2, V2, `mark-079-…-autnum-77` (after a
forced GC).

| owner (MiB) | cmd | A2 | R2 | V2 |
|---|---|---|---|---|
| set expansion (`RangeSet.add`; held by `Report.Policy`) | 1,258 (28%) | 1,481 (35%) | 3,824 (61%) | 3,847 (65%) |
| reports and verdicts (`famRun.report`, `unevaluable`, `perNeighbour`, `Compiled.Decide`) | 811 (18%) | 823 (20%) | 802 (13%) | 815 (14%) |
| compiled filter of the report in flight (`verdict.Compile`) | 328 (7%) | 0 | 0 | 0 |
| registry (`ast`, `object`, `lexer`, `policy`, `Corpus`, `MemSource`; aut-num text) | 1,528 (34%) | 1,298 (31%) | 1,194 (19%) | 780 (13%) |
| route-object lookups (`hygiene`, `resolve.Cache`) | 467 (10%) | 331 (8%) | 214 (3%) | 207 (4%) |
| RPKI VRPs (cmd ran without `-rpki`) | 0 | 148 (4%) | 149 (2%) | 144 (2%) |
| observations (`Check-range1` 46, `observe`, per-family index) | 101 (2%) | 97 (2%) | 88 (1%) | 95 (2%) |
| other | 2 | 8 | 13 | 9 |
| **profile total** | 4,496 | 4,187 | 6,286 | 5,896 |

The aut-num text is the `strings.Builder` under `ast.(*Object).String` that `KeepPolicy` keeps (`-peek`).
- **GC headroom.** A2's peak RSS is 2,230 above its largest mark (4,232), but not all of that is headroom: its
  highest in-use heap, 5,564 at 220 s, came after the last report mark (216.4 s), where only report 77 (no policy)
  and the post-`Check` pass that builds `rejLines` (382 as file bytes in A2) remain, and has no profile (under
  1.05× the last profiled high).
- **Report 1, L's IPv4 import, is `from AS6762 accept ANY`** (cmd's `stdout.txt`): no expansion. It added 641 in A2
  (`series.tsv`); `pprof -base mark-003 mark-004` splits it into `famRun.report` 298.6 (978,368 verdicts × 320 B,
  `unsafe.Sizeof(RouteVerdict)`), route-object lookups 330.6 (`hygiene.fetch` 222.5, `MemSource.OriginatedRoutes`
  68.5, `Cache.lookup` 24.0, 15.6 more) and `perNeighbour` 14.4. The lookups stay for the whole `Check`.
- **RangeSet** is a `map[types.PrefixRange]struct{}`. A `PrefixRange` is 40 B (`unsafe.Sizeof`: a 32 B
  `netip.Prefix`, two `uint8`, padding), so the map is about 60 B per entry (estimate) and a sorted slice 40 B,
  about 1.5× smaller; only a packed encoding is several times smaller. The measured cost per entry is unknown (no
  log counts a retained set's entries); R2's report 8 retained 112.2 for at most 2,097,152 entries, so at least
  56 B per entry if that is one set.

### Why pair 2 needs more memory without RADB

Report k retains the live heap from mark k to mark k+1 (`series.tsv`), in the order cmd's `stdout.txt` prints the
reports; report 77 has no mark after it, so 76 are measured.
- **In A2, 21 reports are unevaluable**: their set (`AS-SEABONE` beside each neighbour) reached 2,097,154
  prefixes, so each keeps an empty `Policy`. They retained 154 in all.
- **In R2 and V2 the same 21 fit under the limit** and each keeps its expansion: 110 to 134 per report in R2 (2,491
  in all), 112 to 144 in V2 (2,510). Each includes its verdicts: report 7's 65,223 routes are 19.9 of its 133.6.
- **The other 54 retain about the same**: 2,477 in A2, 2,366 in R2, 2,345 in V2. Report 45 is left out: its −258
  is the IPv4 observations released at the family's end (`-base mark-047 mark-048`: `Check-range1` −220). Among
  the 54, 13 IPv6 exports with the same filter, `AS-SEABONE-V6`, retain 91 to 122 each (1,465 to 1,492 in all).
  So the check holds more because 21 expansions are no longer stopped, not because of the added data; the
  `rejLines` pass then came on top.
- **Each report retains its own copy**; `Expander.Memo` is unset (realdata_test.go:315, internal/cli/cli.go:149).
  A memo might share expansions, but `AS174 | AS-SEABONE` and `AS701 | AS-SEABONE` are different filters, so
  whether copies would be shared, even for the 13 identical ones, is unknown: a phase-2 check, not a saving.

### Candidate reductions

1. **Stream the reports (routecheck, an API change: v0.6.0).** `Check` hands each finished `Report` to the caller
   (callback or iterator) and keeps none; the CLI writes each as it arrives, so every output byte stays the same,
   and the real-data test consumes them the same way. **Saving:** what the reports hold at the last mark,
   `RangeSet.add` + `famRun.report` + `famRun.unevaluable`: 2,302 in A2, 4,614 in R2, 4,644 in V2 (2,065 in cmd's
   `peak-011`), less the report in flight (up to 299 of verdicts, or 110–144 for an `AS-SEABONE` report). The
   route-object lookups (331, 214, 207) are not freed. **Risk:** an API change with byte-identical output (the
   goldens and the cmd comparison hold it); routecheck only.
2. **Write `rejLines` as they are produced (the real-data test only, no API).** Each line goes to a per-pair
   temporary file that `addPair` appends, or the set list is held once; `rejected-missing.tsv` stays byte-identical.
   **Saving:** at least 682 in R2 and 1,166 in V2 at the stop, roughly 3–4 GiB in all (estimate); about 382 in A2 (file bytes).
3. **A compact `RangeSet` (rpsl, a release).** Frozen into a sorted slice once expanded; `Has` becomes a binary
   search. **Saving:** about a third of the set-expansion owner (estimate); with candidate 1, of the report in
   flight only. **Risk:** an rpsl-wide change under its model and fuzz tests, an rpsl release, then routecheck
   requiring it.
4. **A smaller `RouteVerdict`** (320 B; pair 2's 2,607,757 verdicts are 796). With candidate 1, at most one
   report's (299 here).
5. **A GC setting inside the binary** (a lower `GOGC`): CPU for headroom. Not before 1 and 2 are measured.

### The targets

- **Pair 2 completes in R and V under 8 GB:** reachable with candidates 1 and 2 together; 1 alone leaves
  `rejLines`. Live heap: the pair's start (1,363 in R2, 931 in V2), the lookups and observations (302 in each) and
  one report with its compiled filter (up to 299 + 144 + 328): about 1.2–2.4 GiB (estimate).
- **The 60-pair run A at or below 6,144 MB (the design's wording; MiB):** likely with 1 and 2. Pair 2 alone peaks at 6,462 under profiling;
  its reports hold 2,302 at the last mark, and its highest in-use heap came after the check (unprofiled).
- **The command at or below 5,120 MB, measured on the binary:** uncertain with 1 alone. The live heap would be
  about the registry (1,528), lookups (467), observations (101) and one report with its compiled filter (up to
  299 + 144 + 328): roughly 2.0–2.8 GiB (estimate). With GOGC=100 under the guard's `GOMEMLIMIT=6GiB` the heap may
  still reach twice that; today it swings by 2.3 GiB with a GC a second. If missed, candidate 3 or 5 is next.

### Recommendation

Build candidate 1 in routecheck and candidate 2 in the real-data test, check whether a filter memo would share the
repeated expansions, and measure all three targets, the command on the binary. Decide on candidate 3 (rpsl) or 5
only if the command target is still missed.
