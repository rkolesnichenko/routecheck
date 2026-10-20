# routecheck: which of pair 2's rejections in V do the non-RIR registries rescue? — design

Status: draft, 2026-10-20. A measurement, not a feature: the command and the library do not change.

## Why

Pair 2 (AS9086 from AS6762) rejects 263,472 export routes in run V, the RIRs alone, and 252,133 in run R, every
registry but route objects only from the RIRs (docs/routecheck.md "How much rests on unverified registries";
`.data/stream-V2.log`, `-R2.log`). R's rejections were classified (PR #19). V's were not, and the docs list that
as not measured:

> V's rejections, which were not classified: whether loading the 362 sets never looked up (all in the non-RIR
> dumps V does not load) would flip any of them.

Two facts, found while preparing this design, change how to answer it:

- **The missing-sets method cannot say more about V than it said about R.** All 263,472 of V's rejections name
  AS-CONCERTAP (`.data/stream/V2/missing-sets.tsv`, row `export AS-CONCERTAP 263472`), which stays inconclusive
  (PR #21). Under the method every one of them would be "unknown", as R's were.
- **The question is about objects we already hold.** The sets V misses but never looked up are all in the 11
  non-RIR dumps. R loads those dumps' objects other than route objects. So comparing V and R route by route answers
  the question offline: a route rejected in V and accepted in R is rescued by the non-RIR registries' objects.

The maintainer confirmed that this comparison is the question to answer (2026-10-20).

## What R adds to V

- **The registry order puts the RIRs first** (`realdata_registry_test.go`, the order test). An object an RIR holds
  therefore resolves to the RIR's copy in both runs.
- **The route objects are the same** in both runs: R keeps only the RIRs' route and route6 objects, and V loads
  only the RIRs.
- **So R is V plus the objects only the non-RIR registries hold, other than route objects:**
  - their sets of every class, which is most of it;
  - their aut-nums, with their `member-of:` claims (a claim counts only for a set in its own registry);
  - their maintainers;
  - a registry-scoped reference such as `RADB::AS-X` resolves in R and is missing in V.
- A route rejected in V and accepted in R is rescued by this material as a whole. The comparison cannot say which
  set rescued it; that would need a run per set (a non-goal).

## Goal

Answer, for pair 2's 263,472 export routes rejected in V:

1. **How many R accepts** (rescued by the non-RIR objects) and how many it still rejects, split by address family
   and by route-object answer, as the R classification's cross table was.
2. **What the ones R still rejects are,** without a new run. With the RIRs first and the same route objects, R's
   rejections are route-by-route a subset of V's (checked, below). Run B is R plus the 56 found copies, and it still
   rejected all 252,133 (`.data/pair2-rejections-round1-B.log`). So R's classes carry over to these routes as they
   are: no gap; all unknown on AS-CONCERTAP; real for an RIR-objects filter if AS-CONCERTAP is taken as not found
   (the labelled sensitivity).
3. **Publish** in docs/routecheck.md, the CHANGELOG's `[Unreleased]` and CLAUDE.md. Every figure names its log.

## Preliminary figures (a scratch join, to be recounted)

A scratch awk join of `.data/stream/V2/routes.tsv.gz` and `.data/stream/R2/routes.tsv.gz` on the route key, export
routes only (2026-10-20). These figures are preliminary and do not enter the docs until the measurement recounts
them:

| family | route-object answer (V → R) | rejected in V, accepted in R | rejected in both |
|---|---|---|---|
| ipv4 | yes → yes | 9,642 | 6,413 |
| ipv4 | no → no | 184 | 208,022 |
| ipv4 | unknown → unknown | 1 | 37 |
| ipv6 | yes → yes | 1,506 | 1,667 |
| ipv6 | no → no | 6 | 35,994 |
| sum | | 11,339 | 252,133 |

No route goes from accepted in V to rejected in R, and both runs list the same keys.

## Method

1. **Count with the existing comparer, if it fits.** `TestProvenanceCompare` compares two run directories with the
   same `pairs.tsv`; R2's and V2's are identical. Run it with `ROUTECHECK_PROVENANCE_A=.data/stream/R2`,
   `_B=.data/stream/V2`, `_LABEL=V`. R holds everything V holds, which is the direction its self-checks assume
   (dropping objects cannot add a "yes"). Its "accepted → rejected" cell, R to V, is the rescued set. The log says
   "A" for R; the docs say R.
   - If its wording or its self-checks misfit, a small `_test.go` addition does the join instead. Only test code
     changes.
2. **Write the cross table and the key list,** as `.data/pair2-v-cross.txt` and `.data/pair2-v-rescued.tsv` (the
   rescued keys, sorted). The join reads only the two `routes.tsv.gz` files (about 15 MB each), and A's
   `.data/provenance/A/routes.tsv.gz` for the controls; never the 3.7 GB and 5.1 GB `rejected-missing.tsv`.
3. **Hand-check one rescued route,** an ipv6 one: find in the dumps the non-RIR set that puts its origin or prefix
   in AS6762's export filter for AS9086, and show that V does not hold it.

## Controls (each must hold; a failure stops the work and goes to the maintainer)

- Both runs list the same export keys, and the same import keys.
- Each key has the same route-object answer in V and R.
- Import is unchanged: 978,368 accepted in both.
- No route is accepted in V and rejected in R, so R's 252,133 rejections are exactly the V rejections R does not
  rescue.
- The margins reproduce the published figures:
  - 263,472 − 252,133 = 11,339 rescued;
  - ipv4: 224,299 − 214,472 = 9,827 (the routes undecided in A);
  - ipv6: 5,205 − 3,693 = 1,512 (pair 2's routes accepted in A and rejected in V, less those rejected in R);
  - the 33,968 ipv6 routes rejected in A are rejected in both V and R.
- AS9086's and AS6762's aut-nums are held by an RIR, so the pair's policy is the same object in both runs. If
  either is not, the rescue may partly be another aut-num, and the docs say so.

## Constraints

- **No live queries.** The sets in question are in dumps we hold.
- **No heavy run.** Nothing reruns pair 2; the comparison reads existing run files. It still runs under the guard,
  by convention: `MEMGUARD_NORMAL_PRIORITY=1 ../rpsl/.superpowers/sdd/tools/memguard.sh 8 TIMEOUT env GOWORK=off
  GOMAXPROCS=4 GOMEMLIMIT=6GiB …`, never beside check.sh.
- **The dumps stay the 2026-10-18 files,** and the run files the published ones (V2 and R2 made at ae7d034).
- **Code:** only `_test.go` files if any, docs, the CHANGELOG and CLAUDE.md.
- **Figures:** every figure comes from a command run and names its log. No local home-directory paths in anything
  pushed.

## Non-goals

- Running `TestMissingSetsClassify` over V: the `export AS-CONCERTAP 263472` row already shows it would give all
  "unknown".
- Looking up the 362 sets live.
- Saying which set rescues which route.
- Other pairs, or the R-against-V comparison over all 60 pairs.
- A release.

## Anti-goals

- Calling the rescued routes "gaps". V leaves out the non-RIR registries by design: for a filter built from the
  RIRs alone, these rejections are what that filter decides. The docs say "rescued by the non-RIR registries'
  objects".
- Promoting the routes R still rejects beyond R's own classes.

## Docs to change

- docs/routecheck.md:
  - the "In V, each of 712 sets" line (about line 717): add what the comparison found;
  - "What this means" (about line 796, "V, which loads the RIRs alone, rejects 224,299"): say how many of V's
    rejections the non-RIR objects rescue;
  - the "Not measured" V item (about lines 836-838): replaced by the answer, with what stays unmeasured (which set
    rescues which route).
- CHANGELOG `[Unreleased]`, beside the pair-2 entries.
- CLAUDE.md, the pair-2 line.

## Left to the builder

- Whether the comparer is used as is or a small join is added.
- The run script, `.data/pair2-v-runs.zsh`, modelled on `.data/provenance-pair2-runs.zsh`.
- Which rescued route is hand-checked.
- The wording of the docs, in the plain style of the provenance section.
