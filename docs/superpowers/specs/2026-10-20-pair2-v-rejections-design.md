# routecheck: which of pair 2's rejections in V do the non-RIR registries rescue? — design

Status: done, measured 2026-10-20 (Outcome, below). A measurement, not a feature: the command and the library do
not change.

## Outcome

`TestPair2VAgainstR` (`pair2v_test.go`) joined V2's and R2's `routes.tsv.gz` with A's: PASS, every control held,
peak RSS 1,053 MB (`.data/pair2-v-join.log`). The recount equals the preliminary table below cell for cell
(`.data/pair2-v-cross.txt`; its ipv6 cells split by A's outcome: 1,667 = 10 + 1,657 and 35,994 = 3,683 + 32,311).

- **Rescued by the non-RIR registries' objects: 11,339** of the 263,472 (`.data/pair2-v-rescued.tsv`):
  - 9,827 ipv4, all undecided in A (224,299 − 214,472): 9,642 "yes", 184 "no", 1 "unknown";
  - 1,512 ipv6, all accepted in A (5,205 − 3,693): 1,506 "yes", 6 "no";
  - none of the 33,968 ipv6 routes rejected in A.
- **Still rejected: 252,133,** exactly R's rejections (no route is accepted in V and rejected in R). They carry R's
  classes (run B, `.data/pair2-rejections-round1-B.log`): no gap; all unknown on AS-CONCERTAP; real for an
  RIR-objects filter if AS-CONCERTAP is taken as not found.
- **Controls** (`.data/pair2-v-join.log`): the same keys in both runs; the same route-object answer per key; import
  978,368 accepted in both; the margins above; the 33,968 rejected in both runs.
- **AS6762's aut-num** is held only by `ripe.db.aut-num.gz` (`.data/pair2-v-autnum.log`), so its export clauses are
  the same in both runs.
- **Hand-checked** (`.data/pair2-v-handcheck.txt`): 2001:1398:2::/48 from AS27678, toward AS1299 against
  AS-SEABONE-V6. AS-SEABONE-V6 (RIPE) names AS-HIGHWINDS, which only ALTDB holds; two more ALTDB sets
  (AS-HWNG-CUSTOMERS, AS-HWNG-DOWNSTREAMS) reach AS27678, whose route6 object is LACNIC's. V lacks AS-HIGHWINDS
  and rejects the route; R loads it and accepts it.
- Which set rescues which route is not measured.

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

1. **Count with a small join in test code.** A `_test.go` test, opt-in by environment variable like the other
   measurements, reads V2's and R2's `routes.tsv.gz` (about 15 MB each) and A's `.data/provenance/A/routes.tsv.gz`
   for the controls, joins them on the route key and writes:
   - the cross table, `.data/pair2-v-cross.txt`: pair 2's export routes rejected in V, by R's outcome, address
     family, route-object answer and A's outcome;
   - the rescued keys, sorted, `.data/pair2-v-rescued.tsv`.

   It never reads the 3.7 GB and 5.1 GB `rejected-missing.tsv` files. A unit test pins the join on a small fixture.
2. **Hand-check one rescued route,** an ipv6 one. The export check for a key reads AS6762's export clause toward
   the neighbour named in the key's 4th field (`announce AS-SEABONE`, or `mp-export … announce AS-SEABONE-V6`),
   not its export to AS9086 (`announce ANY`). Trace, in the dumps, the chain from AS-SEABONE-V6 to the route, and
   show that a link of it is held only by a non-RIR registry, so V lacks it. Any link counts: a set, a nested set
   under one, or a registry-scoped reference.

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
- AS6762's aut-num, whose export clauses decide these routes, is RIPE's in both runs: no non-RIR dump holds an
  aut-num of that name, or, if one does, RIPE's precedes it. If not, the rescue may partly be another aut-num, and
  the docs say so.

## Constraints

- **No live queries.** The sets in question are in dumps we hold.
- **No heavy run.** Nothing reruns pair 2; the comparison reads existing run files. It still runs under the guard,
  by convention: `MEMGUARD_NORMAL_PRIORITY=1 ../rpsl/.superpowers/sdd/tools/memguard.sh 8 TIMEOUT env GOWORK=off
  GOMAXPROCS=4 GOMEMLIMIT=6GiB …`, never beside check.sh.
- **The dumps stay the 2026-10-18 files,** and the run files the published ones (V2 and R2 made at ae7d034).
- **Code:** only `_test.go` files, docs, the CHANGELOG and CLAUDE.md.
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

## Settled after the builder check *(my calls)*

1. **A new join, not `TestProvenanceCompare`.** The comparer cannot do this as it stands:
   - it requires exactly 10 excluded pairs, and its self-check expects 1,568,538 import "yes" answers over the 50
     kept pairs, which R2 and V2 (pair 2 only) cannot give, so it always fails;
   - it splits neither by family nor crosses outcome with route-object answer, and writes no key list;
   - its log says "A" for what would be R.
2. **The hand-check reads AS6762's export to the key's named neighbour,** through AS-SEABONE or AS-SEABONE-V6 (the
   design first named the export to AS9086, which announces ANY and rejects nothing).
3. **The aut-num control is AS6762's alone.** AS9086's aut-num does not decide the export routes.

## Left to the builder

- The run script, `.data/pair2-v-runs.zsh`, modelled on `.data/provenance-pair2-runs.zsh`.
- The test's name and file, and its environment variables.
- Which rescued route is hand-checked.
- The wording of the docs, in the plain style of the provenance section.
