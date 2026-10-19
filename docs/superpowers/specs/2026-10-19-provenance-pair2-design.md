# routecheck: pair 2 in the registry-provenance figures — design

Status: draft, 2026-10-19. A measurement, not a feature: the command and the library do not change.

## Why

The registry-provenance measurement (PR #13, docs/routecheck.md "How much rests on unverified registries")
compared three runs of the real-data test on 60 pairs:

| run | loads |
|---|---|
| A | every registry |
| R | every registry, but route objects only from the five RIRs |
| V | the five RIRs only |

It could not include pair 2 (AS9086 from AS6762, 2,607,757 routes in A). In R and V pair 2 went over the 8 GB guard
even alone (8,255 and 8,249 MB). The published shares therefore leave out the largest pair, and the docs say so
("pair 2's shares … the comparison was not redone").

Since v0.6.0 pair 2 completes in R and V: 5,337 and 4,526 MB (`.data/stream-R2.log`, `.data/stream-V2.log`).

The maintainer wants the figures to include it.

## Goals

1. **The A–R and A–V comparisons with pair 2 included**, by the existing offline `TestProvenanceCompare`. The inputs
   are:
   - **A:** `.data/provenance/A`, the run the published figures came from.
   - **R:** `.data/provenance/R1` (every pair but 2) plus `.data/stream/R2` (pair 2 alone), as shards in that order.
   - **V:** `.data/provenance/V1` plus `.data/stream/V2`.

   The saved `pairs.tsv` files line up: R1 and V1 mark pair 2 "not selected"; R2 and V2 mark every other pair
   "not selected". The comparer's routes reader, though, needs each run's pairs in one unbroken order across its
   shards, and these shards interleave (see "Settled after the builder check", 1).
2. **Every published figure of the measurement, given with pair 2 included,** beside the old figures (which leave
   pair 2 out), so the two can be compared. That covers:
   - the route-object answers: "yes" in A that are "no" in R, and their share and RPKI state;
   - the verdict changes, A against R and A against V, by kind and direction, with their sums;
   - the concentration: the top pairs' share, and the reports holding most of the moves.

   Pair 2's own contribution is also given on its own.
3. **The 50-pair self-check still reproduces 1,568,538.** It reads A only, so it must not move.
4. **Published** in docs/routecheck.md's provenance section and the CHANGELOG's `[Unreleased]` (a Measured section),
   with every figure naming its log. The sentences saying pair 2 is left out are replaced.

## Constraints

- **Mixed shards.** R1 and V1 were made before v0.6.0, and R2 and V2 by v0.6.0. That is valid only because
  v0.6.0's results are identical to before: its 60-pair run A's TOTALS and its four output files, decompressed, are
  byte-identical to `.data/provenance/A`'s (CHANGELOG 0.6.0, "Measured, memory"). The docs say the shards were made
  by two versions, and why that is sound.
- **Same inputs:** the 2026-10-18 files, the same seed and the same 60 pairs. The shards confirm this: their pair
  lists are in the same order.
- **No heavy run, unless a check fails.** The comparisons run offline, one at a time under the guard (they stream per
  pair, but pair 2 is 2.6M routes in each run).
  - If the comparer refuses the mixed shards, or any check fails (keys, totals, monotonicity), the builder stops
    and reports. Rerunning R and V in full on v0.6.0 is the fallback, and it needs the maintainer's go-ahead, since
    the whole 60-pair R and V runs were not rerun after the change.
- **Code:** only `_test.go` files, docs and the CHANGELOG may change; the command and the API do not.
- **Figures:** every figure comes from a command run and names its log. No local home-directory paths in anything
  pushed.

## Non-goals

- Rerunning A, R or V. Their outputs exist.
- Changing the method, the verified grouping, or the limit (2,097,152).
- Other pairs, or other samples.
- A release. This is docs and measurement; it ships with the next release when the maintainer asks.

## Anti-goals

- Presenting the with-pair-2 shares as typical. Pair 2 is one very large pair, and its weight must be stated.
- Dropping the old figures. They stay, labelled as leaving pair 2 out.

## Decided by me (the maintainer can overrule while reading)

- **A is `.data/provenance/A`, not the v0.6.0 run.** It is the published baseline. The two are byte-identical, so
  the choice changes no figure.
- **Both "with pair 2" and "without pair 2"** are kept in the docs, since the earlier shares are quoted elsewhere
  (the CHANGELOG of 0.4.x–0.5.0).
- **The comparisons' logs are `.data/provenance-AR2.log` and `.data/provenance-AV2.log`**, beside the old
  `-AR.log` and `-AV.log`.

## Settled after the builder check *(my calls)*

1. **The comparer is extended (test code only) to read shards whose pairs interleave.** Each pair is taken from the
   shard whose `pairs.tsv` marks it checked, in `pairs.tsv` order.
   - Today `zipPairs` refuses R1 then R2 (pair 2 after pair 60) and R2 then R1 (pair 1 after pair 2). That is a
     limit of the tool, not bad data, so it is not the "comparer refuses" stop of the constraints.
   - A test covers interleaved shards.
   - A control reruns A against R1 alone, and A against V1 alone, on the extended comparer. Its tables must equal
     `.data/provenance-AR.log`'s and `.data/provenance-AV.log`'s, apart from timing, before any figure with pair 2
     is trusted.
2. **Pair 2's 400,748 export routes keep the method's rule.** In A they are undecided as unevaluable: AS-SEABONE goes
   over 2,097,152 prefixes. In R and V they are decided.
   - They are counted in the "undecided → either" row, sub-counted by A's reason, as the registry-provenance design
     settled.
   - The docs then say plainly that for pair 2 the limit is reached because of the unverified route objects:
     without them AS-SEABONE fits and these routes are decided. That makes them a data effect that shows up through
     the limit, and the docs must not dismiss them as only a limit effect.
   - Their split into accepted and rejected is given. So is the fact that the rejected ones fail against missing
     sets that the missing-sets lookup never covered (it looked up A's 842 sets): 1,276 distinct in R2 and 1,039 in
     V2, from those runs' logs, recounted.
   - The "What this means" paragraph is rewritten from the new figures, not kept by default.
3. **The shards' versions are named:** R1 and V1 were made at 2d5e24a, and R2 and V2 at ae7d034 (v0.6.0's code
   commit).
   - The reviewer's cross-check goes into the docs as supporting evidence, recounted. R2's pair-2 route-object
     "yes → no" counts (253,107 import, 394,877 export) equal the v0.5.0 marking's "yes (unverified only)" counts
     for the same pair, and the denominators equal A's.
4. **CLAUDE.md's notes on pair 2** (the provenance measurement) are updated with the new figures.

## Left to the builder

- The exact environment for `TestProvenanceCompare`: the exclude list for the self-check, as used for
  `.data/provenance-AR.log`.
- How pair 2's own contribution is extracted: from the comparer's per-pair log lines, or by a run on pair 2's shards
  alone.
- The wording of the updated docs, within the plain style of the existing section.
