# Provenance Pair 2 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** The registry-provenance figures include pair 2 (AS9086 from AS6762), measured offline from the saved
shards, and published beside the old figures.

**Architecture:**
- `TestProvenanceCompare`'s routes reader learns to read a run whose shards interleave: each pair is read from the
  shard whose `pairs.tsv` marks it checked.
- A control first reproduces the published comparisons exactly.
- Then the comparisons run with R = R1 + stream/R2 and V = V1 + stream/V2, and the docs are updated.

**Tech Stack:** Go 1.23 test code (`provenance_test.go`).

**Spec:** `docs/superpowers/specs/2026-10-19-provenance-pair2-design.md`

## Global Constraints

- **Code changes** are limited to `_test.go` files. Besides them, only docs, CHANGELOG and CLAUDE.md change. The
  command, the API and go.mod do not.
- **The inputs:**
  - A = `.data/provenance/A`;
  - R = `.data/provenance/R1,.data/stream/R2`;
  - V = `.data/provenance/V1,.data/stream/V2`;
  - `ROUTECHECK_PROVENANCE_EXCLUDE` = `AS197229-AS20771 AS9086-AS6762 AS60093-AS34984 AS44032-AS15645 AS41446-AS31133 AS48354-AS20485 AS42234-AS9050 AS51885-AS8953 AS199044-AS34984 AS42861-AS6695`
    (the 10 pairs `.data/provenance-AR.log` marks "self-check false").
- **The self-check** must still give 1,568,538.
- **Controls first:** no figure with pair 2 is trusted until the controls reproduce `.data/provenance-AR.log` and
  `.data/provenance-AV.log` apart from timing.
- **Runs:** every comparison runs under the guard, one at a time, never beside check.sh, with no network:
  `MEMGUARD_NORMAL_PRIORITY=1 ../rpsl/.superpowers/sdd/tools/memguard.sh 8 TIMEOUT env GOWORK=off GOMAXPROCS=4 GOMEMLIMIT=6GiB …`.
  A check failure (keys, totals, monotonicity, the self-check) stops the work and goes to the maintainer.
- **Figures:** every figure comes from a command run and names its log. No local home-directory paths in anything
  committed.

## Review Focus

1. **A shard holding a pair its own `pairs.tsv` does not mark checked.** It is an error naming the shard and the
   pair, never a silent skip. Task 1's `TestRunReaderStrayPair` pins it.
2. **A pair checked in one shard with no lines in that shard's routes file** (a pair with no routes). It reads as
   checked with zero routes, as the single-shard reader does today. Task 1's `TestRunReaderEmptyPair` pins it.
3. **A shard's routes out of its own `pairs.tsv` order.** It is still an error, as today. The existing
   `TestPairReaderOrder` stays green.
4. **One shard only.** It behaves exactly as before. The existing comparer tests stay green, and Task 2's controls
   prove it on real data.
5. **A pair checked in two shards.** It stays refused by `readPairStatus`, as today.

---

### Task 1: the comparer reads interleaved shards

**Files:**
- Modify: `provenance_test.go` (`pairReader` near 90-230, `zipPairs` near 290, `TestProvenanceCompare` near 850)
- Test: `provenance_test.go`

**Interfaces:**
- Produces: `newRunReader(dirs []string, order []string) (*runReader, error)`, with the same `Next()` and `Close()`
  contract as `pairReader`.
  - It opens one `pairReader` per shard. It reads each shard's own `pairs.tsv`, to know which pairs that shard
    checked.
  - `Next` returns the run's checked pairs in `order`, the combined `pairs.tsv` order, each read from the shard that
    checked it.
  - `zipPairs` takes runReaders (or an interface both satisfy), and `TestProvenanceCompare` uses `newRunReader` for
    A and for B.
  - A single shard behaves exactly as today.

- [ ] **Step 1: Write the failing tests**, on small gzip shards in `t.TempDir()`, in the existing tests' style:
  - `TestRunReaderInterleaved`: shard 1 checks p1 and p3 (p2 "not selected"); shard 2 checks p2 only; the order is
    p1, p2, p3. `Next` yields p1, p2 and p3 with their routes. Zipping it with a one-shard A holding the same lines
    gives three pairs and no error.
  - `TestRunReaderStrayPair`: shard 2's routes hold p1, which its `pairs.tsv` marks "not selected". This gives an
    error naming shard 2 and p1.
  - `TestRunReaderEmptyPair`: p2 is checked in shard 2 with no lines. It yields p2 with zero routes.
- [ ] **Step 2: Run** `GOWORK=off go test -count=1 -run 'TestRunReader|TestPairReader|TestCompareZip|TestProv' .`. Expected: the new tests FAIL (undefined), the existing ones PASS.
- [ ] **Step 3: Implement.** Then update `TestProvenanceCompare`'s doc and CLAUDE.md's line on the comparer: shards may
  interleave.
- [ ] **Step 4: Run** the same tests, then `scripts/check.sh` under the guard (log `.data/check-prov2-t1.log`). Expected: PASS, then `SUCCESS`.
- [ ] **Step 5: Commit**: `provenance: the comparer reads a run whose shards interleave`.

### Task 2: controls, the comparisons with pair 2, and the docs (controller)

**Files:**
- Modify: `docs/routecheck.md` (the "How much rests on unverified registries" section), `CHANGELOG.md`
  (`[Unreleased]`: Measured), `CLAUDE.md` (the provenance notes on pair 2)

- [ ] **Step 1: The controls.** Run the comparer with B = `.data/provenance/R1` (label R), then with
  B = `.data/provenance/V1` (label V), under the guard.
  - Logs: `.data/provenance-AR-control.log` and `-AV-control.log`.
  - Expected: each log equals `.data/provenance-AR.log` / `-AV.log` once timing, `memguard` and `ok` lines are
    removed.
  - If not, stop.
- [ ] **Step 2: The comparisons with pair 2.** Run B = `.data/provenance/R1,.data/stream/R2` (R), then
  `.data/provenance/V1,.data/stream/V2` (V).
  - Logs: `.data/provenance-AR2.log` and `-AV2.log`.
  - Expected: PASS, the self-check 1,568,538, and pair 2 checked on both sides.
- [ ] **Step 3: Pair 2's own figures.** Take them from the logs' per-pair lines and from the difference between AR2
  and AR (and AV2 and AV), with each subtraction shown. Recount from `.data/stream-R2.log` and `-V2.log`:
  - the rejected routes naming missing sets;
  - the distinct missing sets.

  Cross-check pair 2's route-object yes → no in R against the v0.5.0 marking's unverified-only counts (253,107
  import, 394,877 export; `.data/verified-counts-2097152.log`).
- [ ] **Step 4: Write the docs.**
  - **docs/routecheck.md:** the with-pair-2 figures beside the old ones; pair 2's own part, including its 400,748
    export routes, undecided in A and decided in R and V, and what they mean (design, Settled 2).
  - Also there: the shards' commits (2d5e24a and ae7d034) and why mixing them is sound; the "What this means"
    paragraph rewritten from the figures; the "not redone" sentences removed.
  - **CHANGELOG:** a Measured section.
  - **CLAUDE.md:** the pair-2 note.
  - Then run `scripts/check.sh` under the guard. Expected: `SUCCESS`.
- [ ] **Step 5: Commit**: `docs: pair 2 in the registry-provenance figures`.
