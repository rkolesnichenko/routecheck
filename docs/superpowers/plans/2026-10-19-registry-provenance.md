# Registry-provenance Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Measure how many of routecheck's route-object answers and verdicts rest on unverified registries (RADB and
its ten mirrors), by comparing the every-registry real-data run route by route with a run whose route objects come
only from the five RIRs (R) and a run of the RIRs alone (V).

**Architecture:**
- The opt-in real-data test gains two things: a way to keep route objects only from named registries, and, under
  `ROUTECHECK_REALDATA_OUT`, one compact line per route, streamed per pair to a gzip file, plus a per-pair status file.
- A new opt-in offline test compares two runs' files pair by pair and logs the tables.
- The controller runs A, R and V and publishes the result.
- The command does not change.

**Tech Stack:** Go 1.23 (go.mod floor), rpsl v0.30.0, `compress/gzip`, and zsh with rpsl's memguard.

**Spec:** `docs/superpowers/specs/2026-10-19-registry-provenance-design.md`

## Global Constraints

- The command's behaviour, output, `api/*.txt` and go.mod do not change. Only `_test.go` files, docs, the CHANGELOG
  and CLAUDE.md change in git.
- The verified registries are exactly `ripe,apnic,arin,afrinic,lacnic`. Every other loaded registry is unverified:
  `radb,altdb,bboi,bell,canarie,jpirr,nestegg,nttcom,panix,reach,tc`. Unverified is decided by dump file.
- The runs use `ROUTECHECK_REALDATA_MAX_PREFIXES=2097152`, the 2026-10-18 files in `.data/realdata` (MANIFEST
  unchanged), and the default seed and sample (60 pairs).
- Heavy runs go one at a time, with `MEMGUARD_NORMAL_PRIORITY=1 ../rpsl/.superpowers/sdd/tools/memguard.sh 8 …`,
  `GOMAXPROCS=4` and `GOMEMLIMIT=6GiB`. Never beside check.sh. Never raise the 8 GB cap: shard with
  `ROUTECHECK_REALDATA_PAIRS` instead.
- The per-route output is streamed as each report is read. It is never held for a pair or for the whole run.
- No network.
- Outputs stay in `.data/` (git-ignored).
- No local home-directory path in any committed file or commit message.
- Every published figure names its log or data file.
- Comparison kinds are `accepted`, `rejected`, `undecided` and `no verdict`. Each table sums to its universe
  (defined in Task 3), and the docs show the sum.
- Route-object rule: no route may be `no` in A and `yes` in the other run. One such route fails the comparison.
- The self-check is A's import route-object `yes` over the 50 pairs other than these 10, which must equal 1,568,538:
  `AS197229-AS20771 AS9086-AS6762 AS60093-AS34984 AS44032-AS15645 AS41446-AS31133 AS48354-AS20485 AS42234-AS9050 AS51885-AS8953 AS199044-AS34984 AS42861-AS6695`
  The figure comes from the CHANGELOG, every-registry section: "route objects: import yes 1,568,538".
- `scripts/check.sh` passes, run under the memory guard.

## Review Focus

1. **A report with a policy in one run and none in the other.** Its routes count as `no verdict` on the other side;
   they are never dropped from the universe. Task 3's `TestCompareNoVerdict` pins this.
2. **Shard files given out of order, or a pair id in two files.** The pair-by-pair reader fails instead of
   mis-joining. Task 3's `TestPairReaderOrder` pins this.
3. **A truncated gzip file** (a run the guard killed). Reading it is an error, never a short run.
   Task 3's `TestPairReaderTruncated` pins this.
4. **`ROUTECHECK_REALDATA_ROUTES_FROM` naming an unknown registry, or set together with
   `ROUTECHECK_REALDATA_EXTRA`.** Both are errors that name the cause. Task 1's `TestParseRoutesFrom` pins this.
5. **A route object with `member-of:`** (a route-set claim). Dropping it drops the claim with it, and the loaded-object
   counts say how many such objects were dropped. Task 1's `TestLoadRegistryRoutesFrom` pins this.

---

### Task 1: Keep route objects only from named registries

**Files:**
- Modify: `realdata_test.go` (`TestRealData`'s doc comment and env handling, `loadRegistry`)
- Test: `realdata_registry_test.go`

**Interfaces:**
- Produces:
  - `parseRoutesFrom(s string) (map[string]bool, error)`:
    - `""` gives nil, meaning keep all;
    - otherwise a set of registry names, comma-separated and case-insensitive, each in `registryOrder`;
    - an unknown name is an error naming it.
  - `loadRegistry(tb testing.TB, dumps []string, extra string, routesFrom map[string]bool) *irrRegistry`. With a
    non-nil `routesFrom`:
    - a `*object.Route` or `*object.Route6` from a dump whose registry is not in it is skipped before `c.Put`;
    - `irrRegistry` gains `droppedRoutes map[string]int` (per registry) and `droppedClaims int` (dropped route
      objects carrying `member-of:`).
  - `ROUTECHECK_REALDATA_ROUTES_FROM`:
    - parsed by `parseRoutesFrom`;
    - set together with `ROUTECHECK_REALDATA_EXTRA`, it fails the test;
    - the run logs `routes from: <names>; dropped route objects per registry …; dropped member-of claimants N`,
      or `routes from: every registry`.

- [ ] **Step 1: Write the failing tests:**
  - `TestParseRoutesFrom`:
    - `""` gives nil;
    - `"RIPE, apnic"` gives {ripe, apnic};
    - errors: `"ripe,nope"` (the message holds `nope`) and `"ripe,,apnic"`.
  - `TestLoadRegistryRoutesFrom`, in the style of `TestLoadRegistryPrecedenceAndSelection` (`writeGzip`):
    - a `ripe.db.route.gz` with one route;
    - a `radb.db.gz` with one route, one route carrying `member-of: RS-X`, a `route-set: RS-X` with
      `mbrs-by-ref: ANY`, and an `as-set`;
    - with `routesFrom={ripe}`:
      - `OriginatedRoutes` returns only RIPE's prefix;
      - the as-set is still found;
      - `ExpandPrefixes(RS-X)` is empty;
      - `droppedRoutes["radb"] == 2` and `droppedClaims == 1`;
    - with nil, everything is kept.

- [ ] **Step 2: Run** `GOWORK=off go test -run 'TestParseRoutesFrom|TestLoadRegistryRoutesFrom' .`. Expected: FAIL (undefined).

- [ ] **Step 3: Implement.**
  - Update every `loadRegistry` caller (`TestRealData`, `realdata_registry_test.go`, `bench_test.go`) to pass nil
    where routes are not restricted.
  - Document the variable in `TestRealData`'s doc comment.

- [ ] **Step 4: Run** the focused tests and then `scripts/check.sh` under the guard. Expected: PASS and `SUCCESS`.

- [ ] **Step 5: Commit**: `realdata: keep route objects only from named registries (ROUTECHECK_REALDATA_ROUTES_FROM)`.

### Task 2: Stream one line per route, and each pair's status

**Files:**
- Modify: `realdata_test.go` (`realOut`, `(*pairResult).report`, `checkPair`, the pair loop)
- Test: `realdata_registry_test.go`

**Interfaces:**
- Consumes: the existing `realOut`, `routeKey`, `reportCtx` and `pair.id()`.
- Produces, with `ROUTECHECK_REALDATA_OUT=DIR`, beside the existing files:
  - `DIR/routes.tsv.gz`: one line per route of every report with a policy, written as the report is read.
    - The columns are `key\toutcome\trouteobj\trpki\tdetail`.
    - `routeobj` is `yes`, `no` or `unknown` (RouteObj true, false or nil).
    - `rpki` is `rv.RPKI.String()`, or `none` when RPKI is nil.
    - `detail` is the Undecided reason kinds, sorted and comma-joined, and empty for any other outcome (as
      `routeLine` builds it).
    - Lines come in pair order. One pair's lines are contiguous.
  - `DIR/pairs.tsv`: `pair\tstatus` for every pair in the `PAIRS:` list, in that order. Status is `checked`,
    `timeout`, `error` or `not selected`.
  - `routeLineV2(key string, rv *routecheck.RouteVerdict) string` builds a `routes.tsv.gz` line.
  - The gzip writer and its file are owned by `realOut`, and `finish` and `abort` close them. Every write error
    fails the run.

- [ ] **Step 1: Write the failing tests:**
  - `TestRouteLineV2`:
    - an Accepted route with RouteObj true and RPKI valid gives `…\taccepted\tyes\tvalid\t`;
    - an Undecided one with reasons `unevaluable` and `peval`, RouteObj nil and RPKI nil gives
      `…\tundecided\tunknown\tnone\tpeval,unevaluable`.
  - `TestRealOutRoutesStream`:
    - two pairs through `report` and `addPair`, one of them a timeout;
    - after `finish`, `routes.tsv.gz` decompresses to exactly the checked pair's lines, in report order;
    - `pairs.tsv` lists both pairs with `checked` and `timeout`;
    - nothing is held: the realOut keeps no per-route state for these lines (assert `got` stays empty without TRACK).

- [ ] **Step 2: Run** `GOWORK=off go test -run 'TestRouteLineV2|TestRealOutRoutesStream|TestRealOutTracked' .`. Expected: FAIL.

- [ ] **Step 3: Implement.**
  - `report` writes each line to the run's gzip writer through a field on `pairResult`, set by `checkPair` from
    `realOut`; nil without OUT.
  - A write error is recorded on the pairResult and returned by `addPair`.
  - The pair loop records each pair's status, including `not selected` from `ROUTECHECK_REALDATA_PAIRS`.
  - Document both files in `TestRealData`'s comment.

- [ ] **Step 4: Run** the focused tests and then `scripts/check.sh` under the guard. Expected: PASS and `SUCCESS`.

- [ ] **Step 5: Commit**: `realdata: stream one line per route and each pair's status (ROUTECHECK_REALDATA_OUT)`.

### Task 3: Compare two runs

**Files:**
- Create: `provenance_test.go` (package `routecheck_test`)

**Interfaces:**
- Consumes: Task 2's `routes.tsv.gz` and `pairs.tsv`.
- Produces:
  - `type provRoute struct{ Outcome, RouteObj, RPKI, Detail string }`.
  - `type pairReader struct{ … }`, with:
    - `newPairReader(files []string) (*pairReader, error)`;
    - `(*pairReader) Next() (pair string, routes map[string]provRoute, err error)`, which returns `io.EOF` at the
      end.
    - It reads the files in the order given. A pair id that appears again after another pair, or a key repeated
      within a pair, is an error naming it. A gzip or read error is returned.
  - `readPairStatus(files []string) (map[string]string, []string, error)` reads every `pairs.tsv` given (shards).
    - It returns each pair's status and the pair order.
    - A pair `checked` in two shards is an error.
    - `not selected` in one shard and another status in the other gives the other.
  - `type provTally struct` holds:
    - per direction, the outcome matrix A × other over {accepted, rejected, undecided, no verdict};
    - for `undecided → *`, a sub-count by A's Detail;
    - the route-object matrix over {yes, no, unknown} × the same;
    - the RPKI state of `routeobj yes → no` and of `accepted → rejected`;
    - the universe size, split into: in both, A only, other only.
  - `comparePair(t *provTally, a, b map[string]provRoute, aStatus, bStatus string, subset50 bool) error`.
    - The universe is the union of both maps' keys. A key missing from a side is `no verdict` there, with a
      sub-reason `pair <status>` when that side's pair status is not `checked`, else `no policy`.
    - A route-object `no → yes` is an error naming the key.
    - With subset50, it adds to the 50-pair self-check counters (A's import `yes`, the other run's import `yes` on
      the same routes).
  - `TestProvenanceCompare`:
    - it skips unless `ROUTECHECK_PROVENANCE_A` is set; it also reads `ROUTECHECK_PROVENANCE_B` (each a
      comma-separated list of run DIRs, shards in order), `ROUTECHECK_PROVENANCE_LABEL` (`R` or `V`) and
      `ROUTECHECK_PROVENANCE_EXCLUDE` (the 10 pair ids above);
    - it zips the two pair readers in pair order and logs, per direction: the outcome matrix, the undecided
      sub-counts, the route-object matrix with the `yes → no` share of A's `yes`, the RPKI tables, the universe
      split with every sum checked (an unequal sum fails), and the self-check;
    - it fails if A's 50-pair import `yes` is not 1,568,538;
    - it also logs, per direction, the totals-only figure (A's `yes` count minus the other run's), both runs'
      route-object denominators (yes + no), and whether the totals-only figure equals the route-by-route `yes → no`
      count. When the denominators differ, it says that the totals-only shortcut does not apply (design, settled 2).

- [ ] **Step 1: Write the failing tests:**
  - `TestPairReaderOrder`:
    - two shard files [pair 1, pair 2] and [pair 3] read as 3 pairs in order;
    - [pair 1] [pair 2, pair 1] is an error naming pair 1;
    - a key repeated in a pair is an error.
  - `TestPairReaderTruncated`: a gzip file cut in half gives an error, not EOF.
  - `TestCompareNoVerdict`:
    - a key in A with no counterpart in B, where B's pair is `checked`, counts `accepted → no verdict (no policy)`;
    - with B's pair `timeout`, it counts as `no verdict (pair timeout)`;
    - the universe counts it once.
  - `TestCompareRouteObj`:
    - `yes → no`, with RPKI `valid`, is tallied with its RPKI state;
    - `no → yes` returns an error naming the key.
  - `TestCompareSums`: a table built from 5 mixed routes sums to 5 in every view.

- [ ] **Step 2: Run** `GOWORK=off go test -run 'TestPairReader|TestCompare' .`. Expected: FAIL (undefined).

- [ ] **Step 3: Implement.** The zip holds two pairs' maps at a time, never a whole run.

- [ ] **Step 4: Run** the focused tests and then `scripts/check.sh` under the guard. Expected: PASS and `SUCCESS`;
  `TestProvenanceCompare` skips.

- [ ] **Step 5: Commit**: `provenance: compare two real-data runs route by route`.

### Task 4: Measure and publish (controller)

**Files:**
- Create (git-ignored): logs and run DIRs under `.data/provenance/`
- Modify:
  - `docs/routecheck.md`: in the caveat (the "Load every registry" bullet), replace "How much of that rests on
    RADB and the mirrors, which do not check resource holders, was not measured";
  - `CHANGELOG.md`: `[Unreleased]`, `### Measured, registry provenance`;
  - `CLAUDE.md`: the real-data bullets.

- [ ] **Step 1: Run A** under the guard with `ROUTECHECK_REALDATA_OUT=.data/provenance/A`, logged to `.data/provenance-A.log`.
  Expected: PASS, 60 of 60, and TOTALS equal to `.data/missing-sets-A.log`'s but for timing. Record the peak RSS.
- [ ] **Step 2: Run R**: the same, plus `ROUTECHECK_REALDATA_ROUTES_FROM=ripe,apnic,arin,afrinic,lacnic`, OUT `.data/provenance/R`,
  log `.data/provenance-R.log`. If the guard stops it, rerun in shards with `ROUTECHECK_REALDATA_PAIRS`, one at a
  time, into `R1`, `R2`, …
- [ ] **Step 3: Run V**: `ROUTECHECK_REALDATA_REGISTRIES=ripe,apnic,arin,afrinic,lacnic`, OUT `.data/provenance/V`, log
  `.data/provenance-V.log`. Shard the same way if needed.
- [ ] **Step 4: Compare** A–R and A–V with `TestProvenanceCompare`, logging to `.data/provenance-AR.log` and `-AV.log`. Expected:
  - PASS, with the self-check at 1,568,538 and no `no → yes`;
  - every sum equal to its universe;
  - A's route-object totals per direction equal to A's TOTALS line.

  Hand-check one route of each non-zero `yes → no` and `accepted → rejected` cell against the dumps: grep the route
  object's registry.
- [ ] **Step 5: Docs.**
  - Replace the caveat sentence with the measured answer:
    - route-object answers resting only on unverified route objects (60 pairs, and the 50-pair share of the old
      rise);
    - verdict changes A–R and A–V in both directions;
    - the RPKI states;
    - the grouping assumption (JPIRR with RADB);
    - each log.
  - Add the CHANGELOG Measured section and the CLAUDE.md env bullet.
  - Run `scripts/check.sh` under the guard. Expected: `SUCCESS`.
- [ ] **Step 6: Commit**: `docs: the registry-provenance measurement`.
