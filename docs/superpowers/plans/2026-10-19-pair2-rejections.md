# Pair 2 Rejections Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Classify pair 2's 252,133 export rejections in run R (route objects from the RIRs only) as gap, real or
unknown, with the missing-sets method, and publish the result.

**Architecture:**
- **Test code:** the real-data test learns to combine `_ROUTES_FROM` with `_EXTRA`, and to keep tracked lines
  without copying their set lists. The classifier learns to stream and intern, to use R's class names, to split by
  A's outcome and by the route-object answers, and to give a sensitivity table.
- **The controller then runs, in order:**
  1. a control, which must reproduce R2;
  2. the live lookup and run-B rounds, after the maintainer's go-ahead;
  3. the classification;
  4. the docs.

**Tech Stack:** Go 1.23 test code (`realdata_test.go`, `missingsets_classify_test.go` and their tests).

**Spec:** `docs/superpowers/specs/2026-10-19-pair2-rejections-design.md`

## Global Constraints

- **Code changes** are limited to `_test.go` files. Besides them, only docs, CHANGELOG and CLAUDE.md change. The
  command, the API and go.mod do not.
- **Output formats do not change.** `tracked.tsv`, `rejected-missing.tsv`, `missing-sets.tsv`, `routes.tsv.gz`
  and `pairs.tsv` stay byte for byte what the earlier code writes for the same run. The classifier's
  `routes.tsv` keeps its format, with only the class names changing under the R option.
- **The R class names** (design, Settled 1):
  - `gap`;
  - `real without the unverified route objects`;
  - `real for an RIR-objects filter`;
  - `unknown`.

  The unknown reasons are unchanged.
- **The run-B environment** is R2's (`.data/stream-runs.zsh`) plus `_EXTRA` and `_TRACK`:
  `ROUTECHECK_REALDATA=$PWD/.data/realdata ROUTECHECK_REALDATA_MAX_PREFIXES=2097152 ROUTECHECK_REALDATA_ROUTES_FROM=ripe,apnic,arin,afrinic,lacnic ROUTECHECK_REALDATA_PAIRS=2`
  (check `$rirs` in `.data/stream-runs.zsh` and use exactly its value).
- **Lookup.** The lookup works in `.data/pair2-rejections/lookup`, a copy of `.data/missing-sets/lookup` (cache and
  `queries.log` included). The cap stays at 5,000 queries, counted with `queries.log`'s existing 1,641 lines.
  - IN names `.data/missing-sets/A/missing-sets.tsv`, `B1`–`B4`'s, `.data/stream/R2/missing-sets.tsv` and this
    measurement's rounds.
  - **No live query is sent before the maintainer's explicit go-ahead in the conversation.**
- **Runs:** every heavy run under the guard, one at a time, never beside check.sh:
  `MEMGUARD_NORMAL_PRIORITY=1 ../rpsl/.superpowers/sdd/tools/memguard.sh 8 TIMEOUT env GOWORK=off GOMAXPROCS=4 GOMEMLIMIT=6GiB …`.
- **Figures:** every figure comes from a command run and names its log. No local home-directory paths in anything
  committed.

## Review Focus

1. **Equal set lists must share one backing array** (in `realOut` and in `readTracked`); a copy per line is the
   5 GB failure. Tasks 1 and 2 pin it with pointer-equality tests.
2. **`tracked.tsv` bytes must be unchanged** for a run that tracks keys, including a "none" line for an unchecked
   pair. The existing `TestRealOutTracked` and `TestTrackedLines` stay green unchanged.
3. **Under `_ROUTES_FROM`, the extra dump's route objects are dropped and its sets kept.** Task 1's test pins
   both. Without `_ROUTES_FROM`, `_EXTRA` behaves as before (`TestLoadRegistryExtraDumpRanksLast` green).
4. **A tracked key missing from A's or R's routes file is an error naming it, never a silent "none" row.** So are
   split tables that do not sum to the total (Task 2).
5. **A malformed tracked line still fails naming its file and line,** now that the reader streams
   (`TestReadTracked` green).

---

### Task 1: the real-data test combines `_ROUTES_FROM` with `_EXTRA`, and keeps tracked lines compact

**Files:**
- Modify: `realdata_test.go`:
  - the doc ~:116-150 and the refusal ~:214-216;
  - `loadRegistry`'s route drop;
  - `realOut.got` ~:359 and `pairResult.lines`, `addPair` ~:550-588, `finish` ~:645-660.
- Test: `realdata_registry_test.go`.

**Interfaces:**
- Produces:
  - `_EXTRA` works with `_ROUTES_FROM`. The extra dump's registry ("extra") is never in `_ROUTES_FROM`'s list, so
    its route and route6 objects (and their `member-of:` claims) are dropped, and its sets and other objects are
    loaded.
  - A tracked result is held as `trackedResult{Outcome, Detail, Sets string}`. `Sets` is the comma-joined list,
    interned through one `map[string]string` per run, so equal lists share one string. `tracked.tsv` is written
    from it with the same bytes as before.

- [ ] **Step 1: Write the failing tests**:
  - `TestLoadRegistryRoutesFromWithExtra`. The fixture is a RIR dump with a route, plus an extra dump holding an
    as-set and a route, with `routesFrom` = that RIR. Assert three things:
    - the extra's as-set is loaded;
    - the extra's route is not;
    - the RIR's route is loaded.
  - `TestTrackedSetsInterned`. Two tracked routes of one pair, rejected with the same missing sets, give
    `trackedResult`s whose `Sets` have equal `unsafe.StringData`. The `tracked.tsv` written is byte-identical to the
    format `TestRealOutTracked` pins.
- [ ] **Step 2: Run** `GOWORK=off go test -count=1 -run 'TestLoadRegistry|TestTracked|TestRealOut|TestReadTrackKeys|TestParseRoutesFrom' .`. Expected: the new tests FAIL, the existing ones PASS.
- [ ] **Step 3: Implement.**
  - Remove the refusal, and update the doc comment (`_ROUTES_FROM` "cannot be used with `_EXTRA`" goes) and the
    CLAUDE.md line saying the same.
- [ ] **Step 4: Run** the same tests, then `scripts/check.sh` under the guard (log `.data/check-p2rej-t1.log`). Expected: PASS, then `SUCCESS`.
- [ ] **Step 5: Commit**: `realdata: _EXTRA with _ROUTES_FROM; tracked lines share their set lists`.

### Task 2: the classifier streams, uses R's names, splits, and gives a sensitivity table

**Files:**
- Modify: `missingsets_classify_test.go` (`readTracked` ~:46, `classifyRoute` ~:103, `TestMissingSetsClassify`
  ~:318 and its doc).

**Interfaces:**
- Produces:
  - **`readTracked`** streams the file with a `bufio.Reader`, line by line (a line can exceed 21 KB). Equal set
    fields share one `[]string`. Errors are unchanged.
  - **`ROUTECHECK_MISSINGSETS_RIR_ONLY=1`** switches the two "real" class names to the R names (Global
    Constraints), in the log and in `routes.tsv`.
  - **`ROUTECHECK_MISSINGSETS_A_ROUTES` and `ROUTECHECK_MISSINGSETS_R_ROUTES`** (a `routes.tsv.gz` each, optional,
    used together) add two split tables over all tracked routes:
    - by A's outcome × class;
    - by the route-object answer, A → R (`yes → no`, `no → no`, and each other pair seen), × class.

    Each split table logs the unknown reasons, checks that its rows sum to the total, and checks that every tracked
    key was found in both files (an error otherwise). The gz files are streamed, keeping only tracked keys.
  - **`ROUTECHECK_MISSINGSETS_TAKE_NOT_FOUND`** (set names, comma-separated, matched as `setKey`) logs one more
    table, titled "sensitivity: … taken as not found", in which those sets' class reads "not found". `routes.tsv`
    and the main tables keep the method's classes.

- [ ] **Step 1: Write the failing tests**, on small files in `t.TempDir()`:
  - `TestReadTrackedInternsSets`: two lines with the same sets field give `&a.Sets[0] == &b.Sets[0]`.
  - `TestClassifyRIROnlyNames`: with the option, a rejected route with no missing set reads
    `real without the unverified route objects`, and one with only deleted or not-found sets reads
    `real for an RIR-objects filter`.
  - `TestClassifySplits`. Three tracked keys, with A outcomes undecided, accepted and rejected, and route-object
    answers yes→no, no→no and yes→no:
    - each split row holds the right class counts, and the rows sum to 3;
    - a tracked key absent from A's file is an error naming the key.
  - `TestClassifyTakeNotFound`: a route whose only missing sets are a deleted one and an inconclusive X is unknown
    in the main table, and in the sensitivity table with X taken as not found it is `real for an RIR-objects filter`
    (with the R option).

  Refactor `TestMissingSetsClassify`'s body into a function the tests can call with explicit inputs, if that is the
  cleanest way to test it.
- [ ] **Step 2: Run** `GOWORK=off go test -count=1 -run 'TestReadTracked|TestMergeTracked|TestClassify|TestParseSubset|TestMissingSets' .`. Expected: the new tests FAIL, the existing ones PASS.
- [ ] **Step 3: Implement.** Update the doc comment of `TestMissingSetsClassify` with the new variables.
- [ ] **Step 4: Run** the same tests, then `scripts/check.sh` under the guard (log `.data/check-p2rej-t2.log`). Expected: PASS, then `SUCCESS`.
- [ ] **Step 5: Commit**: `missing sets: the classifier streams, names R's classes, splits by A and route objects`.

### Task 3: control, lookup rounds, classification, and docs (controller)

**Files:**
- Create: `.data/pair2-rejections-runs.zsh` (not committed).
- Modify: `docs/routecheck.md` (the pair-2 part of the provenance section, and "What this means"), `CHANGELOG.md`
  (`[Unreleased]`), `CLAUDE.md`.

- [ ] **Step 1: The control.** Run B on pair 2 in R with `_TRACK` = `.data/stream/R2/rejected-missing.tsv` and no
  `_EXTRA`, `OUT` = `.data/pair2-rejections/B0`.
  - Log: `.data/pair2-rejections-B0.log`.
  - Expected:
    - TOTALS equal `.data/stream-R2.log`'s (apart from timing and memory);
    - `rejected-missing.tsv`, `missing-sets.tsv` and `pairs.tsv` are byte-identical (`cmp`) to `stream/R2`'s,
      and so is `routes.tsv.gz` decompressed;
    - `tracked.tsv` has 252,133 lines, all "rejected";
    - peak RSS is under the cap.
  - If any of this fails, stop and report.
- [ ] **Step 2: Ask the maintainer for the go-ahead for live queries.** Give the count of sets never looked up
  (469 expected) and the queries left under the cap (3,359). Wait for an explicit yes.
- [ ] **Step 3: The rounds** (`.data/pair2-rejections-runs.zsh`, modelled on `.data/missing-sets-rounds.zsh`).
  Per round k = 1..5:
  1. the lookup on the copy, with IN as in Global Constraints plus B1..B(k-1) of this measurement;
  2. run B_k, with `_EXTRA` = the copy's `extra.db.gz`, `_TRACK` = R2's `rejected-missing.tsv`, and `OUT` =
     `.data/pair2-rejections/B<k>`;
  3. stop at closure, at the cap, when a service stops, or at k = 5.

  Logs: `.data/pair2-rejections-round<k>-lookup.log` and `-B.log`.
- [ ] **Step 4: Classify.** Run `TestMissingSetsClassify` with:
  - `DIR` = the copy;
  - `TRACKED` = the last B's `tracked.tsv`;
  - `RIR_ONLY=1`;
  - `A_ROUTES=.data/provenance/A/routes.tsv.gz` and `R_ROUTES=.data/stream/R2/routes.tsv.gz`;
  - `TAKE_NOT_FOUND=AS-CONCERTAP`.

  Log: `.data/pair2-rejections-classify.log`. The second control: the 33,968 rejected in A are all
  `unknown / inconclusive set`. If not, stop and report.
- [ ] **Step 5: Write the docs.**
  - **The method's classes,** by A's outcome and by the route-object answers, with sums.
  - **The sensitivity table,** labelled.
  - **The family split:** the 214,472 are ipv4, and the 3,693 and 33,968 are ipv6.
  - **"What this means," rewritten** to say how much of the 214,472 is a RADB effect at all.
  - **Queries used,** from `queries.log`.
  - **CHANGELOG and CLAUDE.md:** a Measured section, and CLAUDE.md's notes on the real-data test and the
    classifier.

  Then run `scripts/check.sh` under the guard. Expected: `SUCCESS`.
- [ ] **Step 6: Commit**: `docs: pair 2's rejections without RADB, classified`.
