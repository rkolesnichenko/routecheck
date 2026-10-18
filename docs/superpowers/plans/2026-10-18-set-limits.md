# Set limits make one report unevaluable — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A `*resolve.SetTooLargeError` from peval makes only its report "unevaluable" (ruling R19's path, new
ruling R27) instead of failing the whole `Check` and the command's run with exit 3.

**Architecture:**
- `famRun.report` (check.go) matches `*resolve.SetTooLargeError` beside `*resolve.AnySetError` and takes the
  existing R19 path.
- The command gains a test-only seam to reach a limit cheaply.
- The real-data test turns its pair-level "set too large" count into a hard guard, and one every-registry run
  publishes the 10 pairs it could not check before.

**Tech Stack:**
- Go (go.mod floor 1.23), `GOWORK=off`;
- rpsl v0.30.0 (`resolve.SetTooLargeError`, its `Limit` values, `peval.Evaluator.Expander`).

**Spec:** `docs/superpowers/specs/2026-10-18-set-limits-design.md`. Read it first; it is the authority.

## Global Constraints

- **The limits.** All four rpsl limits get this treatment: `MaxPrefixes`, `MaxVisited`, `MaxDepth` and
  `MaxConjuncts`. Match with a bare `errors.As(err, &*resolve.SetTooLargeError)`; never filter on `.Limit`.
- **The unevaluable report** is R19's, unchanged:
  - `Report.Unevaluable` = the error's text, whatever the route count;
  - an empty `Policy`;
  - every route Undecided with the single reason `verdict.ReasonUnevaluable`, Why = that text, Clause -1,
    Index -1;
  - hygiene computed as for any report.
- **Failures stay failures.** A missing aut-num, a Source error, a context error, an unreadable input and an
  unreachable server still fail the run (exit 3).
- **No change to:**
  - `api/*.txt`, go.mod, or the rpsl version;
  - `verdict`, `pathre`, `observe` or `hygiene`;
  - the JSON or text formats (no new field, no new reason kind).

  A user-facing flag or environment variable for the limits is not allowed. A test-only seam in
  `internal/cli` is allowed (spec, settled 5).
- **Exit status** follows R19: 0 if nothing is Rejected, 1 if something is, never 3 because of an
  unevaluable report.
- **Heavy runs:**
  - one at a time, alone, never beside `check.sh`;
  - command prefix: `MEMGUARD_NORMAL_PRIORITY=1 GOMAXPROCS=4 ../rpsl/.superpowers/sdd/tools/memguard.sh 8
    <timeout> env GOWORK=off GOMAXPROCS=4 GOMEMLIMIT=6GiB …`, run from routecheck's root;
  - every published figure names its `.data/` log.
- No local home-directory path in any committed file. Commit on branch `set-limits`, never on `main`. Nothing
  is pushed.

## Review Focus

1. **A run where every report is over a limit.** It exits 0 or 1 by the Rejected routes, never 3, and each
   report prints its `policy not evaluable` line (Task 2, `TestUnevaluableLimit`, the both-directions case).
2. **A limit and a real failure in one run** (an over-limit import and a missing aut-num for the export). The
   run still fails with the missing aut-num's error (Task 1, `TestCheckSetTooLarge`, the last case).
3. **A limit other than `MaxPrefixes`** gives the same unevaluable report (Task 1, the `MaxDepth` case).
4. **JSON consumers.** An over-limit report's JSON has `"Unevaluable"` with the limit's text and each route's
   reason `"Kind":"unevaluable"`. The view decodes with `DisallowUnknownFields` (Task 2).
5. **The 50 comparable pairs of PR #7** keep their figures exactly in the new every-registry run. Any
   difference is a defect, not a finding (Task 3, step 4).

---

### Task 1: `Check` makes an over-limit report unevaluable

**Files:**
- Modify: `check.go`:
  - `famRun.report` (around line 462: the `errors.As` and the R19 branch);
  - `Report.Unevaluable`'s doc (around 145–152);
  - `Check`'s doc (around 200–216: move "a limit" out of the error list into the unevaluable paragraph).
- Modify: `check_test.go`:
  - replace `TestCheckPevalError` (around 615) with `TestCheckSetTooLarge`;
  - update `TestCheckUnevaluable`'s doc comment (around 643: "any other peval error still fails the run"
    becomes "a limit is unevaluable too, see `TestCheckSetTooLarge`; a missing aut-num still fails").

**Interfaces:**
- Produces: `Check` returns no error for a `*resolve.SetTooLargeError` from `Eval.Import`/`Eval.Export`. The
  report carries it in `Unevaluable`. Tasks 2 and 3 rely on this.

- [ ] **Step 1: Write the failing test** `TestCheckSetTooLarge` (check_test.go). Three cases, each a `Check`
  in session mode on `records(capture())` with `Local: asL, Peer: asX`:

  1. **`MaxPrefixes`.**
     - Registry: `TestCheckPevalError`'s (`import: from AS64500 accept AS-BIG`, `AS-BIG` with members AS64500
       and AS64501, plus `autX`), with `c.Eval.Expander = resolve.Expander{MaxPrefixes: 1}`.
     - Want:
       - `err == nil`;
       - `res[0].Import.Unevaluable` contains `"MaxPrefixes"`, and its `Policy` is empty;
       - every import route is Undecided with exactly one reason, `{Kind: verdict.ReasonUnevaluable, Why:
         Unevaluable, Clause: -1, Index: -1}`, and has its hygiene computed (as `TestCheckUnevaluable`
         checks);
       - `res[0].Export[0].Unevaluable == ""`, with the export decided: the same `summaries` as
         `TestCheckUnevaluable`'s export, if that fixture's export is the same, or else at least one route
         not Undecided.
  2. **`MaxDepth`.** A registry where AS-BIG nests sets deeper than `Expander{MaxDepth: 1}` allows (for
     example AS-BIG → AS-MID → AS64501). Want `err == nil` and `Import.Unevaluable` containing `"MaxDepth"`.
     Choose the depth so the assertion holds, and say in a comment why that depth trips the limit.
  3. **A limit plus a missing aut-num.**
     - Registry: case 1's, without `autX`, with `Directions: routecheck.DirBoth`.
     - Want: `errors.Is(err, resolve.ErrNotFound)` and `res == nil`. The missing aut-num still fails the run
       though a limit was also hit.
     - Keep `TestCheckPevalError`'s missing-aut-num assertion too, as its own check in this test.

- [ ] **Step 2: Run it and see it fail.**

  Run: `GOWORK=off go test -count=1 -run 'TestCheckSetTooLarge' .`
  Expected: FAIL in case 1: `Check` returns the `*resolve.SetTooLargeError`.

- [ ] **Step 3: Implement.**
  - In `famRun.report`, a `*resolve.SetTooLargeError` (via `errors.As`) takes the same branch as
    `*resolve.AnySetError`. Whether that is a second `errors.As` or a small helper naming both is the
    implementer's choice.
  - The branch comment names both rulings: R19 for AS-ANY and R27 for a limit.
  - Update the doc comments listed under Files.

- [ ] **Step 4: Run it, then the module.**

  Run:
  ```
  GOWORK=off go test -count=1 -run 'TestCheckSetTooLarge|TestCheckUnevaluable' .
  GOWORK=off go vet ./... && GOWORK=off go test -count=1 ./...
  ```
  Expected: PASS.

- [ ] **Step 5: Commit**
  ```
  git add check.go check_test.go
  git commit -m "check: a set over an expansion limit makes its report unevaluable (R27)"
  ```

### Task 2: the command, its test seam, and the docs that need no figures

**Files:**
- Modify: `internal/cli/cli.go` (line ~143, where `routecheck.Checker` is built).
- Modify: `internal/cli/cli_test.go`: add `TestUnevaluableLimit` next to `TestUnevaluable` (~614).
- Modify: `docs/routecheck.md`:
  - the `unevaluable` reason row (~188): add "or a set over one of rpsl's expansion limits (MaxPrefixes,
    MaxVisited, MaxDepth, MaxConjuncts)";
  - the exit-3 row (~290): drop "a limit" from "peval failing (a limit, a Source error; …)", and say a limit
    makes that report unevaluable;
  - the R19 "Known limitations" bullet (~372): add a sentence that a set over a limit is reported the same
    way.
- Modify: `SECURITY.md` (~58–61, "Never guess"): a policy over an expansion limit also makes that report
  "unevaluable" instead of failing the run.
- Modify: `CLAUDE.md`:
  - R19/R21: drop "a limit" from "Every other peval error (…) still fails the run";
  - add **R27** after R19/R21: a `*resolve.SetTooLargeError` (any of the four limits) takes R19's path for
    that report only; the run goes on; exit status as R19; no new reason kind; the CLI's test-only seam.
- Modify: `CHANGELOG.md` `[Unreleased]` → `### Changed`:
  - `Check` no longer returns `*resolve.SetTooLargeError`; the report is unevaluable instead.
  - The command no longer exits 3 for it; the exit status is 0 or 1 by the Rejected routes.
  - Every unevaluable report prints its `policy not evaluable` line.

**Interfaces:**
- Consumes: Task 1's behaviour.
- Produces: `var expander resolve.Expander` in package `cli` (internal/cli/cli.go). It is unexported and zero
  by default (rpsl's defaults), and is used as `peval.Evaluator{Src: src, Expander: expander}`. Tests set it
  and restore it in `t.Cleanup`. Its doc comment says it is a test seam that no flag sets. The package's tests
  do not run in parallel (no `t.Parallel`); keep it so in this test.

- [ ] **Step 1: Write the failing test** `TestUnevaluableLimit` (cli_test.go).
  - Registry: `TestUnevaluable`'s shape, but with L's import naming a two-member as-set
    (`import: from AS64500 accept AS-BIG`) and `expander = resolve.Expander{MaxPrefixes: 1}`.
  - Case A, default `-routes`, both directions:
    - the exit code is `exitOK`, or `exitRejected` if the fixture's export rejects a route; never
      `exitFailed`;
    - stdout contains `import, AS64496 from AS64500:` and `policy not evaluable, no route decided: `
      followed by text containing `MaxPrefixes`;
    - the export report is printed with its counts.
  - Case B, `-format json`:
    - decodes into `[]jsonResult` with `DisallowUnknownFields`;
    - `Import.Unevaluable` contains `MaxPrefixes`;
    - the compacted output contains `"Kind":"unevaluable"`;
    - `Export[0].Unevaluable == ""`.
  - Case C: with export also over the limit (X's export names a two-member as-set too), the exit is still not
    `exitFailed`, and both reports print the `policy not evaluable` line.

- [ ] **Step 2: Run it and see it fail.**

  Run: `GOWORK=off go test -count=1 -run TestUnevaluableLimit ./internal/cli`
  Expected: FAIL to build (`expander` undefined). Once it is declared but unused by the `Checker`, it fails on
  the exit code.

- [ ] **Step 3: Implement** the seam and the docs listed under Files.

- [ ] **Step 4: Run it, the module, and `check.sh`.**

  Run:
  ```
  GOWORK=off go test -count=1 ./...
  MEMGUARD_NORMAL_PRIORITY=1 GOMAXPROCS=4 ../rpsl/.superpowers/sdd/tools/memguard.sh 8 1800 scripts/check.sh > .data/check-set-limits-t2.log 2>&1; echo $?
  ```
  Expected: PASS; `0`; the log ends with `check: ok`.

- [ ] **Step 5: Commit**
  ```
  git add internal/cli/cli.go internal/cli/cli_test.go docs/routecheck.md SECURITY.md CLAUDE.md CHANGELOG.md
  git commit -m "cli, docs: an over-limit report is unevaluable; the run goes on (R27)"
  ```

### Task 3: the real-data guard, one every-registry run, and the measured docs

**Files:**
- Modify: `realdata_test.go`:
  - `checkPair`'s error switch (~919–926): a `*resolve.SetTooLargeError` from `Check` is now
    `tb.Errorf("AS%d from AS%d: Check returned a SetTooLargeError, which R27 makes a report's: %v", …)` and
    is still counted;
  - the doc comment (~83) changes to say a limit is an unevaluable report, tallied with the others.
- Modify:
  - `CHANGELOG.md` `[Unreleased]` → `### Measured`;
  - `docs/routecheck.md`: the MaxPrefixes "Known limitations" bullet (~403–415) and the 389,413 → 47,522
    paragraph (~385–402);
  - `CLAUDE.md`: the MaxPrefixes and Registries Known-limitations bullets.

**Interfaces:**
- Consumes: Task 1's behaviour. The pinned files of `.data/realdata/MANIFEST`, unchanged since PR #7.
- Consumes: `.data/same-pairs.py` (git-ignored; `python3 -I .data/same-pairs.py BASELINE EVERY [diff]`). It
  sums the per-pair log lines over the pairs both runs checked.

- [ ] **Step 1: The guard change.** Make the `realdata_test.go` edits above.

  Run: `GOWORK=off go vet ./... && GOWORK=off go test -count=1 ./...`
  Expected: PASS (`TestRealData` skips without data).

- [ ] **Step 2: Commit**
  ```
  git add realdata_test.go
  git commit -m "realdata: a SetTooLargeError from Check is an error now (R27); limits are unevaluable reports"
  ```

- [ ] **Step 3: The every-registry run, alone, under the guard.**

  Run:
  ```
  MEMGUARD_NORMAL_PRIORITY=1 GOMAXPROCS=4 ../rpsl/.superpowers/sdd/tools/memguard.sh 8 6000 env GOWORK=off GOMAXPROCS=4 GOMEMLIMIT=6GiB ROUTECHECK_REALDATA=$PWD/.data/realdata go test -count=1 -timeout 100m -run 'TestRealData$' -v . > .data/realdata-set-limits.log 2>&1; echo $?
  ```
  Expected:
  - `0`, and the log ends `SUCCESS`;
  - `TOTALS: 60 pairs: 60 checked, 0 timed out, 0 set too large, 0 other errors`;
  - `TOTALS: unevaluable reports:` lists the over-limit reports with their routes.

- [ ] **Step 4: The 50 comparable pairs did not move.**

  Run: `python3 -I .data/same-pairs.py .data/realdata-every-registry.log .data/realdata-set-limits.log > .data/set-limits-same-pairs.log`

  Expected: the 50 pairs that PR #7's every-registry run checked have identical figures in both runs:
  observations, import and export outcomes, report counts, missing sets and route objects. The script lists
  the 10 others as excluded only from the old run's side. Report any difference before going on; it stops the
  task.

- [ ] **Step 5: Hand checks**, written to `.data/set-limits-checks.log`.
  - **(a)** For pair 2 (AS9086 from AS6762), show from `realdata-set-limits.log` that AS6762's export report
    toward AS174 is unevaluable with the `MaxPrefixes` text, and that the pair's other export reports are
    decided.
  - **(b)** Run the command end to end on that pair with every dump, in precedence order, default direction:
    ```
    routecheck -local AS9086 -peer AS6762 -collector .data/realdata/filtered/AS6762.mrt -af ipv4 -dump <the 32 dumps in MANIFEST order>
    ```
    under the guard, to `.data/set-limits-cli.log`. Expected: exit 0 or 1, not 3, with
    `export, AS6762 to AS174:` followed by the `policy not evaluable` line, and the import report decided.

- [ ] **Step 6: The measured docs.**
  - **CHANGELOG `### Measured`:**
    - the run's TOTALS;
    - the unevaluable reports by limit, with their routes;
    - the 10 pairs' outcomes, now that they are checked;
    - the 50-pair identity (step 4);
    - the hand checks;
    - wall time and peak RSS;
    - each with its log.
  - **docs/routecheck.md:**
    - the MaxPrefixes bullet now says the report is unevaluable and the run goes on, so the
      "check the other direction" workaround is no longer needed;
    - the 389,413 paragraph points at the new totals.
  - **CLAUDE.md:** the two Known-limitations bullets the same way.
  - Every figure comes from a log written in steps 3–5.

  Run: `MEMGUARD_NORMAL_PRIORITY=1 GOMAXPROCS=4 ../rpsl/.superpowers/sdd/tools/memguard.sh 8 1800 scripts/check.sh > .data/check-set-limits-t3.log 2>&1; echo $?`
  Expected: `0`, `check: ok`.

- [ ] **Step 7: Commit**
  ```
  git add CHANGELOG.md docs/routecheck.md CLAUDE.md
  git commit -m "docs, real data: over-limit reports are unevaluable; all 60 pairs checked with every registry"
  ```
