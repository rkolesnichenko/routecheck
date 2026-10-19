# Stream Reports (memory phase 2) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `Check`'s reports are handed over as they are built and let go, by the library, the command and the
real-data test, with byte-identical output, and the three memory targets are measured.

**Architecture:**
- **Library.** `Checker.CheckEach` runs the check and calls a function per finished report. `Check` becomes
  `CheckEach` plus collecting. `DirectNotChecked` is counted before a family's first report.
- **Command.** It renders each report into its output bytes (text sections or JSON) as the report arrives, keeps
  only bytes and small flags, and writes them in today's order once the check succeeds.
- **Real-data test.** It processes each report on arrival, and spools `routes.tsv.gz` and `rejected-missing.tsv`
  lines through per-pair temporary files.

**Tech Stack:** Go 1.23, rpsl v0.30.0.

**Spec:** `docs/superpowers/specs/2026-10-19-stream-reports-design.md` (its predecessor's addendum:
`docs/superpowers/specs/2026-10-19-memory-profile-design.md`).

## Global Constraints

- **Byte-identical output.** Text and JSON output, the exit status, and stderr are byte-identical to v0.5.0,
  including on failure: a failed run has empty stdout, no route-object note, and exit 3 (ruling R28;
  `TestFailures` and `TestNoSession` are unchanged).
- **The goldens are not regenerated.** `testdata/golden/*` must pass untouched.
- **JSON field order** stays as the goldens have it: AF, Coverage, Import, Export.
- **`Check` stays.** Its signature and results are unchanged. `api/*.txt` gains only `CheckEach`; regenerate with
  `ROUTECHECK_API_UPDATE=1 GOWORK=off go run ./internal/apisurface -check` and review the diff.
- **`routes.tsv.gz` and `rejected-missing.tsv`** stay byte-identical. A pair that timed out or failed writes none of
  its lines to either.
- **The guard as always:** `MEMGUARD_NORMAL_PRIORITY=1 ../rpsl/.superpowers/sdd/tools/memguard.sh 8 TIMEOUT env GOWORK=off GOMAXPROCS=4 GOMEMLIMIT=6GiB …`.
  - One heavy run at a time, never beside check.sh, no network.
  - The command target is measured on the built binary.
- **Targets (MiB):**
  - pair 2 alone with `ROUTECHECK_REALDATA_OUT` completes in runs R and V under the 8 GB guard;
  - the 60-pair run A with `ROUTECHECK_REALDATA_OUT` peaks ≤ 6,144;
  - the command run peaks ≤ 5,120.
- **Never in the shipped command:** no local home-directory paths in anything committed. Every figure comes from a
  command run, and names its log.
- **check.sh:** `scripts/check.sh` passes under the guard at the end of each task.

## Review Focus

1. **A check that fails after some reports.** Empty stdout, no note, exit 3, in both formats. Task 2's
   `TestFailureAfterSomeReports` pins it.
2. **A callback that returns an error.** `CheckEach` stops at once, calls nothing more, and returns that error
   wrapped as is (`errors.Is` holds). Task 1's `TestCheckEachCallbackError` pins it.
3. **A family whose export ran with no neighbour.** Text still prints `export, <X>: no neighbour seen` and JSON
   still writes `"Export": []`. This needs CheckEach's returned `Result` to tell "export ran, no report" from
   "export not asked". Task 1's `TestCheckEachEmptyExport` and the collector goldens pin it.
4. **Reports actually released.** After `CheckEach` returns, no report it handed over is still referenced by the
   library. Task 1's `TestCheckEachReleasesReports` pins it.
5. **A pair that fails between two good pairs.** Its spooled lines appear nowhere, and its temporary files are
   removed. Task 3's `TestPairSpool` pins it.

---

### Task 1: Checker.CheckEach in the library

**Files:**
- Modify: `check.go` (`Check`, the family loop near lines 310-350, `famRun.perNeighbour` near 626), `api/routecheck.txt`
- Test: `check_test.go`

**Interfaces:**
- Produces:
  ```go
  // CheckEach is Check, handing each finished report to f instead of keeping it ...
  func (c *Checker) CheckEach(ctx context.Context, mode Mode, records iter.Seq2[mrt.Record, error], o Options,
      f func(res *Result, dir Direction, rep *Report) error) ([]Result, error)
  ```
  - **The order:** per family in `Check`'s order, the import report (dir `DirImport`), then the export reports
    (`DirExport`) in `Check`'s order.
  - **What `res` is:** that family's `Result`, complete before its first report, with `Coverage.DirectNotChecked`
    already counted, and with `Import` nil and `Export` nil.
  - **What `f` may do:** keep `rep`. The library holds no reference to it after `f` returns, and the caller must
    not modify `res`.
  - **An error from `f`** stops the check, and `CheckEach` returns it unwrapped, with nil results.
  - **The returned `[]Result`** is `Check`'s, with every report removed:
    - `Import` is nil;
    - `Export` is nil when export was not checked, and an empty non-nil slice when it was, whatever the number of
      reports.
  - **`Check`** is `CheckEach` with an `f` that collects, and its results are exactly today's.
  - **`DirectNotChecked`** moves out of `perNeighbour` into a count made before the family's first report.

- [ ] **Step 1: Write the failing tests:**
  - `TestCheckEachMatchesCheck`: on the fixtures of `TestCheckSessionImport`, `TestCheckCollectorExportPerNeighbour`
    and `TestCheckFamilies`:
    - the reports collected from `f`, in order with their `res.AF` and `dir`, deep-equal what `Check` returns for
      the same input;
    - CheckEach's results equal Check's with the reports removed, as above.
  - `TestCheckEachEmptyExport`: a collector capture in which X has no neighbour in one family. That family's
    returned `Export` is non-nil and has length 0, no `DirExport` call is made for it, and `Check`'s `Export` there
    is also empty and non-nil.
  - `TestCheckEachCallbackError`: `f` returns a sentinel on its second call. `CheckEach` returns an error that
    `errors.Is` the sentinel, with nil results, and `f` was called exactly twice.
  - `TestCheckEachReleasesReports`:
    - In `f`, for each report with routes, `runtime.SetFinalizer(&rep.Routes[0], …)` counts into an atomic, and `f`
      keeps nothing.
    - After `CheckEach` returns and the results are dropped, `runtime.GC()` runs up to 10 times, with
      `runtime.Gosched` between.
    - Every finalizer has run. Use the collector fixture with at least 3 reports.
  - `TestDirectNotCheckedBeforeReports`: in the collector fixture with direct-feed observations,
    `res.Coverage.DirectNotChecked` seen in the first `f` call of that family equals `Check`'s final value.
- [ ] **Step 2: Run** `GOWORK=off go test -count=1 -run 'TestCheckEach|TestDirectNotCheckedBeforeReports' .`. Expected: FAIL (undefined).
- [ ] **Step 3: Implement.** Then regenerate `api/*.txt`; the diff must show only `CheckEach`.
- [ ] **Step 4: Run** the focused tests with `-race`, then `scripts/check.sh` under the guard (log `.data/check-stream-t1.log`). Expected: PASS, then `SUCCESS`.
- [ ] **Step 5: Commit**: `routecheck: CheckEach hands each report over as it is built`.

### Task 2: the command streams through CheckEach

**Files:**
- Modify: `internal/cli/cli.go` (`Run`), `internal/cli/text.go` (`writeText`, `printer`), `internal/cli/json.go`
  (`writeJSON`)
- Test: `internal/cli/cli_test.go`

**Interfaces:**
- Consumes: Task 1's `CheckEach`.
- Produces: `Run` calls `CheckEach`.
  - **The callback keeps only:**
    - the report's rendered bytes, in today's text or JSON form;
    - for text, per family, the route count of the first report that is not `NoPolicy` (what `heldRoutes`
      reads);
    - for text, whether any report's `Policy.Undecided` has `peval.WhyLocalRouter` or `peval.WhyPeerRouter` (what
      `hint` reads);
    - whether any report has `Rejected > 0`, for the exit status.
  - **It keeps no `*Report`.**
  - **After `CheckEach` succeeds,** and after the existing session checks and the note, `Run` writes the output in
    today's order from the held bytes and flags.
  - **JSON:** each report is encoded as `encoding/json`'s indented encoder would encode it at its depth, inside a
    hand-written frame (`[`, the `Result` objects with AF, Coverage, Import and Export in that order, `]`), so the
    bytes equal today's.

- [ ] **Step 1: Write the failing tests:**
  - `TestFailureAfterSomeReports`: an `-irrd` run against the in-process IRRd (`serve`) whose policy makes the
    import report succeed. The export report then fails: X's aut-num is missing, or the server is closed after
    the first report, whichever the existing helpers allow.
    - Assert, for `-format text` and for `-format json`: stdout is empty, stderr has no `route objects:` line,
      and the exit status is 3.
  - `TestStreamingMatchesGoldens`: the existing `TestGoldens` must pass untouched. Also add one multi-family
    collector case with several exports and an empty-export family, checked in both formats against today's
    rendering. Write that golden with the current code before changing anything (commit it first, in the same
    task), then make the change and require it unchanged.
- [ ] **Step 2: Run** `GOWORK=off go test -count=1 -run 'TestFailureAfterSomeReports|TestGoldens|TestStreamingMatchesGoldens|TestFailures|TestNoSession' ./internal/cli`. Expected: the new golden case passes on the old code, and `TestFailureAfterSomeReports` passes on the old code too: it pins behaviour that must not change.
- [ ] **Step 3: Implement** the streaming `Run`, text and JSON.
- [ ] **Step 4: Run** the same tests, then `GOWORK=off go test -count=1 ./internal/cli`, then `scripts/check.sh` under the guard (log `.data/check-stream-t2.log`). Expected: PASS, with no golden file changed (`git diff --stat testdata/golden` is empty apart from the case added in step 1).
- [ ] **Step 5: Commit**: `cli: stream reports through CheckEach, output unchanged`.

### Task 3: the real-data test streams, and spools its per-pair lines

**Files:**
- Modify: `realdata_test.go` (`checkPair` near 1337-1400, `pairResult`, `addPair` near 433, `openRealOut`)
- Test: a new `realdata_spool_test.go`

**Interfaces:**
- Consumes: Task 1's `CheckEach`.
- Produces:
  - **checkPair calls CheckEach,** and the callback does today's per-report work (`pairResult.report`,
    `summarize`), plus what `summarize` needs per family from `res`.
  - **routes.tsv.gz and rejected-missing.tsv lines** are written as produced to two per-pair temporary files in
    the OUT directory (`.pair-<i>.routes` and `.pair-<i>.rejected`).
  - **addPair** appends the files to the outputs, in pair order, only for a pair that was checked. It then
    removes them.
  - **A pair that timed out or failed** has its files removed, unappended.
  - **The tracked lines** (`r.lines`) are as today. The OUT and TRACK behaviour is otherwise unchanged.

- [ ] **Step 1: Write the failing test** `TestPairSpool`. Through the spool API, pair 1 (checked) writes lines a1
  and a2, pair 2 (failed) writes b1, and pair 3 (checked) writes c1.
  - The decompressed `routes.tsv.gz` and `rejected-missing.tsv` hold a1, a2, c1, in that order.
  - No `.pair-*` file remains.
- [ ] **Step 2: Run** `GOWORK=off go test -count=1 -run TestPairSpool .`. Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** the test, the root package's tests, then `scripts/check.sh` under the guard (log `.data/check-stream-t3.log`). Expected: PASS, then `SUCCESS`.
- [ ] **Step 5: Commit**: `realdata: stream reports and spool each pair's lines`.

### Task 4: measure, compare, document (controller)

**Files:**
- Modify: `CHANGELOG.md` (`[Unreleased]`: Added, Changed, Measured), `CLAUDE.md` (a new ruling, R29), `docs/routecheck.md` (memory figures)

- [ ] **Step 1: The command, on the binary.** Run `.data/max-prefixes-cli-runs.zsh`'s command at 2097152 under the
  guard, built at head, with its own log `.data/stream-cli-2097152.log`.
  - Expected: exit 1, and output equal to `.data/verified-counts-2097152.log` apart from memory and timing lines.
  - Peak RSS ≤ 5,120 MiB; record it whether or not it is met.
- [ ] **Step 2: The 60-pair run A**, with `ROUTECHECK_REALDATA_OUT=.data/stream/A`, as `.data/provenance-A.log` was
  run, under the guard (log `.data/stream-A.log`).
  - Expected: TOTALS equal `.data/provenance-A.log`'s.
  - The decompressed `routes.tsv.gz` and `rejected-missing.tsv` byte-equal `.data/provenance/A`'s.
  - Peak ≤ 6,144 MiB.
- [ ] **Step 3: Pair 2 alone in runs R and V**, with OUT, as `.data/provenance-shards.zsh` does, under the guard
  (logs `.data/stream-R2.log`, `.data/stream-V2.log`).
  - Expected: both complete, with their peaks recorded.
  - Their pair-2 routes are new results. Report their counts, and do not compare them with anything.
- [ ] **Step 4: For a missed target,** record the figure. Name the addendum's next candidates (a compact
  `RangeSet`, a GC setting) for the maintainer, and build nothing more.
- [ ] **Step 5: Document.**
  - CHANGELOG: Added `CheckEach`; Changed (the command and the real-data test stream); Measured (the three figures
    with their logs, and the before figures).
  - CLAUDE.md, R29: reports are handed over and let go; `Check` collects. The command writes only after success.
  - docs/routecheck.md: its memory figures.
  - Run `scripts/check.sh` under the guard. Expected: `SUCCESS`.
- [ ] **Step 6: Commit**: `docs: streamed reports, measured`.
