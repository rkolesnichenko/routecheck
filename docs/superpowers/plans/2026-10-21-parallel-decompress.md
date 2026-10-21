# Parallel decompression of inputs Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** The command reads its compressed inputs (MRT, RPSL dumps and drafts, VRPs) through
`mrt.DecompressWith` instead of the serial `mrt.Decompress`, with output unchanged and the speedup
measured on real data.

**Architecture:**
- One helper in `internal/cli` picks the worker count per kind of input and calls
  `mrt.DecompressWith`.
- Each file's reader gets its own cancellable context, derived from `Run`'s and cancelled when that
  file is done.
- The root package's real-data tests get a test-side copy, so run A measures the same path.
- A kind that measures slower goes back to `Workers: 0`, which is exactly `mrt.Decompress`.

**Tech Stack:** Go 1.23 module `github.com/rkolesnichenko/routecheck`; mrt v0.3.2
(`DecompressWith`, `DecompressOptions{Workers, Context}`); rpsl v0.30.0.

**Spec:** `docs/superpowers/specs/2026-10-21-parallel-decompress-design.md`

## Global Constraints

- **go.mod is unchanged:** rpsl, rpsl/types and rpsl/resolve at v0.30.0, mrt at v0.3.2. No
  `replace`, no `go.work`.
- **Worker count:** `min(4, runtime.GOMAXPROCS(0))`, and `0` when GOMAXPROCS is 1. There is no new
  flag.
- **Library packages unchanged.** `.`, `observe`, `verdict`, `pathre` and `hygiene` must not change
  (principle 2). The API golden `api/` is unchanged.
- **Output unchanged.** The goldens pass without `ROUTECHECK_GOLDEN_UPDATE`. Real-data run A's four
  output files are byte-identical to `.data/stream/A`.
- **Cancellation.** A cancelled run exits 3 with empty stdout and "context canceled" on stderr. For
  MRT inputs, the error also satisfies `errors.Is(err, context.Canceled)`.
- **Every file's derived context is cancelled when that file's reading ends:** at EOF, on an error,
  or when the caller stops early.
- **No home-directory path** in any committed file or commit message.
- **Heavy runs:**
  - only under the memory guard, one at a time, never beside check.sh:
    `MEMGUARD_NORMAL_PRIORITY=1 ../rpsl/.superpowers/sdd/tools/memguard.sh 8 TIMEOUT env GOWORK=off GOMAXPROCS=4 …`;
  - output to a file under `.data/`, and the exit status on the next line;
  - the real-data runs (run A, the `cmd` runs) need the user's go-ahead first.
- **Figures.** Every figure in docs or the CHANGELOG comes from a command run in this work, with
  its log under `.data/` named. Otherwise it is "not measured".

## Review Focus

1. **A truncated or corrupt compressed input** must fail exactly as with `Decompress`: exit 3, the
   file named. Task 1's equivalence test includes a truncated `.gz` and a truncated `.bz2`.
2. **An uncompressed input**, raw MRT or plain RPSL, must still work. `DecompressWith` gives a plain
   buffered reader then, with no goroutines. Task 1 covers raw MRT; Task 2 covers a plain dump.
3. **Several `-collector` files in a row** must each have their context cancelled before the next
   opens, with no goroutines building up. Task 1's early-stop test reads two compressed files and
   checks the goroutine count after each.
4. **A cancel while a gzip dump is loading** must end the run (exit 3), not hang or panic. Task 2's
   cancel test.
5. **`-policy` given a gzip file** goes through the same `readRPSL` path. Task 2's equivalence test
   reads a gzip draft too.

---

### Task 1: The helper, and MRT inputs through it

**Files:**
- Create: `internal/cli/decompress.go`
- Create: `internal/cli/decompress_test.go`
- Create: `testdata/mrt/rv2-rib.20261015.1200.bz2`
- Modify:
  - `internal/cli/load.go:37-74`: `records` and `readInput`;
  - `internal/cli/cli.go:149`: the `records(...)` call;
  - `testdata/README.md`: the `mrt/` lines and the RouteViews section.

**Interfaces:**
- Produces (`internal/cli/decompress.go`):
  - `type inputKind int`, with the constants `kindMRT`, `kindRPSL`, `kindVRPs`.
  - `var workersFor = func(k inputKind) int`. The default gives `min(4, runtime.GOMAXPROCS(0))`,
    `0` when GOMAXPROCS is 1, and `0` for a kind in `serialKinds`. It is a variable so that tests
    can force the parallel path, as `openInput` is replaced today.
  - `var serialKinds = map[inputKind]bool{}`: the kinds measured slower in parallel (design
    decision 7). It is empty until Task 4.
  - `func decompress(ctx context.Context, r io.Reader, k inputKind) (io.Reader, error)`. It returns
    `mrt.DecompressWith(r, mrt.DecompressOptions{Workers: workersFor(k), Context: ctx})`. The caller
    owns cancelling ctx when it stops reading.
- Produces (`load.go`): `func records(ctx context.Context, names []string) iter.Seq2[mrt.Record, error]`
  and `func readInput(ctx context.Context, name string, yield func(mrt.Record, error) bool) bool`.

- [ ] **Step 1: Make the bzip2 fixture.**
  - Decompress `testdata/mrt/rv2-rib.20261015.1200.gz`, then `bzip2 -9` it into
    `testdata/mrt/rv2-rib.20261015.1200.bz2`.
  - Check that the bz2 file's decompressed sha256 is
    `ba1423bf55b5f05a1fcb4d99312e021b178df9621e1d3b24b9550c2de3e6ec0f`, the slice sha256 that
    `testdata/README.md` already records.
  - In `testdata/README.md`, add the command and that sha256, and say the file is the gzip
    fixture's bytes recompressed with bzip2.

- [ ] **Step 2: Write the failing tests** in `internal/cli/decompress_test.go`. Each test forces
  `workersFor` to return 4 for every kind, restoring it with `t.Cleanup`.
  - **`TestRecordsMatchDecompress`.** For each of the gz fixture, the bz2 fixture, the raw bytes
    (written with `write`), a truncated gz (its first half) and a truncated bz2 (its first half):
    - collect `(rec, err)` from `records(ctx, []string{f})`;
    - collect them from a serial reference, `mrt.Records` over `mrt.Decompress` of the same file,
      with errors wrapped `fmt.Errorf("%s: %w", f, err)` as `readInput` does;
    - assert the same number of records, `bytes.Equal` on each record's `Raw()`, and the same error
      text, or both nil. Collect `bytes.Clone(rec.Raw())`, since a record's bytes may share a
      buffer that the next iteration reuses.
  - **`TestRecordsEarlyStopReleases`.**
    1. Take a baseline `runtime.NumGoroutine()`.
    2. Range `records(ctx, []string{gz, bz2})`. Break after the first record of the bz2 file; for
       the gz file, read one record, then let it go on to the next file.
    3. After the loop, poll `runtime.NumGoroutine()` every 10 ms, at most 2 s, until it is at most
       the baseline.
    4. Fail with both counts if it never gets there.
  - **`TestRecordsCancelMidRead`.**
    1. Make `ctx, cancel`. Replace `openInput` with a wrapper whose reader calls `cancel()` after
       its first `Read` returns.
    2. Range `records(ctx, []string{bz2})` to the end.
    3. Assert the last error satisfies `errors.Is(err, context.Canceled)`, and that fewer records
       came than the file holds.
  - **`TestRunCancelMidRead`.**
    1. With the same `openInput` wrapper, call `runCtx(t, ctx, …)` in collector mode on the bz2
       fixture, with the golden registry `-dump`.
    2. Assert exit `exitFailed` (3), empty stdout, and stderr containing "context canceled".

- [ ] **Step 3: Run them and see them fail.**
  Run `GOWORK=off go test -count=1 -run 'TestRecords|TestRunCancelMidRead' ./internal/cli`.
  Expected: build failure (`records` takes no ctx; `workersFor` undefined).

- [ ] **Step 4: Implement.**
  - Write `decompress.go` as in Interfaces.
  - In `readInput`, right after opening the file: `ctx, cancel := context.WithCancel(ctx); defer cancel()`.
    Then `decompress(ctx, f, kindMRT)` replaces `mrt.Decompress(f)`.
  - `records` passes its ctx to `readInput`.
  - `Run` calls `records(ctx, cfg.inputs)`.
  - Update `records`' doc comment: it names `mrt.DecompressWith`, the per-file context, and the
    cancel on return.

- [ ] **Step 5: Run the package's tests.**
  Run `GOWORK=off GOMAXPROCS=4 go test -count=1 -race ./internal/cli`, output to a file and the
  status on the next line. Expected: PASS. The goldens are unchanged; do not set
  `ROUTECHECK_GOLDEN_UPDATE`.

- [ ] **Step 6: Commit.**
  ```bash
  git add internal/cli/decompress.go internal/cli/decompress_test.go internal/cli/load.go internal/cli/cli.go testdata/mrt/rv2-rib.20261015.1200.bz2 testdata/README.md
  git commit -m "cli: read MRT inputs through mrt.DecompressWith"
  ```

### Task 2: RPSL files and VRPs through the helper

**Files:**
- Modify:
  - `internal/cli/load.go`:
    - `readVRPs` (78);
    - `readRPSL` (377): open through `openInput`, so tests can watch it;
    - `readDraft` (287);
    - the `readRPSL` call in `loadPolicy` (161);
    - the `readDraft` call (147);
  - `internal/cli/cli.go:138`: the `readVRPs` call.
- Test: `internal/cli/decompress_test.go`

**Interfaces:**
- Consumes: `decompress`, `workersFor`, `kindRPSL`, `kindVRPs` (Task 1).
- Produces:
  - `func readVRPs(ctx context.Context, name string) (*rpki.VRPs, error)`;
  - `func readRPSL(ctx context.Context, name string, fn func(o rpsl.Object, class, key, source string, diags []rpsl.Diagnostic)) error`;
  - `func readDraft(ctx context.Context, name string, stderr io.Writer) (*draft, error)`.

  Each derives a per-file `context.WithCancel` and defers its cancel, as `readInput` does.

- [ ] **Step 1: Write the failing tests.**
  - **`TestReadRPSLMatchesDecompress`.**
    1. Build an RPSL text: the golden registry file (`registry`, the `-dump` that `session()`
       uses), repeated with distinct keys until it is at least 1 MiB, so the gzip readahead hands
       over more than one 128 KiB chunk.
    2. Write it raw and gzipped.
    3. For each, with `workersFor` forced to 4 and forced to 0, collect `(class, key, source,
       o.String())` from `readRPSL`.
    4. Assert all four lists are equal, and the same for `readDraft` on the gzip file (the draft
       holds the aut-nums; its stderr output must be equal too).
  - **`TestRunCancelDuringDump`.**
    1. Replace `openInput` with a wrapper that calls `cancel()` after the first `Read` of the
       gzipped 1 MiB dump.
    2. Call `runCtx` with that dump as `-dump`.
    3. Assert exit 3, empty stdout, and stderr containing "context canceled".
  - **`TestReadVRPsGzip`.** Gzip a VRP JSON fixture from `testdata/rpki/`. `readVRPs` with
    `workersFor` forced to 4 must give the same VRPs (`reflect.DeepEqual`) as on the raw file.
  - **`BenchmarkReadVRPs`.** Opt-in: it is skipped unless `ROUTECHECK_BENCH_VRPS` names a file.
    Sub-benchmarks `workers=0` and `workers=default` each call `readVRPs` on that file. Task 4 uses
    it.

- [ ] **Step 2: Run them and see them fail.**
  Run `GOWORK=off go test -count=1 -run 'TestReadRPSL|TestRunCancelDuringDump|TestReadVRPs' ./internal/cli`.
  Expected: build failure (signatures).

- [ ] **Step 3: Implement** the three signatures in Interfaces.
  - Pass `ctx` from `Run` to `readVRPs`, and from `loadPolicy` to `readRPSL` and `readDraft`.
  - Each reader uses `decompress(ctx, f, kindRPSL|kindVRPs)`.
  - `readRPSL` opens through `openInput`.
  - Keep `readRPSL`'s read-error path as it is (`rpsl/read-error` → `fmt.Errorf("%s: reading: %s", …)`).
    The cancel's text reaches stderr through it, as the design's decision 5 accepts.

- [ ] **Step 4: Run the package's tests.**
  Run `GOWORK=off GOMAXPROCS=4 go test -count=1 -race ./internal/cli`, output to a file and the
  status on the next line. Expected: PASS, goldens unchanged.

- [ ] **Step 5: Commit.**
  ```bash
  git add internal/cli/load.go internal/cli/cli.go internal/cli/decompress_test.go
  git commit -m "cli: read RPSL files and VRPs through mrt.DecompressWith"
  ```

### Task 3: The real-data tests read the same way

**Files:**
- Modify:
  - `realdata_test.go:931-990` (`loadRegistry`, the `mrt.Decompress` at 957);
  - `realdata_test.go:1084-1112` (`readMRT`, at 1095);
  - `missingsets_test.go:773-783` (`heldIndex.scan`, at 779).
- Create: `decompress_test.go` (package `routecheck_test`).

**Interfaces:**
- Produces: `func decompressFile(r io.Reader) (io.Reader, context.CancelFunc, error)` in
  `decompress_test.go`.
  - It calls `mrt.DecompressWith` with `Context: ctx`, where `ctx, cancel :=
    context.WithCancel(context.Background())`, and the worker count from the same rule as
    `workersFor`'s default. A comment says it mirrors `internal/cli`'s `workersFor`, which is
    unexported.
  - The caller defers the cancel (before `f.Close`).
  - `readMRT` cancels on every return path, including the early `return` after `!yield`.
  - No `serialKinds` here. If Task 4 makes a kind serial, Task 4 applies the same choice to its
    caller here.

- [ ] **Step 1: Write `TestDecompressFileMatches`** in `decompress_test.go`, over
  `testdata/mrt/rv2-rib.20261015.1200.gz` and `.bz2`. The bytes read through `decompressFile` must
  be `bytes.Equal` to those read through `mrt.Decompress`.

- [ ] **Step 2: Run it and see it fail.**
  Run `GOWORK=off go test -count=1 -run TestDecompressFileMatches .`. Expected: build failure
  (`decompressFile` undefined).

- [ ] **Step 3: Implement** `decompressFile` and switch the three call sites to it.

- [ ] **Step 4: Run the root package's tests.**
  Run `GOWORK=off GOMAXPROCS=4 go test -count=1 -race .`, output to a file and the status on the next
  line. Expected: PASS. The real-data tests skip without `ROUTECHECK_REALDATA`.

- [ ] **Step 5: Commit.**
  ```bash
  git add decompress_test.go realdata_test.go missingsets_test.go
  git commit -m "test: real-data readers use mrt.DecompressWith"
  ```

### Task 4: Measure, decide per kind, document

This task runs the heavy, real-data runs. **Ask the user before Step 2.**

**Files:**
- Create: `.data/parallel-decompress-runs.zsh`. It is git-ignored and not committed.
- Modify:
  - `internal/cli/decompress.go` (`serialKinds`) and `decompress_test.go`, only if a kind falls
    back;
  - `CHANGELOG.md` (Unreleased);
  - `docs/routecheck.md:32-33`;
  - `CLAUDE.md` (the real-data figures).

**Interfaces:**
- Consumes: everything from Tasks 1–3. `BenchmarkReadVRPs` comes from Task 2.

- [ ] **Step 1: Write `.data/parallel-decompress-runs.zsh`**, modelled on `.data/mrt-v032-runs.zsh`,
  with these steps:
  - **`bins`.** Build `.data/rc-before` from `main` (a `git worktree add` of main in `.data/wt-main`,
    removed afterwards) and `.data/rc-after` from this branch's HEAD. Print both commits.
  - **`cmd`.** Run the command of `.data/stream-runs.zsh` `cmd` (every `-dump`, `-collector
    .data/realdata/filtered/AS6762.mrt`, `-local AS9086 -peer AS6762 -max-prefixes 2097152`).
    - Run it four times, alternating before, after, before, after, each under the guard with a
      1,800 s timeout.
    - Logs go to `.data/pd-cmd-{before,after}-{1,2}.log`, with the guard's wall time and peak on
      each.
  - **`A`.** Run A as in `.data/mrt-v032-runs.zsh run`, on this branch. Output goes to
    `.data/pd/A`, the log to `.data/pd-A.log`.
  - **`compare`.**
    - `cmp` the four files of `.data/pd/A` against `.data/stream/A`.
    - Diff the summary lines of `.data/mrt-v032-A.log` and `.data/pd-A.log` with the timing fields
      stripped (`in N s`, `wall …`, `of it checks …`, the slowest pair's seconds, `pass N (…):
      DURATION`, `heap in use N MB`).
    - Print pass 1, pass 2, the registry line's load time and peak RSS for both logs.
    - Write all of it to `.data/pd-compare.log`.
  - **`vrps`.** Gzip `.data/realdata/vrps-ntt.20261018.json` into `.data/vrps-ntt.json.gz`. Then
    run `ROUTECHECK_BENCH_VRPS=… go test -run '^$' -bench BenchmarkReadVRPs -count 3 ./internal/cli`
    under the guard, and log to `.data/pd-vrps.log`.

- [ ] **Step 2: Ask the user**, then run the steps one at a time, alone, in this order: `bins`,
  `vrps`, `cmd`, `A`, `compare`. Expected:
  - every guard log ends `SUCCESS`;
  - `compare` prints `identical` for all four files, and an empty diff of the stripped summary
    lines.

  If a file differs: stop. That is a bug to root-cause, not a figure to report.

- [ ] **Step 3: Decide per kind** (design decision 7), from the logs:
  - **MRT:** after's pass 1 + pass 2 against before's (41.637 s + 92.456 s, `.data/mrt-v032-A.log`).
  - **RPSL:** the mean wall time of the two `cmd` after-runs against the two before-runs.
  - **VRPs:** `workers=default` against `workers=0` in `.data/pd-vrps.log`.

  A kind whose after is not lower goes into `serialKinds`. Task 3's `decompressFile` caller for that
  kind also passes `Workers: 0`. Then:
  - add a `decompress_test.go` assertion that `workersFor(k) == 0` for it;
  - rerun the affected measurement (run A for MRT, `cmd` for RPSL), with logs suffixed `-serial`;
  - commit `cli: read <kind> serially, measured slower in parallel`.

  If every kind is faster, there is nothing to commit in this step.

- [ ] **Step 4: Run check.sh.**
  Run `GOWORK=off GOMAXPROCS=4 FUZZTIME=15s scripts/check.sh` under the guard (3,600 s), to
  `.data/check-parallel-decompress.log`. Expected: `check: ok`, exit 0.

- [ ] **Step 5: Docs.**
  - **`docs/routecheck.md:32-33`.** Inputs are read through `mrt.DecompressWith`, with `min(4,
    GOMAXPROCS)` workers (none when GOMAXPROCS is 1), one file at a time. Name the kinds read
    serially, if any. Give mrt's documented bound: about 216.7 MB held live at 4 workers for a
    hostile bzip2 input.
  - **`CHANGELOG.md` Unreleased, `### Changed`:**
    - the change;
    - the figures from Step 3, each before → after with its log;
    - the peak RSS;
    - each kind's decision;
    - the cancellation note from design decision 5: a cancel during a compressed dump now stops
      the load, but not during an uncompressed one;
    - that `cmd`'s figure is the whole run's wall time;
    - "not measured" for anything that was not.
  - **`CLAUDE.md`.** Update the Commands → Real data figures that changed (run A's time and peak),
    with the log.

- [ ] **Step 6: Commit.**
  ```bash
  git add CHANGELOG.md docs/routecheck.md CLAUDE.md
  git commit -m "docs: parallel decompression, measured"
  ```
