# Parallel decompression of inputs — design

Status: draft, 2026-10-21, revised after the builder check. routecheck v0.7.0 requires mrt v0.3.2;
`mrt.DecompressWith` has been in mrt since v0.3.0.

## Intent

routecheck reads every compressed input with the serial `mrt.Decompress`. mrt v0.3.0 added
`mrt.DecompressWith(r, DecompressOptions{Workers, Context})`:

- a bzip2 input is decoded block by block on `Workers` goroutines;
- a gzip input is decompressed one goroutine ahead of the reader.

The bytes it yields are the same as `Decompress`'s, and so is the error where `Decompress` fails
(mrt's doc comment on `DecompressWith`). mrt measured it with `Workers: 4`, `GOMAXPROCS=4`, in its
CHANGELOG under 0.3.0:

- route-views2 RIB (bzip2), decompress plus `Routes`: 22.95 s down to 6.09 s;
- RIS rrc00 bview (gzip): 13.94 s down to 9.51 s.

A caller that only copies the bytes reads gzip slower, though: 5.68 s against 6.81 s (0.83×). mrt's
v0.3.2 fix narrowed that gap to 0.93×. routecheck's dumps go through `rpsl.Parse`, which does more
per byte than a copy, so whether gzip dumps get faster is an open question that the measurement
answers.

routecheck spends much of its real-data time reading those two RIBs. The 60-pair run A with mrt v0.3.2
(`.data/mrt-v032-A.log`) took 4m41s wall. Of that:

- pass 1, ASes on paths over both RIBs: 41.637 s;
- pass 2, filtering them to 55 files: 1m32.456 s;
- the checks, which read the filtered, uncompressed files: 1m35s.

How much of the two passes is decompression is **not measured**. This change measures it.

A user of the command reads the same kind of files with `-collector`, plus gzip IRR dumps with `-dump`.

## Goals

1. The command (`internal/cli`) reads its compressed inputs through `DecompressWith`:
   - the MRT inputs of `-session` and `-collector`;
   - the RPSL files of `-dump` and `-policy` (both go through `readRPSL`);
   - `-vrps`.

   Each kind is kept only where it is measured no slower (decision 7).
2. The output does not change. The goldens are unchanged, and real-data run A's output files are
   byte-identical to `.data/stream/A`.
3. The speedup is measured, not assumed:
   - pass 1, pass 2 and the registry load of run A, before and after, with peak RSS;
   - the command's dump loading, before and after.
4. Stopping early releases what `DecompressWith` started. This covers an error, the caller ending
   the iteration, and SIGINT/SIGTERM.

## Non-goals

- **The library API.** `Checker.Check` and `CheckEach` take an `iter.Seq2[mrt.Record, error]`, and
  the caller decompresses. Nothing in `.`, `observe`, `verdict`, `pathre` or `hygiene` changes. Their
  "no goroutines they don't own" rule (CLAUDE.md principle 2) stays as it is.
- **The rest of mrt v0.2's API.** `mrt.RoutesWith`, `bgp.Interner` and `Route.Originated` are not
  adopted.
- **Reading several files at once.** Inputs stay one after another, one descriptor at a time
  (`records` in `internal/cli/load.go`).
- **A release.** Whether this ships as v0.7.1 is decided after it merges.

## Anti-goals (a failure even if it works)

- Any difference in a verdict, count, golden or real-data output file.
- A cancelled or failed run that no longer looks like one. Today an interrupted run exits 3 with
  empty stdout (R29, exit status 3).
- Goroutines or buffers still live after a file is done or the reading stops. mrt's contract: "A
  caller that stops reading before then must cancel Context".
- A real-data peak that crosses the 8 GB guard. Run A peaked at 6,139 MB with mrt v0.3.2.

## Decisions

Each decision below is marked either as one the user made or as my call.

1. **Scope** (user): the mrt v0.3.2 `DecompressWith` route, design first.
2. **Where** (my call): every `mrt.Decompress` call in the module goes through `DecompressWith`:
   - the CLI's three: `readInput`, `readVRPs` and `readRPSL`, at load.go:61, 84 and 383.
     `readRPSL` serves both `-dump` (load.go:161) and `-policy` (`readDraft`, load.go:290).
   - the real-data test's two: the dump loader at realdata_test.go:957 and `readMRT` at 1095;
   - missingsets_test.go:779.

   The tests then read the way the command does, and run A measures the command's code path for
   MRT.
3. **Workers** (my call): `min(4, runtime.GOMAXPROCS(0))`, and 0 when that is 1. `Workers: 0` is
   exactly `Decompress`.
   - There is no new flag. `GOMAXPROCS` is the user's control.
   - 4 is the figure mrt measured and bounded. mrt documents about 216.7 MB held live at 4 workers
     for a hostile bzip2 input, and 389.0 MB at 14.
   - Inputs are read one at a time, so at most one such reader is live.
4. **Context** (my call):
   - Each file gets its own `context.WithCancel` from the run's context.
   - None of the readers takes a ctx today, so `Run`'s ctx has to be passed down through four
     signatures: `records` (load.go:43, with `readInput`), `readVRPs` (load.go:78, called at
     cli.go:138), `readRPSL` (load.go:377) and `readDraft` (load.go:287). `loadPolicy` already has
     one (load.go:143).
   - It is cancelled when that file's reading ends, by EOF, an error or an early stop. A `defer`
     beside the file's `Close` does it.
   - A cancel of the run's ctx (SIGINT) reaches the decompressor too. The `Read` then returns
     `context.Canceled`. mrt's `Records` wraps a reader error with `%w` ("mrt: reading record at
     offset N: …"), so `errors.Is(err, context.Canceled)` still holds.
5. **Cancellation** (my call). A run cancelled while a compressed input is being read ends as an
   interrupted run does now: exit 3, empty stdout, and "context canceled" on stderr. That is what the
   existing `TestCancelled` (cli_test.go:509) checks.
   - For MRT inputs, the error also satisfies `errors.Is(…, context.Canceled)`. The cancel can come
     first from the decompressor's read or from `Check`'s every-4096-records check.
   - For RPSL files it cannot. `rpsl.Parse` reports a read error as a `Diagnostic` that holds only a
     message string, and `readRPSL` formats it with `%s`. The message still carries "context
     canceled". Making the cause typed would mean changing rpsl, which is out of scope.
   - One behaviour changes. Today a SIGINT during the registry load does not stop the load; the
     cancel is noticed only once `CheckEach` runs. With the ctx passed down, a cancel during a
     compressed dump stops the load at the next read. A cancel during an uncompressed dump still
     takes effect only at `CheckEach`, because `Workers: 0` and raw input take no ctx. The
     CHANGELOG says so.
6. **Memory settings** (my call). The after-run keeps the before-run's settings exactly, including
   `GOMEMLIMIT=6GiB`, so the two are comparable. Run A peaked at 6,139 MB, at that soft limit, so
   the after-run may collect garbage harder while a decompressor is live. That cost is part of what a
   user with the same limit sees. The comparison reports the peak RSS beside the timings and names
   the possible GC effect, without correcting for it.
7. **Per-kind fallback** (my call). The helper takes the worker count per call.
   - If a kind of input measures slower with `DecompressWith`, that kind goes back to `Workers: 0`
     (exactly `Decompress`). The kinds are MRT, RPSL dumps and VRPs; the -dump timing is the likely
     case.
   - The CHANGELOG records the figure behind each choice.
   - All-or-nothing is not required.
8. **Docs:**
   - docs/routecheck.md's input paragraph (lines 32–33) names `mrt.DecompressWith`, the worker
     count, and mrt's memory bound.
   - The CHANGELOG gets an Unreleased entry with the measured figures.
   - CLAUDE.md gets one line under Commands or Heavy runs, with the new real-data figures.

## Tests (what must hold)

- **Equivalence.** For each compressed file under `testdata/` (gzip and bzip2: at least
  `testdata/mrt/rv2-rib.20261015.1200.gz`), the CLI's reader yields the same records, and the same
  final error, as `mrt.Records(mrt.Decompress(f))`.
  - The testdata has no bzip2 MRT file. Neither has mrt's: its bzip2 fixtures are not MRT, and Go's
    standard library has no bzip2 encoder.
  - My call: commit `testdata/mrt/rv2-rib.20261015.1200.bz2`, the same bytes as the gzip fixture,
    recompressed with the `bzip2` tool. `testdata/README.md` records the command and both files'
    sha256 of the decompressed bytes.
  - To reach the parallel path at all, the test sets `Workers` above 0 directly. The fixture is
    small, possibly a single bzip2 block.
- **Early stop.** Stopping the iteration after the first record of a compressed input ends the
  goroutines `DecompressWith` started. The test checks this by polling `runtime.NumGoroutine` back to
  its baseline, with a bounded wait.
- **Cancel.** Cancelling `Run`'s ctx while a compressed input is being read gives exit 3, empty
  stdout and "context canceled" on stderr, for an MRT input and for a gzip dump (decision 5).
  - For the MRT input, the error returned through `CheckEach` also satisfies `errors.Is`.
  - The test cancels after reading has started, not before `Run`, so it reaches the decompressor's
    read. It uses the `openInput` hook or a reader that cancels after N bytes; builder's choice.
- **Goldens.** `go test ./internal/cli` passes without `ROUTECHECK_GOLDEN_UPDATE`.
- **check.sh.** `FUZZTIME=15s scripts/check.sh` ends `check: ok`, with `-race`.

## Measurement (real data)

- **Before.** `.data/mrt-v032-A.log`, made at e818f21 with mrt v0.3.2 and serial decompression:
  - pass 1: 41.637 s;
  - pass 2: 1m32.456 s;
  - wall: 4m41s;
  - peak RSS: 6,139 MB.

  The registry load's time is on the log's `registry:` line. Read it from there, do not restate it
  from memory.
- **After.** Run A again, alone, under the 8 GB guard, with the same settings as
  `.data/mrt-v032-runs.zsh run`. Its peak may pass the 6,144 MB threshold, so ask before running it.
  Compare:
  - the four output files with `.data/stream/A`: they must be byte-identical;
  - the summary lines, after removing the timing fields (`in N s`, `wall`, `of it checks`, the
    slowest pair's time, `pass N (…): DURATION`, `heap in use`): they must be identical. A plain md5
    of the lines differs even between two runs of the same code (`.data/mrt-v032-compare.log`);
    diffing with the timings stripped showed only timings differing;
  - pass 1, pass 2, the registry load and peak RSS: report each as before → after.
- **The command's dump path** (my call). Time the command run in `.data/stream-runs.zsh` `cmd`,
  before and after. That is pair 2 over every `-dump` file, with the uncompressed
  `filtered/AS6762.mrt` as `-collector`.
  - This times the gzip dump loading and nothing of MRT decompression. Run A's passes already cover
    the MRT path through the same helper.
  - It peaked at 5,959 MB before (`.data/stream-cli-2097152.log`).
  - Run it alone, under the guard, and name the logs. Ask before running, together with run A.
  - The command prints no load time of its own. Compare wall time from the guard's log, and say in
    the CHANGELOG that the figure is the whole run's.
- If a figure is not measured, the CHANGELOG says so.

## Left to the builder

- The helper's name and shape, and whether it lives in `internal/cli` alone or also gets a test
  copy in the root package. The root package's tests may import `internal/cli`.
- Test names, and how the equivalence test gets a bzip2 file.
- The exact wording of the docs.
