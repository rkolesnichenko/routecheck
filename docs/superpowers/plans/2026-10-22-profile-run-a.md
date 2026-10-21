# Profile run A Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** One CPU-profiled run A on the current code, with every phase labelled and its CPU, GC and wall time
logged, and a findings section naming what the profile supports as the next target.

**Architecture:** Test code only. A small `phaseClock` in a new test file wraps each phase in `pprof.Do` with a
`phase` label and reads the kernel's CPU (`getrusage`) and the runtime's GC counters around it. `TestRealData` and
`checkPair` use it. The run itself is `go test -cpuprofile` under the memory guard, analysed offline with
`go tool pprof`.

**Tech Stack:** Go 1.23 floor; `runtime/pprof` (`Do`, `Labels`, `Label`), `runtime/metrics`, `syscall.Getrusage`;
`go tool pprof`; zsh for the run script.

**Spec:** `docs/superpowers/specs/2026-10-21-profile-run-a-design.md` (decision 5 revised after approval in c230247,
the `pairs` label added in 341c3fb).

## Global Constraints

- Test code and docs only. No library package, `internal/cli` or `api/` file changes.
- Go 1.23 floor. CI is Linux only, development is macOS: `syscall.Getrusage` builds on both. Convert a
  `syscall.Timeval` with its `Nano()` method (darwin's `Usec` is `int32`, Linux's `int64`).
- The phase names, exactly: `load`, `vrps`, `pass1`, `pass2`, `pairs`, `check`, `recount`, `output`, `totals`.
  The per-pair label key is `pair`, its value the 1-based pair index as `strconv.Itoa`.
- Log line formats, exactly (seconds, three decimals):
  - `CPU: <phase> user %.3fs sys %.3fs wall %.3fs`
  - `GC: <phase> %.3fs over %d cycles`
  - `GC: run %.3fs over %d cycles`
- No `runtime.GC()` is forced anywhere in `TestRealData`.
- None of the new lines may match the run comparison's pattern
  `TOTALS|pass [12] |registry:|VRPs:|routes from|limits:|PAIRS:`.
- Heavy runs: one at a time, under `MEMGUARD_NORMAL_PRIORITY=1 ../rpsl/.superpowers/sdd/tools/memguard.sh 8`, with
  `GOWORK=off GOMAXPROCS=4 GOMEMLIMIT=6GiB`, never beside check.sh. Run A needs the user's go-ahead (last peak
  6,311 MB, over the 6,144 MB threshold).
- Every figure in docs comes from a command run on this branch, with its log named; otherwise "not measured".
- No `/Users/...` path in any committed file or commit message.

## Review Focus

1. **The pair label lost inside `checkPair`.** `pprof.Do` sets the goroutine's labels to the *ctx's* labels plus
   the new ones, and restores the ctx's on return. A span given a ctx without the pair label would drop it, and on
   return leave the goroutine with only that ctx's labels. Pinned by `TestPhaseClockLabels` (the pair survives
   inside the span, and `phase` is back to `pairs` after it), and by `checkPair` taking the labelled ctx.
2. **Sixty pairs' spans of one name overwriting instead of summing.** Pinned by `TestPhaseClockCPU` (two spans of
   one name give one line whose wall covers both).
3. **`TestPairSpool`'s call of `checkPair`, which has no clock.** A nil `*phaseClock` must run `fn` unchanged.
   Pinned by the nil case in `TestPhaseClockLabels` and by `TestPairSpool` still passing.
4. **New log lines leaking into the run comparison.** Pinned by `TestPhaseClockLines` (no line matches the
   comparison's pattern, for the real phase names).
5. **`go test -cpuprofile` leaving its `routecheck.test` binary in the repository root.** The run script passes
   `-o`; Task 3 checks `git status --porcelain` is empty after the run.

---

### Task 1: The phase clock

**Files:**
- Create: `realdata_phase_test.go` (package `routecheck_test`): the helpers and their tests.

**Interfaces:**
- Produces:
  - `type phaseClock struct` (unexported fields: per-name CPU and wall sums, per-top-phase GC deltas, names in
    first-seen order).
  - `func newPhaseClock() *phaseClock`
  - `func (c *phaseClock) top(ctx context.Context, name string, fn func(context.Context))`: runs `fn` under
    `pprof.Do(ctx, pprof.Labels("phase", name), …)`; adds the getrusage user and sys delta and the wall time to
    `name`, and the GC delta (`/cpu/classes/gc/total:cpu-seconds`, `/gc/cycles/total:gc-cycles`) to `name`.
  - `func (c *phaseClock) span(ctx context.Context, name string, fn func(context.Context))`: the same labels and
    CPU and wall sums, no GC reading. A nil `c` calls `fn(ctx)` and nothing else.
  - `func (c *phaseClock) lines() []string`: the `CPU:` lines for every name in first-seen order, then the `GC:`
    lines for every `top` name in first-seen order, then one `GC: run` line read at the call (the process's whole
    `/cpu/classes/gc/total` and `/gc/cycles/total` so far).
  - A name's place in the order is fixed when its first `top` or `span` *starts*, so `pairs` comes before the
    spans inside it.
  - A name used with both `top` and `span` is not supported; nothing needs it.

- [ ] **Step 1: Write the failing tests** in `realdata_phase_test.go`:
  - `TestPhaseClockLabels`: `c.top(ctx, "pairs", …)`; inside it `pprof.Do(ctx, pprof.Labels("pair", "2"), …)`;
    inside that `c.span(ctx, "check", …)`. Inside the span, `pprof.Label(ctx, "phase")` is `"check"` and
    `pprof.Label(ctx, "pair")` is `"2"`. After the span, inside the pair's `Do`, `phase` is `"pairs"` and `pair` is
    `"2"`. Then `(*phaseClock)(nil).span(context.Background(), "check", fn)` calls `fn` exactly once, and
    `pprof.Label` of the ctx it gets has no `phase`.
  - `TestPhaseClockCPU`: two `c.span(ctx, "spin", …)` calls, each a busy loop of 150 ms wall (loop on
    `time.Since`, no sleep). `c.lines()` has exactly one line starting `CPU: spin `, matching
    `^CPU: spin user (\d+\.\d{3})s sys (\d+\.\d{3})s wall (\d+\.\d{3})s$`, with wall ≥ 0.300 and user + sys ≥ 0.150
    (half the busy time, so `-race` and a loaded machine still pass).
  - `TestPhaseClockGC`: `c.top(ctx, "x", …)` calling `runtime.GC()` twice. `c.lines()` is, in order: one line
    matching `^CPU: x user `, one matching `^GC: x \d+\.\d{3}s over (\d+) cycles$` with the count ≥ 2, and a last
    one matching `^GC: run \d+\.\d{3}s over \d+ cycles$`.
  - `TestPhaseClockLines`: a clock with `top` for `load`, `vrps`, `pass1`, `pass2`, `pairs`, `totals` and, inside
    `pairs`, `span` for `check`, `recount`, `output`, each with an empty `fn`. `lines()` has 9 `CPU:` lines in
    exactly that order (load, vrps, pass1, pass2, pairs, check, recount, output, totals), 6 `GC:` phase lines, the
    `GC: run` line, and no line matches `TOTALS|pass [12] |registry:|VRPs:|routes from|limits:|PAIRS:`.

- [ ] **Step 2: Run them to see them fail**

Run (from the repository root): `GOWORK=off go test -count=1 -run 'TestPhaseClock' .`
Expected: build failure, `undefined: newPhaseClock`.

- [ ] **Step 3: Implement the clock** in `realdata_phase_test.go`, with the signatures above.
  - CPU: `syscall.Getrusage(syscall.RUSAGE_SELF, &ru)`, `time.Duration(ru.Utime.Nano())` and the same for `Stime`.
    A `Getrusage` error panics (it cannot fail with these arguments).
  - GC: one `metrics.Read` of the two names; the cycles value is `Uint64`, the CPU value `Float64` seconds.
  - A doc comment on `phaseClock` saying what the design's decision 5 says: process-wide CPU from the kernel, GC
    lagging by at most one cycle per reading, no GC split among spans.

- [ ] **Step 4: Run them to see them pass, with the race detector**

Run: `GOWORK=off go test -race -count=3 -run 'TestPhaseClock' .`
Expected: `ok`.

- [ ] **Step 5: Commit**

```bash
git add realdata_phase_test.go
git commit -m "test: a phase clock for the real-data run (labels, getrusage, GC)"
```

### Task 2: Label and time every phase of TestRealData

**Files:**
- Modify: `realdata_test.go`: `TestRealData` (lines 173–344, and its doc comment), `checkPair` (1525–1605).
- Modify: `realdata_spool_test.go:138` (the other `checkPair` caller).

**Interfaces:**
- Consumes: Task 1's `newPhaseClock`, `top`, `span`, `lines`.
- Produces: `func checkPair(ctx context.Context, tb testing.TB, clock *phaseClock, reg *irrRegistry, …the rest unchanged…) pairResult`.

- [ ] **Step 1: Give `checkPair` the labelled ctx and the clock.**
  - New leading parameters `ctx context.Context, tb testing.TB, clock *phaseClock`; the timeout context derives from
    `ctx` (`context.WithTimeout(ctx, timeout)`) instead of `context.Background()`.
  - `clock.span(ctx, "check", …)` wraps exactly the span `r.elapsed` times today: from `start := time.Now()` through
    `r.elapsed = time.Since(start)`. That includes the `summarize` callback and the per-route spool writes; the
    profile's split tells routecheck's library from the test's own `summarize`.
  - `clock.span(ctx, "recount", …)` wraps exactly the span `r.countDur` times (the `observe.Collector` re-count).
  - `realdata_spool_test.go:138` passes `context.Background(), t, nil`.
- [ ] **Step 2: Wrap `TestRealData`'s phases**, with `ctx := context.Background()` and `clock := newPhaseClock()`
  before `start`. Variables a later phase reads are declared before the `top` call and assigned inside it.
  - `top(ctx, "load", …)`: from `t0 := time.Now()` (line 210) through the `ROUTECHECK_REALDATA_LOAD_ONLY` block
    (253). The early `return` there becomes: set a flag inside, return from the test after `top` returns. Nothing
    from the clock is logged on that path.
  - `top(ctx, "vrps", …)`: lines 255–262.
  - `top(ctx, "pass1", …)`: lines 264–282 (`countASes` through the `len(pairs) == 0` fatal; `pickPairs` is light
    and stays here).
  - `top(ctx, "pass2", …)`: lines 284–305.
  - `top(ctx, "pairs", …)`: lines 307–337, the selection parse and the loop. Each selected iteration's body runs
    inside `pprof.Do(ctx, pprof.Labels("pair", strconv.Itoa(i+1)), …)`, and its labelled ctx is the one passed to
    `checkPair` and to `clock.span(ctx, "output", …)`, which wraps exactly `out.addPair(&r)` and its error check.
    `continue` for an unselected pair stays outside the `Do`.
  - `top(ctx, "totals", …)`: lines 338–343 (`tot.log` and `out.finish`).
  - After `totals`: `for _, l := range clock.lines() { t.Log(l) }`. The `CPU: output … wall` line is design
    decision 4's output-time line; no other line is added for it.
  - `pprof.Do` sets labels on the goroutine for `fn`'s run, so `loadRegistry`, `countASes`, `filterRIBs` and the
    rest keep their signatures; only `checkPair` needs the ctx, because its spans nest under the pair's labels.
- [ ] **Step 3: Extend `TestRealData`'s doc comment** with one paragraph: each phase runs under a pprof `phase`
  label (the nine names, and `pair` per pair), the test logs the `CPU:` and `GC:` lines after the TOTALS (what they
  measure, the GC lag of at most one cycle), and how to profile: add `-cpuprofile FILE -o BIN` to the command above,
  and `GODEBUG=gctrace=1` to the environment for per-cycle GC lines.
- [ ] **Step 4: Verify**

Run: `GOWORK=off go vet . && GOWORK=off go test -race -count=1 -run 'TestPhaseClock|TestPairSpool' .`
Expected: no vet output, `ok`.
Run: `gofmt -l .`
Expected: no output.

- [ ] **Step 5: Commit**

```bash
git add realdata_test.go realdata_spool_test.go
git commit -m "test: label and time every phase of the real-data run"
```

- [ ] **Step 6 (controller): check.sh under the guard**

Run: `MEMGUARD_NORMAL_PRIORITY=1 ../rpsl/.superpowers/sdd/tools/memguard.sh 8 1800 env GOMAXPROCS=4 scripts/check.sh > .data/check-profile.log 2>&1; echo "exit=$?"`
Expected: exit 0, the log ends `check: ok`. If the guard does not start it (exit 3, not enough memory), retry in a
bounded loop (6 attempts, 60 s apart) ending SUCCESS, FAILURE or TIMEOUT.

### Task 3 (controller): The profiled run

Run by the controller, never by a subagent, and only after the user's go-ahead for run A.

**Files:**
- Create: `.data/profile-runs.zsh` (git-ignored), modelled on `.data/parallel-decompress-runs.zsh`, with steps
  `A | compare | pprof`.

- [ ] **Step 1: Write the script.**
  - `A`: `out=.data/prof/A`, `log=.data/prof-A.log`, `rm -rf .data/prof; mkdir -p $out`; the guard with timeout
    6000; the same environment as `parallel-decompress-runs.zsh A` plus `GODEBUG=gctrace=1`; `go test` with
    `-cpuprofile $PWD/.data/prof/cpu.pprof -o $PWD/.data/prof/routecheck.test`. Print the status and the summary.
  - `compare`: the four output files of `.data/prof/A` against `.data/stream/A` with `cmp`; the summary lines of
    `.data/prof-A.log` against `.data/mrt-v032-A.log` through the same `strip` as `parallel-decompress-runs.zsh`
    (a `diff` to `.data/prof-compare-summary.diff`); everything to `.data/prof-compare.log`.
  - `pprof`, into `.data/prof/`:
    - `go tool pprof -tags .data/prof/cpu.pprof > tags.txt`;
    - for each of the nine phases, `-top -cum -nodecount=15 -tagfocus=phase=^NAME$` to `top-NAME.txt`;
    - the unlabelled share: `-top -nodecount=15 -tagignore=phase=.` to `top-unlabelled.txt`.
- [ ] **Step 2: Run it** (after the user's go-ahead): `zsh .data/profile-runs.zsh A > .data/prof-A.status 2>&1; echo "exit=$?"`, in the background with a bounded wait (the Bash tool's timeout, then a bounded watcher ending SUCCESS,
  FAILURE or TIMEOUT).
  Expected: `ok`, `SUCCESS` from the guard, peak below 8 GB.
- [ ] **Step 3: Check the run.**
  - `zsh .data/profile-runs.zsh compare`: four `identical:` lines and `summary lines: identical with timings
    stripped`. Anything else stops the plan: the labels changed what the run does.
  - `git status --porcelain` is empty.
  - `.data/prof-A.log` has 9 `CPU:` lines, 6 `GC:` phase lines and the `GC: run` line.
- [ ] **Step 4: Check the labels.**
  - `zsh .data/profile-runs.zsh pprof`.
  - `tags.txt` lists all nine phase values and 60 `pair` values.
  - In `top-unlabelled.txt`, every function with 1% or more of the profile's samples is in package `runtime` (GC
    workers, the scavenger, the profiler). If a phase's own code shows up there, a goroutine started outside its
    `pprof.Do`: fix it in Task 2's code and rerun (a new go-ahead, since it is a second heavy run).
  - The sample count of `top-unlabelled.txt` plus the per-phase counts in `tags.txt` equals the profile's total;
    if `-tagignore=phase=.` does not do that, use the per-phase sum from `tags.txt` instead and say so in the
    ledger.
- [ ] **Step 5: Decide on a trace.** For each phase, CPU (user + sys) against wall. A phase whose CPU is under
  half its wall and whose top functions do not explain the wait (no I/O, syscalls or channel waits among them):
  stop and propose one `-trace` run to the user. Otherwise, no trace.

### Task 4 (controller): Findings

**Files:**
- Modify: `CHANGELOG.md` (Unreleased).
- Modify: `CLAUDE.md` (the Real data bullet, around line 297).

- [ ] **Step 1: Write `### Measured, where run A's time goes`** under `## [Unreleased]`:
  - The setting: the date, machine (Apple M3 Max), GOMAXPROCS=4, GOMEMLIMIT=6GiB, the guard, the commit, the
    profiler on at 100 Hz, its own cost not measured, and that this is the first run A of serial-RPSL v0.7.1-era
    code.
  - One table, a row per phase: wall (from `CPU:`), user + sys, GC (with its cycle count), profile samples × 10 ms,
    the top two or three functions with their module (routecheck, rpsl, mrt, runtime, standard library).
  - The GC's share of the whole run (`GC: run` against the summed CPU).
  - The cross-check: where profile samples fall short of user + sys, by how much.
  - Against `.data/pd-A.log`: the differences stated (that run read RPSL in parallel and had no profiler).
  - The targets: the one or two the profile supports, each as a bound ("phase X spends N s CPU in F; removing it
    entirely saves at most M s wall"), and which repository each lives in.
  - What the profile cannot tell.
  - The output check (`.data/prof-compare.log`) and the logs: `.data/prof-A.log`, `.data/prof/`.
- [ ] **Step 2: CLAUDE.md.** Replace the parenthesis "RPSL files were also read in parallel in that run, and the
  final serial-RPSL run A was not measured, see the CHANGELOG" with this run's wall and peak and its log, and add one
  sentence on taking the profile (`-cpuprofile`, `-o`, `GODEBUG=gctrace=1`, the `CPU:`/`GC:` lines, `pprof -tags`).
- [ ] **Step 3: Check and commit.** Every figure in both files appears in a named log; `grep -n '/Users' CHANGELOG.md
  CLAUDE.md` is empty.

```bash
git add CHANGELOG.md CLAUDE.md
git commit -m "docs: where run A's time goes"
```

- [ ] **Step 4: Final review.** An independent reviewer reads the whole branch diff (code changes, so required
  before merging); fix its Critical and Important findings.
