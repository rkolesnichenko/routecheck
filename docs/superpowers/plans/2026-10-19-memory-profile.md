# Memory Profile (phase 1) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Profile the four big runs and write the phase-1 findings as an addendum to the design, for the
maintainer's checkpoint. Phase 2 (the reductions) gets its own plan after the checkpoint.

**Architecture:**
- **The sampler.** A test-support package, `internal/memprof`, holds a sampler. It writes a `MemStats` time series,
  plus a heap profile at each new high and at each named mark (a mark forces a GC, so it also measures the live
  heap).
- **Who uses it.** The real-data test uses it behind one new environment variable, and marks the load, each pair
  and each report; reports are marked by a test-only wrapper around the `PolicySource`. A new opt-in test in
  `internal/cli` uses it to run the command in-process through `Run`, unchanged.
- **The runs.** The controller runs the four profiled runs under the guard and attributes the heap with
  `go tool pprof`.

**Tech Stack:** Go 1.23, `runtime`, `runtime/pprof`, `go tool pprof`; rpsl v0.30.0.

**Spec:** `docs/superpowers/specs/2026-10-19-memory-profile-design.md`

## Global Constraints

- **Results never change.** With profiling off, the tests behave exactly as before. With profiling on, every
  verdict and output byte is the same; only memory and time figures may differ.
- **No profiling in the shipped command.** `go list -deps ./cmd/routecheck` must not list `internal/memprof`, and
  no flag, environment variable or hook is added to library or command code.
- **The guard:** `MEMGUARD_NORMAL_PRIORITY=1 ../rpsl/.superpowers/sdd/tools/memguard.sh 8 TIMEOUT env GOWORK=off GOMAXPROCS=4 GOMEMLIMIT=6GiB …`.
  - The cap is 8 GB and is never raised.
  - One heavy run at a time, never beside check.sh.
  - No network.
- **Units:** the guard's "MB" is MiB, and every figure states the unit it uses. The targets are RSS from the guard.
- **Owners:** heap is attributed to these owners, in this order (design, Goals 1):
  1. registry;
  2. set expansion;
  3. caches;
  4. observations;
  5. reports and verdicts held for output;
  6. other (anything over 5% of the peak is named);
  7. GC headroom (RSS minus live heap).
- **No local paths:** none of the user's home-directory paths in anything committed or pushed.
- **Figures:** every figure comes from a command run, and names its log.
- **check.sh:** `scripts/check.sh` passes, run under the guard.

## Review Focus

1. **Profiling unset.** No sampler goroutine, no files and no forced GC; the run is unchanged. Task 2's
   `TestMarksAreNoOpsWhenOff` pins it.
2. **A sampler stopped twice, or never started.** `Stop` is idempotent; a nil `*Sampler` is valid and all its
   methods are no-ops. Task 1's `TestSamplerNilAndDoubleStop` pins it.
3. **Profile flooding on a slowly rising heap.** A new-high profile is written only when the heap is at least 5% above
   the last profiled high, and at most once per 5 s. Task 1's `TestPeakProfilesAreRateLimited` pins it.
4. **A run the guard kills mid-way.** The time series is flushed after every line, so it survives SIGKILL up to the
   last second. Task 1's `TestSeriesFlushedPerLine` pins it.
5. **The shipped binary pulling in the package.** Task 1's `TestNotInCommand` runs
   `go list -deps ./cmd/routecheck` and fails on `internal/memprof`.

---

### Task 1: internal/memprof, the sampler

**Files:**
- Create: `internal/memprof/memprof.go`
- Test: `internal/memprof/memprof_test.go`

**Interfaces:**
- Produces:
  - `memprof.Start(dir string, every time.Duration) (*Sampler, error)`
    - It creates `dir` and writes `dir/series.tsv`, with the header
      `t_ms\theap_inuse\theap_alloc\tsys\tnext_gc\tnum_gc\tmark` (bytes).
    - It samples `runtime.ReadMemStats` every `every`.
    - When `HeapInuse` is ≥ 1.05 × the last profiled high and ≥ 5 s have passed since the last such profile, it
      writes `dir/peak-NNN.pb.gz` (NNN counts up from 001).
  - `(*Sampler) Mark(label string) (live uint64)`
    - It runs `runtime.GC()` and reads `HeapAlloc`, the live heap.
    - It writes `dir/mark-NNN-<label>.pb.gz`, where the label is sanitized to `[A-Za-z0-9._-]`.
    - It appends a series line whose `mark` column is the label, and returns the live bytes.
  - `(*Sampler) Stop() error`: stops the goroutine, writes `dir/final.pb.gz`, and closes the files. It is idempotent.
  - A nil `*Sampler`'s methods do nothing and return zero values.
  - Profiles are `pprof.Lookup("heap").WriteTo(f, 0)`.
  - The package comment says it is test support and must not be imported by the command.

- [ ] **Step 1: Write the failing tests:**
  - `TestSamplerWritesSeriesAndMarks`: start with `every = 10ms`, allocate and hold 64 MiB, then call `Mark("after alloc")`.
    - The returned live heap is ≥ 64 MiB.
    - `series.tsv` has the header and ≥ 2 lines, one with mark `after alloc`.
    - `mark-001-after_alloc.pb.gz` exists, and so does `final.pb.gz` after `Stop`.
  - `TestPeakProfilesAreRateLimited`: grow the held heap in 10 steps of 8 MiB within 1 s, at `every = 10ms`.
    Exactly one `peak-*.pb.gz` is written.
  - `TestSeriesFlushedPerLine`: while running, the file's size grows without `Stop`.
  - `TestSamplerNilAndDoubleStop`: on a nil `*Sampler`, `Mark` returns 0 and `Stop` returns nil. `Stop` twice on a
    live sampler returns nil.
  - `TestNotInCommand`: `go list -deps ./cmd/routecheck`, run from the module root, has no line ending in
    `/internal/memprof`.
- [ ] **Step 2: Run** `GOWORK=off go test -count=1 ./internal/memprof`. Expected: FAIL (undefined).
- [ ] **Step 3: Implement** per the Interfaces.
- [ ] **Step 4: Run** the same command under `-race`, then `scripts/check.sh` under the guard (log `.data/check-memprof-t1.log`). Expected: PASS, then `SUCCESS`.
- [ ] **Step 5: Commit**: `memprof: a test-support heap sampler (series, peak and mark profiles)`.

### Task 2: the real-data test profiles behind ROUTECHECK_REALDATA_MEMPROF

**Files:**
- Modify: `realdata_test.go` (`TestRealData`, `checkPair`, the env table near line 101)
- Test: `realdata_test.go`, or a new `memprof_realdata_test.go` for the unit tests
- Modify: docs/routecheck.md, the real-data section listing the `ROUTECHECK_REALDATA_*` variables, and CLAUDE.md's
  Commands, if they list them

**Interfaces:**
- Consumes: Task 1's `Start`, `Mark` and `Stop`.
- Produces:
  - `ROUTECHECK_REALDATA_MEMPROF=DIR`. When set, `TestRealData` calls `memprof.Start(DIR, time.Second)` before
    loading and `Stop` at the end (deferred, so also on failure). Marks:
    - `load` after the registry load;
    - `pair-<i>-start` and `pair-<i>-end` around each pair (i as in `ROUTECHECK_REALDATA_PAIRS`);
    - a report mark from the wrapper below.
  - `markingSource{resolve.PolicySource; s *memprof.Sampler; pair int; n int}` wraps the `PolicySource` handed to
    `peval.Evaluator` in `checkPair`.
    - Its `AutNum` calls `s.Mark(fmt.Sprintf("pair-%d-autnum-%d-%s", pair, n, as))` before delegating, and
      increments n.
    - Every other method delegates unchanged (embedding).
    - `checkPair` gains a `prof *memprof.Sampler` parameter. When it is nil, the Evaluator gets `reg.src` itself,
      not a wrapper.
  - The run log gains one line per mark: `MEMPROF: <label> live <MiB> MiB` (from Mark's return).

- [ ] **Step 1: Write the failing tests:**
  - `TestMarkingSourceDelegates`: over a tiny Corpus, `markingSource.AutNum` returns what the inner source returns,
    calls `Mark` once per call (counted through a sampler on `t.TempDir()`, by the mark files written), and leaves
    the sets' answers unchanged.
  - `TestMarksAreNoOpsWhenOff`: with a nil sampler, `checkPair` gets an Evaluator whose `Src` is `reg.src` itself.
    Assert this by a small seam: a function `policySourceFor(reg, prof, pair) resolve.PolicySource` returns `reg.src`
    for a nil prof.
- [ ] **Step 2: Run** `GOWORK=off go test -count=1 -run 'TestMarkingSourceDelegates|TestMarksAreNoOpsWhenOff' .`. Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** the focused tests, then `scripts/check.sh` under the guard (log `.data/check-memprof-t2.log`). Expected: PASS, then `SUCCESS`.
- [ ] **Step 5: Commit**: `realdata: heap profiles and per-report marks (ROUTECHECK_REALDATA_MEMPROF)`.

### Task 3: TestMemProfileCommand, the command in-process

**Files:**
- Create: `internal/cli/memprof_test.go`

**Interfaces:**
- Consumes: Task 1.
- Produces: `TestMemProfileCommand`, which is opt-in.
  - It skips unless `ROUTECHECK_MEMPROF_OUT=DIR` and `ROUTECHECK_MEMPROF_ARGS` are set. The args are separated by
    spaces; paths hold no spaces, and a test fails on an empty arg.
  - It starts a sampler on DIR at 1 s and calls `Run(context.Background(), args, stdout, stderr)`, with stdout and
    stderr written to `DIR/stdout.txt` and `DIR/stderr.txt`.
  - After `Run` it calls `Mark("after-run")`, then `Stop`.
  - It logs `exit <code>` and the mark's live heap. It does not fail on exit 1, since rejected routes are a result.
    Exit 2 or 3 fails the test.

- [ ] **Step 1: Write the test** and a tiny companion `TestMemProfileCommandSmoke`, which is not opt-in. It runs
  the golden session (the same arguments as `TestGoldens`' session case) through the same helper, on `t.TempDir()`,
  and asserts:
  - `stdout.txt` equals `testdata/golden/session.txt`;
  - `series.tsv` and `final.pb.gz` exist.
- [ ] **Step 2: Run** `GOWORK=off go test -count=1 -run 'TestMemProfileCommand' ./internal/cli`. Expected: the smoke test FAILs before the helper exists, and the opt-in test SKIPs.
- [ ] **Step 3: Implement** the shared helper `runProfiled(t *testing.T, dir string, args []string) int` in the same file.
- [ ] **Step 4: Run** the same command, then `scripts/check.sh` under the guard (log `.data/check-memprof-t3.log`). Expected: PASS, then `SUCCESS`.
- [ ] **Step 5: Commit**: `cli: TestMemProfileCommand profiles the command in-process (opt-in)`.

### Task 4: the four runs and the addendum (controller)

**Files:**
- Modify: `docs/superpowers/specs/2026-10-19-memory-profile-design.md` (new section `## Addendum: phase 1 findings`)
- Create: `.data/memprof-runs.zsh` (not committed)

- [ ] **Step 1: Run each of the four, one at a time, under the guard.** Each run gets its own DIR under
  `.data/memprof/` and its own log `.data/memprof-<name>.log`.
  - **cmd**: `TestMemProfileCommand` with the args of `.data/max-prefixes-cli-runs.zsh` at `-max-prefixes 2097152`.
    Guard timeout 1800.
  - **A2, R2, V2**: `TestRealData` with `ROUTECHECK_REALDATA_PAIRS=2`, `ROUTECHECK_REALDATA_MAX_PREFIXES=2097152`
    and `ROUTECHECK_REALDATA_OUT`, plus R's or V's variables as in `.data/provenance-shards.zsh`. Guard timeout 6000.
  - Expected: cmd and A2 complete; R2 and V2 may be stopped by the guard (MEMLIMIT). Their series and the profiles
    written before the stop are the findings.
- [ ] **Step 2: Results unchanged.**
  - cmd's `stdout.txt`, report lines and route lists equal `.data/verified-counts-2097152.log`'s, apart from timing
    and memory lines.
  - A2's TOTALS equal pair 2's in `.data/provenance-A.log`, or, if that log has no per-pair TOTALS, its pair-2
    report lines.
  - If anything differs, stop and investigate before writing findings.
- [ ] **Step 3: Attribute.** For each run, take:
  - the highest peak profile;
  - the mark nearest before the peak (live heap);
  - for R2 and V2, the last profile before the stop.

  Read each with `go tool pprof -sample_index=inuse_space -top -cum`, and with `-focus` for each owner:

  | owner | `-focus` regexp |
  |---|---|
  | registry | `resolve\.\(\*Corpus\)\|buildMemSource\|resolve\.\(\*MemSource\)\|rpsl\.Parse\|rpsl\.Decode` |
  | set expansion | `resolve\.\(\*Expander\)\|resolve\..*[Ee]xpand\|PrefixRange\|peval\..*[Nn]ormal` |
  | caches | `resolve\.\(\*Cache\)\|FilterMemo` |
  | observations | `observe\.\|mrt\.\|bgp\.` |
  | reports and verdicts | `routecheck\.\(\*famRun\)\|routecheck\.\(\*Checker\)\.Check\|verdict\.` |

  Overlaps are resolved by the first matching row. The remainder is "other" (named when over 5%), and GC headroom is
  RSS minus live heap.
- [ ] **Step 4: Answer the R/V question.**
  - From the `MEMPROF:` lines, find which report's mark comes before the largest rise, in A2, R2 and V2.
  - From that report's expansion: which set, and how many prefixes in each run (the run log's unevaluable lines name
    the sets over the limit in A2).
- [ ] **Step 5: Write the addendum.** For each run:
  - the peak RSS, the live heap, and the owner table;
  - the time series' shape: one spike or a climb.

  Then:
  - the R/V answer;
  - the candidate reductions, each with its estimated saving, where it lives (routecheck or rpsl), and its risk;
  - for each target, whether it looks reachable, and a recommendation (including "stop" if the peak is inherent).

  Every figure names its file under `.data/memprof/` or its log.
- [ ] **Step 6: Commit** `docs: memory profile, phase 1 findings` and hand the addendum to the maintainer. **Stop here: phase 2 waits for the maintainer's choice.**
