# `-max-prefixes` Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** a `-max-prefixes N` option that raises rpsl's `MaxPrefixes` for the policy evaluation, with its memory
cost measured on real data and published.

**Architecture:** the command parses `-max-prefixes` into its config and builds
`peval.Evaluator{Src: src, Expander: resolve.Expander{MaxPrefixes: cfg.maxPrefixes}}`; 0, which is the absent
option, is rpsl's default. The real-data test reads `ROUTECHECK_REALDATA_MAX_PREFIXES` the same way. The
measurements run under the memory guard. The controller runs them, and the published docs are written from
their logs.

**Tech Stack:** Go 1.23, `flag`, rpsl v0.30.0 (`resolve`, `peval`), the memory guard
(`../rpsl/.superpowers/sdd/tools/memguard.sh`).

**Spec:** `docs/superpowers/specs/2026-10-18-max-prefixes-design.md`

## Global Constraints

- **No changes to:** rpsl (stays v0.30.0), `api/*.txt`, `go.mod`, or the JSON and text formats.
- **The absent option is the zero `Expander`:** exactly v0.3.0's behaviour. The code never writes 1,048,576
  (or `1 << 20`) as its own constant. The usage text may say "rpsl's default".
- **N must be a positive integer.** 0, a negative number (in rpsl a negative limit means *unlimited*) and a
  non-number are command-line errors: exit 2, with stderr naming `-max-prefixes`.
- **No options for `MaxVisited`, `MaxDepth` or `MaxConjuncts`.**
- **Every published figure comes from a log written in this work** and is named with it. A figure not
  measured is unknown.
- **Heavy runs:** one at a time, under the memory guard, 8 GB cap, normal priority (`MEMGUARD_NORMAL_PRIORITY=1`),
  `GOMAXPROCS=4`, `GOMEMLIMIT=6GiB`, never beside check.sh.
- **No local home-directory path in any committed file.** Commit on branch `max-prefixes`, never on `main`.
- **Release** (v0.4.0) is outside this plan. The plan ends at a reviewed branch.

## Review Focus

1. **The option exactly at the size needed:** rpsl fails when the count is *greater than* the limit, so N equal
   to the expansion's size must decide the report. Pinned by Task 1's `TestMaxPrefixesOption` (N = 2 on a
   2-prefix set).
2. **The option absent:** it must not mean 0 = unlimited or a tiny limit, and a set within rpsl's default is
   decided. Pinned by `TestMaxPrefixesOption` (no option: decided; `-max-prefixes 1`: unevaluable).
3. **A negative N:** rpsl would read it as unlimited, the opposite of what was typed. Pinned by
   `TestBadCommandLines` rows.
4. **`-irrd`:** the option must reach the evaluator when the policy comes from a server. Pinned by
   `TestMaxPrefixesOption` case "irrd" over the package's test IRRd (`serve`).
5. **A very large N** (above 2^31): it must parse and decide, with no overflow into a negative limit. Pinned by
   `TestMaxPrefixesOption` case "huge" (`1099511627776`).

---

### Task 1: The `-max-prefixes` option

**Files:**
- Modify: `internal/cli/cli.go`:
  - remove the `expander` variable and its comment (~31-35);
  - add a `config` field (~94-109);
  - add the flag in `parse` (~230-260) and its check after `fs.Visit`;
  - build the `Evaluator` (~150).
- Test: `internal/cli/cli_test.go`:
  - `TestUsage` (~95-103) and `TestBadCommandLines` (~106-148);
  - `TestUnevaluableLimit` (~686-765);
  - a new `TestMaxPrefixesOption`.
- Docs, without figures:
  - `docs/routecheck.md`: the flag table (~40-54) and the `unevaluable` reason row (~188);
  - `CLAUDE.md`: R27 (~192-196);
  - `SECURITY.md`: the "Memory is bounded" bullet (~50);
  - `CHANGELOG.md` `[Unreleased]`: a new `### Added`.

**Interfaces:**
- Produces: `config.maxPrefixes int` (0 = rpsl's default). The flag is named `max-prefixes`. Nothing outside
  `internal/cli` changes.

- [ ] **Step 1: Write the failing tests**
  - **`TestUsage`:** add `"-max-prefixes"` to the `wantContains` list.
  - **`TestBadCommandLines`:** add three rows, each expecting exit 2 and stderr containing `"-max-prefixes"`:
    - `{"zero max-prefixes", session("-max-prefixes", "0"), "-max-prefixes"}`
    - `{"negative max-prefixes", session("-max-prefixes", "-5"), "-max-prefixes"}`
    - `{"non-number max-prefixes", session("-max-prefixes", "many"), "-max-prefixes"}`
  - **`TestUnevaluableLimit`:** drop the `expander` save, set and restore, and its doc sentence about the seam.
    `argsFor` appends `"-max-prefixes", "1"`. Cases A, B and C keep their assertions.
  - **New `TestMaxPrefixesOption`**, beside `TestUnevaluableLimit`, on the same registry with
    `registry("ANY")`: L imports `accept AS-BIG`, and AS-BIG expands to exactly 2 prefixes. Cases, each over
    `-session` and `-af ipv4`:

    | case | extra arguments | want |
    |---|---|---|
    | absent | none | exit 0; no `policy not evaluable` line; the import line reads `import, AS64496 from AS64500: 1 route: 1 accepted` |
    | at the size | `-max-prefixes 2` | the same as "absent" |
    | below | `-max-prefixes 1` | exit 0; exactly one `policy not evaluable` line, containing `MaxPrefixes (1)` |
    | huge | `-max-prefixes 1099511627776` | the same as "absent" |
    | irrd | `-irrd serve(t, registry("ANY")) -sources TEST -max-prefixes 1`, instead of `-dump` | the same as "below" |

- [ ] **Step 2: Run the tests to see them fail**

  Run: `GOWORK=off go test -count=1 -run 'TestUsage|TestBadCommandLines|TestUnevaluableLimit|TestMaxPrefixesOption' ./internal/cli`

  Expected: FAIL in `TestUsage`, `TestUnevaluableLimit` and `TestMaxPrefixesOption`, which get exit 2 for the
  unknown flag. The new `TestBadCommandLines` rows may already pass, since the unknown flag's error names it.
  They pin the refusal once the flag exists.

- [ ] **Step 3: Implement the option in `internal/cli/cli.go`**
  - **The flag:** `fs.Int("max-prefixes", 0, …)`, with the usage text "the most prefixes one set's expansion
    may reach (`N`); default rpsl's limit; raising it costs memory, see docs/routecheck.md". Keep the style of
    the neighbouring flags: a backquoted placeholder, and no number written.
  - **The check:** after `fs.Visit`, if `set["max-prefixes"]` and the value is `< 1`, return
    `usagef("-max-prefixes: %d is not a positive number of prefixes", n)`. A non-number is already refused by
    `flag` with an error that names `-max-prefixes`.
  - **The evaluator:** `peval.Evaluator{Src: src, Expander: resolve.Expander{MaxPrefixes: cfg.maxPrefixes}}`.
  - Remove `var expander` and its comment.

- [ ] **Step 4: Run the tests to see them pass**

  Run the step 2 command, then `GOWORK=off go vet ./... && GOWORK=off go test -count=1 ./...`.

  Expected: all PASS.

- [ ] **Step 5: The docs without figures**
  - **`docs/routecheck.md`:**
    - a flag-table row after `-direction`: "`-max-prefixes N` | The most prefixes one set's expansion may reach
      (rpsl's `MaxPrefixes`). The default is rpsl's limit. A report over it is unevaluable (R27); raising N
      lets it be decided at the memory cost given under 'Known limitations'. N must be a positive integer.";
    - in the `unevaluable` reason row, after "MaxConjuncts)", add "; `-max-prefixes` raises the first".
    - Leave the Known-limitations MaxPrefixes bullet to Task 3.
  - **`CLAUDE.md` R27:** replace the last sentence (the test-only seam) with "`-max-prefixes N` (internal/cli)
    sets `Expander.MaxPrefixes`; absent, it is the zero `Expander` (rpsl's default); 0 and negatives are
    refused (a negative is unlimited in rpsl)."
  - **`SECURITY.md`,** in the "Memory is bounded" bullet: "Set expansion is bounded by rpsl's limits;
    `-max-prefixes` raises one, at the user's choice and memory."
  - **`CHANGELOG.md` `[Unreleased]`:** a new `### Added` section above `### Changed`, with one bullet: the option,
    its default, the refusal of 0, negatives and non-numbers, and that it applies with `-dump` and `-irrd`.

- [ ] **Step 6: Run `scripts/check.sh` under the guard**

  Run: `MEMGUARD_NORMAL_PRIORITY=1 ../rpsl/.superpowers/sdd/tools/memguard.sh 8 1200 env GOMAXPROCS=4 scripts/check.sh > .data/check-max-prefixes-t1.log 2>&1; echo "exit=$?"; tail -3 .data/check-max-prefixes-t1.log`

  Expected: `exit=0`, `check: ok`, `SUCCESS`.

- [ ] **Step 7: Commit**

  ```bash
  git add internal/cli/cli.go internal/cli/cli_test.go docs/routecheck.md CLAUDE.md SECURITY.md CHANGELOG.md
  git commit -m "cli: -max-prefixes raises rpsl's MaxPrefixes; the test seam goes"
  ```

### Task 2: The real-data test reads the limit

**Files:**
- Modify: `realdata_test.go`:
  - `TestRealData` (~112-160);
  - `checkPair` (~909-914) and its caller (~190);
  - the doc comment's environment list (~100-110).
- Test: `realdata_test.go` (a new pure test that runs without data).
- Docs: `CLAUDE.md`'s real-data environment bullets (~279-283).

**Interfaces:**
- Consumes: nothing from Task 1. It sets the same `resolve.Expander` field.
- Produces:
  - `parseMaxPrefixes(s string) (int, error)`: "" gives 0, nil; a positive integer gives itself; anything else
    gives an error naming `ROUTECHECK_REALDATA_MAX_PREFIXES`;
  - `checkPair(tb, reg, vrps, p, file, timeout, exp resolve.Expander)`;
  - the log line `limits: MaxPrefixes <N or "rpsl's default">`, written once before the pairs.

- [ ] **Step 1: Write the failing test `TestParseMaxPrefixes`**

  A table: `""` → `0, nil`; `"2097152"` → `2097152, nil`; `"1099511627776"` → `1099511627776, nil`; `"0"`,
  `"-1"`, `"x"` and `"1.5"` → an error whose text contains `ROUTECHECK_REALDATA_MAX_PREFIXES`.

- [ ] **Step 2: Run it to see it fail**

  Run: `GOWORK=off go test -count=1 -run TestParseMaxPrefixes .`

  Expected: FAIL (undefined: `parseMaxPrefixes`).

- [ ] **Step 3: Implement**
  - Add `parseMaxPrefixes`.
  - `TestRealData`: `tb.Fatalf` on its error, then log `limits: MaxPrefixes …` before the sample.
  - Pass `resolve.Expander{MaxPrefixes: n}` to `checkPair`, which builds
    `peval.Evaluator{Src: reg.src, Expander: exp}`.
  - Add the variable to the doc comment's environment list.
  - **`CLAUDE.md`:** a bullet beside `ROUTECHECK_REALDATA_REGISTRIES`, saying "`ROUTECHECK_REALDATA_MAX_PREFIXES`
    (a positive integer; unset means rpsl's default) sets `Expander.MaxPrefixes` as `-max-prefixes` does".

- [ ] **Step 4: Run to see it pass**

  Run: `GOWORK=off go vet ./... && GOWORK=off go test -count=1 ./...`

  Expected: PASS. `TestRealData` skips without data.

- [ ] **Step 5: Commit**

  ```bash
  git add realdata_test.go CLAUDE.md
  git commit -m "realdata: ROUTECHECK_REALDATA_MAX_PREFIXES sets the limit, logged"
  ```

### Task 3: Measure the cost and publish it

The controller runs steps 1-4 (the heavy runs and the checks of their logs) alone, under the guard, and writes
a facts file. The implementer writes steps 5-7 from that file only.

**Files:**
- Logs, git-ignored:
  - `.data/max-prefixes-cli-{default,2097152,4194304,8388608,16777216}.log`;
  - `.data/realdata-max-prefixes.log`;
  - `.data/max-prefixes-same-pairs.log`.
- Docs:
  - `docs/routecheck.md`: the Known-limitations MaxPrefixes bullet (~421-436);
  - `CLAUDE.md`: the MaxPrefixes bullet (~320-324);
  - `CHANGELOG.md` `[Unreleased]`: `### Measured, max-prefixes`.

**Interfaces:**
- Consumes: Task 1's option; Task 2's variable and its `limits:` line.

- [ ] **Step 1 (controller): Run the command at each limit**
  - Build `.data/routecheck-bin` from the branch head. The command is
    `routecheck -local AS9086 -peer AS6762 -collector .data/realdata/filtered/AS6762.mrt [-max-prefixes N] -dump <the 32 dumps in .data/realdata/MANIFEST order>`,
    in the default direction, with `-af both` and without `-vrps`.
  - Run it first without the option (`default`), then at N = 2097152, 4194304, 8388608 and 16777216, each as
    `MEMGUARD_NORMAL_PRIORITY=1 memguard.sh 8 1800 env GOMAXPROCS=4 GOMEMLIMIT=6GiB …`, writing to
    `.data/max-prefixes-cli-<N>.log`.
  - Stop after the first N whose output has no `policy not evaluable` line naming `MaxPrefixes`, or the first run
    the guard stops (record its guard line; try no higher value).
  - **Record for each run:**
    - the exit status;
    - the guard's peak RSS and seconds;
    - the count of `policy not evaluable` lines naming `MaxPrefixes`, and of those naming anything else;
    - the summed accepted, rejected and undecided routes over the export reports, and the import line.
  - **Expected:** `default` reproduces `.data/set-limits-cli.log`'s ipv4 figures (21 MaxPrefixes lines in
    ipv4). Any difference is to be explained before going on.

- [ ] **Step 2 (controller): The every-registry run at the chosen N**

  N is the lowest value that left no MaxPrefixes line in step 1, or else the highest value that completed. Run:

  `MEMGUARD_NORMAL_PRIORITY=1 GOMAXPROCS=4 ../rpsl/.superpowers/sdd/tools/memguard.sh 8 6000 env GOWORK=off GOMAXPROCS=4 GOMEMLIMIT=6GiB ROUTECHECK_REALDATA=$PWD/.data/realdata ROUTECHECK_REALDATA_MAX_PREFIXES=<N> go test -count=1 -timeout 100m -run 'TestRealData$' -v . > .data/realdata-max-prefixes.log 2>&1`

  **Expected:** PASS, `limits: MaxPrefixes <N>`, and "60 checked … 0 set too large".

- [ ] **Step 3 (controller): The 50 pairs must not move**
  - Compare every figure, per pair, of `.data/realdata-set-limits.log` against `.data/realdata-max-prefixes.log`
    (extend `.data/same-pairs.py`'s `diff` mode to all its per-pair keys if needed). Write the result to
    `.data/max-prefixes-same-pairs.log`.
  - **Expected:** every pair that differs is one of the 10 in `.data/set-limits-pairs-unevaluable.log`
    (pairs 1, 2, 10, 15, 21, 24, 30, 32, 33, 53). Any other difference is a defect: stop and explain it before
    publishing.

- [ ] **Step 4 (controller): The facts file**

  Write `.superpowers/sdd/<workspace>/task-3-facts.md`. It holds:
  - the cost table (limit, peak RSS, seconds, MaxPrefixes reports left, other unevaluable reports, exit
    status), one row per step-1 run, with its log;
  - step 2's TOTALS:
    - the unevaluable reports left, by limit;
    - how the 549,847 routes of `.data/realdata-set-limits.log` now split between accepted, rejected and
      undecided, over the 10 pairs, with the subtractions shown;
    - wall time and peak RSS, against 3m45s and 6,482 MB;
  - step 3's result;
  - what was not measured.

- [ ] **Step 5 (implementer): The measured docs**

  Use only figures from the facts file.
  - **`docs/routecheck.md`'s MaxPrefixes bullet:**
    - drop "No flag raises the limit";
    - say `-max-prefixes N` lifts it;
    - add the cost table with its logs;
    - say the default stays rpsl's, with the every-registry figures at the chosen N.
  - **`CLAUDE.md`'s MaxPrefixes bullet:** the same, in short.
  - **`CHANGELOG.md` `[Unreleased]`:** a `### Measured, max-prefixes` section after the existing Measured
    sections, holding every figure with its log.

- [ ] **Step 6 (implementer): Run `scripts/check.sh` under the guard**

  Run it as in Task 1, step 6, writing to `.data/check-max-prefixes-t3.log`.

  Expected: `check: ok`.

- [ ] **Step 7 (implementer): Commit**

  ```bash
  git add docs/routecheck.md CLAUDE.md CHANGELOG.md
  git commit -m "docs: the measured cost of -max-prefixes"
  ```
