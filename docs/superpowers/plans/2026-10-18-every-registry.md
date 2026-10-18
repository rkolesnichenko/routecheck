# Every-registry real-data run — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** routecheck's opt-in real-data run loads every IRR registry rpsl fetches, not RIPE alone. The run
checks the same 60 pairs on the same pinned files, RIPE-only and then every registry, and publishes the
before-and-after.

**Architecture:**
- `scripts/fetch-data.sh` fetches 15 more registries. A `--registries` mode adds them to an existing
  `MANIFEST` without touching its other lines.
- `realdata_test.go` places each dump file in a fixed precedence order by its name. It loads the chosen
  registries into one `resolve.Corpus`, as the command loads `-dump` files, but selects pairs from RIPE's
  files only.
- It tallies the missing sets that remain and the route-object answers.
- The command and the library do not change.

**Tech Stack:**
- Go (go.mod floor 1.23, toolchain go1.27.2), `GOWORK=off`;
- rpsl v0.30.0 (`resolve.Corpus`, `resolve.Expander`), mrt v0.1.0;
- POSIX sh and curl.

**Spec:** `docs/superpowers/specs/2026-10-18-every-registry-design.md`. Read it first; it is the authority.

## Global Constraints

- The command, the library and `api/*.txt` do not change. Only `scripts/fetch-data.sh`, the test files and
  the docs do.
- Precedence, ripe first: ripe, apnic, arin, afrinic, lacnic, radb, altdb, bboi, bell, canarie, jpirr,
  nestegg, nttcom, panix, reach, tc.
- Pairs are selected only from objects read from RIPE's files (`ripe.db.*`). The same seed and sample
  sizes are used (defaults 50 + 10, seed 1).
- Memory gate: projected full-run peak = 4,234 MB + (every-registry load peak − RIPE load peak). Go only
  if the projection is ≤ 6,144 MB; otherwise stop and report to the user. Never raise the 8 GB cap or drop
  a registry.
- Heavy runs:
  - one at a time, alone;
  - `MEMGUARD_NORMAL_PRIORITY=1 GOMAXPROCS=4 <memguard> 8 <timeout> env GOWORK=off GOMAXPROCS=4
    GOMEMLIMIT=6GiB …`, where `<memguard>` is rpsl's `.superpowers/sdd/tools/memguard.sh`, reached as
    `../rpsl/.superpowers/sdd/tools/memguard.sh` from routecheck's root;
  - never beside `scripts/check.sh`.
- No local home-directory path in any committed file: `check.sh` greps for one, and the plan's own text
  must not trip it.
- Commit on branch `every-registry`, never on `main`. Nothing is pushed without the user's go-ahead.
- Every figure in a doc or the CHANGELOG comes from a log written in Task 4 and is named with it. Logs go
  in `.data/` (git-ignored).
- Nothing downloaded is committed.

## Review Focus

1. **A registry download fails.** The script must exit non-zero naming the file. It must neither write a
   `MANIFEST` line for that file nor drop the existing lines; a rerun fetches only what is missing (Task 1,
   steps 3–4).
2. **An older RIPE-only `MANIFEST`.** The test runs on RIPE alone and logs `registries: ripe`. Asking
   `ROUTECHECK_REALDATA_REGISTRIES` for a registry the `MANIFEST` does not pin fails, naming it
   (Task 2, `TestChooseDumps`).
3. **A `MANIFEST` file with an unknown registry prefix** fails the test, naming the file. It is never
   silently skipped (Task 2, `TestDumpRegistry`).
4. **The same as-set held by RIPE and RADB.** RIPE's members are the ones used. An aut-num held only by
   RADB is never a sampled L or X (Task 2, `TestLoadRegistryPrecedenceAndSelection`).
5. **A rejected route whose failing clauses name two missing sets.** It counts once in the
   rejected-with-a-missing-set total and once under each set in the top list (Task 3,
   `TestReportTalliesMissingSetsAndRouteObjects`).

---

### Task 1: `fetch-data.sh` fetches every registry, and `--registries` adds them alone

**Files:**
- Modify: `scripts/fetch-data.sh` (header comment, constants, `download`, a registries section, the
  `--registries` mode, the `FETCH_DATA_DIR` override)

**Interfaces:**
- Produces: `MANIFEST` lines for these files, the names Task 2 parses:
  - `apnic.db.<class>.gz` for class in aut-num, as-set, route-set, route, route6, filter-set,
    peering-set, inet-rtr, rtr-set (from `https://ftp.apnic.net/apnic/whois/`);
  - `arin.db.gz` (`https://ftp.arin.net/pub/rr/arin.db.gz`);
  - `afrinic.db.gz` (`https://ftp.afrinic.net/pub/dbase/afrinic.db.gz`);
  - `lacnic.db.gz` (`https://ftp.lacnic.net/lacnic/irr/lacnic.db.gz`);
  - `radb.db.gz` and `<m>.db.gz` for m in altdb, bboi, bell, canarie, jpirr, nestegg, nttcom, panix,
    reach, tc (`ftp://ftp.radb.net/radb/dbase/<name>.db.gz`).

  These are the URLs of rpsl's `scripts/fetch-irr-dumps.sh`; copy them from there and say so in a comment.

- [ ] **Step 1: Write the script changes**
  - **The default run** fetches RIPE's files, the registries above, the RIBs and the VRPs, in that
    `MANIFEST` order, and writes `MANIFEST` as today (temporary file, then `mv`).
  - **`--registries`** fetches only the registries. It then writes a new `MANIFEST`:
    - every existing line whose file name is not one of these registry files, byte for byte and in
      order;
    - then the registry lines.

    It goes through a temporary file and `mv`, so a failure leaves the old `MANIFEST` untouched. With no
    `MANIFEST` it prints `fetch-data: --registries needs an existing MANIFEST (run scripts/fetch-data.sh
    first)` and exits 1 before downloading anything.
  - **`download`** tries five times for an `ftp://` URL and three times otherwise, waiting 10 s between
    tries (RADB's FTP often times out).
  - **`FETCH_DATA_DIR`** overrides `.data/realdata`.
  - **Header comment:** document the new files, the mode, the precedence order (the spec's), and that
    RADB's FTP files are fetched unauthenticated and pinned by sha256 on first fetch.
  - Any other argument prints usage and exits 2.

- [ ] **Step 2: Syntax**

  Run: `sh -n scripts/fetch-data.sh; echo $?`
  Expected: `0`

- [ ] **Step 3: The refusal, offline**

  Run: `d=$(mktemp -d); FETCH_DATA_DIR=$d scripts/fetch-data.sh --registries; echo "exit=$?"; ls -A $d`
  Expected: the refusal message, `exit=1`, and an empty directory.

- [ ] **Step 4: The real fetch, preserving the pinned lines**

  Run:
  ```
  cp .data/realdata/MANIFEST .data/manifest-before-registries
  scripts/fetch-data.sh --registries > .data/fetch-registries.log 2>&1; echo "exit=$?"
  ```
  Then compare: `head -n $(wc -l < .data/manifest-before-registries) .data/realdata/MANIFEST | cmp - .data/manifest-before-registries`

  Expected:
  - `exit=0`;
  - `cmp` silent: the old lines are unchanged and first;
  - `MANIFEST` has 9 + 1 + 1 + 1 + 1 + 10 = 23 new lines.

  If a registry fails after its retries, rerun the same command. It must fetch only what is missing.
  Record both runs in the log.

- [ ] **Step 5: Commit**
  ```
  git add scripts/fetch-data.sh
  git commit -m "fetch-data: every registry rpsl fetches; --registries adds them to a pinned MANIFEST"
  ```

### Task 2: the real-data test loads the chosen registries in precedence order, selecting pairs from RIPE

**Files:**
- Modify: `realdata_test.go`:
  - `realData` and `openRealData` (lines 163–222);
  - `ripeRegistry` and `loadRegistry` (224–317), renaming `ripeRegistry` → `irrRegistry` wherever `grep`
    finds it (`bench_test.go` calls `loadRegistry`; keep it compiling);
  - `TestRealData`'s load log and a load-only exit (91–102);
  - its doc comment (40–90).
- Create: `realdata_registry_test.go`: unit tests that run in `check.sh` and need no data.

**Interfaces:**
- Produces, in package `routecheck_test` (the package `realdata_test.go` is in):
  - `var registryOrder = []string{"ripe", "apnic", "arin", "afrinic", "lacnic", "radb", "altdb", "bboi", "bell", "canarie", "jpirr", "nestegg", "nttcom", "panix", "reach", "tc"}`
  - `func dumpRegistry(name string) (string, bool)`: base name → registry, the part before the first
    `.db.` or `.db.gz`. `ok` is false when that registry is not in `registryOrder`, or the name has
    neither form.
  - `func orderDumps(dumps []string) []string`: a new slice, stably sorted by the registry's index in
    `registryOrder`, keeping `MANIFEST` order within a registry. Precondition: every name passes
    `dumpRegistry`.
  - `func chooseDumps(dumps []string, want string) ([]string, error)`:
    - `want` is `ROUTECHECK_REALDATA_REGISTRIES`, comma-separated registry names, case-insensitive;
    - `""` means every dump;
    - a name not in `registryOrder`, or with no dump in `dumps`, is an error naming it;
    - the result keeps `dumps`' order.
  - `irrRegistry` gains:
    - `sources []string`: the precedence passed to `Corpus.Source`, first appearance in file order;
    - `perSource map[string]int`: objects kept per source;
    - `registries []string`: registries loaded, in order.

    `imports`, `reImports` and `autnums` are filled only from files whose `dumpRegistry` is `ripe`.
  - `openRealData` keeps every `<registry>.db…` file in `rd.dumps`, after `orderDumps` and `chooseDumps`.
    A `MANIFEST` file that is neither a dump, a RIB (`rv2-`, `rrc`) nor VRPs (`vrps-`) fails the test,
    naming it.
  - `ROUTECHECK_REALDATA_LOAD_ONLY=1`: `TestRealData` logs the registry line, then a `LOAD:` line, then
    returns before reading VRPs or RIBs. The `LOAD:` line gives registries, sources in order, objects per
    source, the RIPE-selected aut-nums, the load time, and the heap in use after `runtime.GC()`.

- [ ] **Step 1: Write the failing tests** in `realdata_registry_test.go`:
  ```go
  func TestDumpRegistry(t *testing.T) // table:
  //   "ripe.db.aut-num.gz"→"ripe",true; "apnic.db.route6.gz"→"apnic",true;
  //   "radb.db.gz"→"radb",true; "nttcom.db.gz"→"nttcom",true;
  //   "level3.db.gz"→"",false; "rv2-rib.20261018.1200.bz2"→"",false; "ripe.gz"→"",false
  func TestOrderDumps(t *testing.T)
  //   in:   [altdb.db.gz radb.db.gz apnic.db.route.gz ripe.db.aut-num.gz arin.db.gz ripe.db.as-set.gz]
  //   want: [ripe.db.aut-num.gz ripe.db.as-set.gz apnic.db.route.gz arin.db.gz radb.db.gz altdb.db.gz]
  func TestChooseDumps(t *testing.T)
  //   dumps [ripe.db.aut-num.gz ripe.db.as-set.gz radb.db.gz]:
  //   ""→all three; "RIPE"→the two ripe files; "ripe,radb"→all three;
  //   "ripe,arin"→error containing "arin"; "foo"→error containing "foo"
  func TestLoadRegistryPrecedenceAndSelection(t *testing.T)
  ```
  `TestLoadRegistryPrecedenceAndSelection` writes three gzip files to `t.TempDir()` and calls
  `loadRegistry` on them in this order:
  - `ripe.db.aut-num.gz`: `aut-num: AS64496`, `import: from AS64500 accept AS-X`, `source: RIPE`;
  - `ripe.db.as-set.gz`: `as-set: AS-X`, `members: AS64501`, `source: RIPE`;
  - `radb.db.gz`:
    - `aut-num: AS64497`, `import: from AS64500 accept ANY`, `source: RADB`;
    - `as-set: AS-X`, `members: AS64502`, `source: RADB`;
    - `as-set: AS-Y`, `members: AS64503`, `source: RADB`.

  It asserts:
  - `reg.autnums` is exactly {AS64496}, and `reg.imports` has exactly the key AS64496 (RADB's aut-num is
    not selectable);
  - `reg.sources` is `[RIPE RADB]`, and `reg.perSource` is {RIPE: 2, RADB: 3};
  - `(&resolve.Expander{Src: reg.src}).ExpandAS(ctx, AS-X)` lists exactly [AS64501] (RIPE's wins);
  - ExpandAS of AS-Y lists [AS64503] (a RADB-only set resolves).

  Build the `SetRef` with `types.ParseSetRef`.

- [ ] **Step 2: Run them to see them fail**

  Run: `GOWORK=off go test -count=1 -run 'TestDumpRegistry|TestOrderDumps|TestChooseDumps|TestLoadRegistryPrecedenceAndSelection' .`
  Expected: build failure (undefined `dumpRegistry`, `orderDumps`, `chooseDumps`, fields).

- [ ] **Step 3: Implement the interfaces above** in `realdata_test.go`.
  - `loadRegistry` keeps its parse loop.
  - The selection maps are filled only when `dumpRegistry(filepath.Base(name))` is `ripe`.
  - The registry log line in `TestRealData` gains the registries and sources.
  - Update the doc comment:
    - `ROUTECHECK_REALDATA_REGISTRIES` and `ROUTECHECK_REALDATA_LOAD_ONLY`;
    - the precedence order;
    - that pairs come from RIPE's files only.

- [ ] **Step 4: Run them to see them pass**, then the whole module

  Run: the command of step 2, then `GOWORK=off go vet ./... && GOWORK=off go test -count=1 ./...`
  Expected: PASS. `TestRealData` skips without `ROUTECHECK_REALDATA`.

- [ ] **Step 5: Commit**
  ```
  git add realdata_test.go realdata_registry_test.go bench_test.go
  git commit -m "realdata: load the pinned registries in precedence order; pairs come from RIPE's files"
  ```

### Task 3: the run tallies the missing sets left, the route-object answers, and logs its pairs

**Files:**
- Modify: `realdata_test.go`:
  - `pairResult` (735–771), `report` (891–988), `totals`, `add` and `log` (1043–1143);
  - `TestRealData`, after `pickPairs` (121–126).
- Modify: `realdata_registry_test.go` (one more test).

**Interfaces:**
- Consumes: `pairResult.report(rep *routecheck.Report, dir int, label string)` as it is.
- Produces:
  - `pairResult` and `totals` gain:
    - `missingSets [2]tally`: per direction, routes per missing set, keyed by `types.SetRef.String()`.
      A Rejected route adds 1 under each distinct set named in any of its `Fails[i].Missing`.
      `rejMissing` stays: once per route.
    - `routeObj [2]tally`: per direction, Accepted, Rejected and Undecided routes alike, with keys
      `"yes"`, `"no"` and `"unknown"` from `RouteVerdict.RouteObj` true, false and nil. This is per
      report: a route that appears in several export reports counts once in each.
  - `func topN(t tally, n int) string`: the `n` largest entries as `key count`, comma-separated, ordered
    by count descending then key ascending. `""` for an empty tally.
  - New `TOTALS:` lines:
    - `missing sets left: import N distinct, export N distinct`;
    - `missing sets by routes, import: <topN(…, 20)>`, and the same line for export;
    - `route objects, import: yes N, no N, unknown N`, and the same line for export.
  - After the sample line, one line: `PAIRS: AS<L>-AS<X> AS<L>-AS<X> …` in sample order, for diffing.

- [ ] **Step 1: Write the failing test** `TestReportTalliesMissingSetsAndRouteObjects` in
  `realdata_registry_test.go`.

  It builds a `routecheck.Report` by hand with three routes:
  1. Rejected, with two `Fails` whose `Missing` are [AS-A] and [AS-A, AS-B], and `RouteObj` true;
  2. Rejected, with `Fails` [{Missing: [AS-B]}], and `RouteObj` false;
  3. Accepted, with `RouteObj` nil.

  It calls `report(&rep, 1, "x")` on a fresh `pairResult` whose tallies are initialized, as `checkPair`
  does. It asserts:
  - `rejMissing[1] == 2`;
  - `missingSets[1]` is {AS-A: 1, AS-B: 2};
  - `routeObj[1]` is {yes: 1, no: 1, unknown: 1};
  - `topN(tally{"AS-B": 2, "AS-A": 1, "AS-C": 2}, 2) == "AS-B 2, AS-C 2"`;
  - `topN(tally{}, 5) == ""`.

- [ ] **Step 2: Run it to see it fail**

  Run: `GOWORK=off go test -count=1 -run TestReportTalliesMissingSetsAndRouteObjects .`
  Expected: build failure (undefined fields, `topN`).

- [ ] **Step 3: Implement** the fields, the tallying in `report`, the summing in `totals.add`, the
  `TOTALS:` lines and the `PAIRS:` line. Initialize the new tallies wherever `checkPair` and
  `TestRealData` initialize the others.

- [ ] **Step 4: Run it, then the module and `check.sh`**

  Run:
  ```
  GOWORK=off go test -count=1 ./...
  MEMGUARD_NORMAL_PRIORITY=1 GOMAXPROCS=4 ../rpsl/.superpowers/sdd/tools/memguard.sh 8 1800 scripts/check.sh > .data/check-every-registry-t3.log 2>&1; echo $?
  ```
  Expected: PASS; `0`; the log ends with `check: ok`.

- [ ] **Step 5: Commit**
  ```
  git add realdata_test.go realdata_registry_test.go
  git commit -m "realdata: tally the missing sets left and the route-object answers; log the pairs"
  ```

### Task 4: measure, then run RIPE-only and every registry on the same files

The runs are operational; no code changes unless a run shows a defect. Each command runs alone, under the
guard, at normal priority. Time is not the constraint (spec, settled 7): raise `-timeout` and the guard's
timeout if a run needs it, and record that you did. `GUARD` stands for:

```
MEMGUARD_NORMAL_PRIORITY=1 GOMAXPROCS=4 ../rpsl/.superpowers/sdd/tools/memguard.sh 8
```

and `ENV` stands for:

```
env GOWORK=off GOMAXPROCS=4 GOMEMLIMIT=6GiB ROUTECHECK_REALDATA=$PWD/.data/realdata
```

- [ ] **Step 1: Load RIPE alone**

  Run:
  ```
  GUARD 1800 ENV ROUTECHECK_REALDATA_LOAD_ONLY=1 ROUTECHECK_REALDATA_REGISTRIES=ripe go test -count=1 -timeout 30m -run TestRealData -v . > .data/load-ripe.log 2>&1
  ```
  Record the guard's peak RSS (P_ripe) and the `LOAD:` line.

- [ ] **Step 2: Load each other registry alone, then all together**

  Load each other registry alone (`.data/load-<registry>.log`): `ROUTECHECK_REALDATA_REGISTRIES=<registry>`,
  the same command otherwise. Stop early if any single one is over 4 GB, and report it. Then load every
  registry (`.data/load-all.log`, `ROUTECHECK_REALDATA_REGISTRIES` unset). Record its peak RSS (P_all).

- [ ] **Step 3: The gate**
  - Projection = 4,234 + (P_all − P_ripe) MB.
  - If it is > 6,144 MB: stop. Report every load figure to the user and run nothing more.
  - Otherwise go on.
  - Write the arithmetic in `.data/every-registry-gate.log`.

- [ ] **Step 4: The RIPE-only baseline on the current files**

  Run:
  ```
  GUARD 6000 ENV ROUTECHECK_REALDATA_REGISTRIES=ripe go test -count=1 -timeout 100m -run TestRealData -v . > .data/realdata-ripe-only.log 2>&1
  ```
  Expected: PASS, and its figures equal `.data/realdata-v0.2.log`'s. They are the same files, so any
  difference is a defect to explain before going on.

- [ ] **Step 5: Every registry**

  Run:
  ```
  GUARD 6000 ENV go test -count=1 -timeout 100m -run TestRealData -v . > .data/realdata-every-registry.log 2>&1
  ```
  Expected: PASS.

- [ ] **Step 6: The pairs are the same.**
  - The `PAIRS:` lines of steps 4 and 5 must be identical.
  - That line must equal the 60 pairs in `.data/realdata-v0.2.log`'s `pair i/60:` lines, extracted with
    a `grep`/`sed` you record in `.data/every-registry-checks.log`.

  A difference stops the task.

- [ ] **Step 7: Hand checks**, recorded in `.data/every-registry-checks.log`.
  - **(a) The top missing set.** For the export top list's first set, `gzip -dc` every pinned dump and
    grep for its name, case-insensitive, as an `as-set:`/`route-set:`/`filter-set:`/`peering-set:` key.
    Expect no hit.
  - **(b) One count and its denominator.** For one pair whose export rejections fell between the two
    runs, take one route the every-registry run accepts. Show the set that RIPE lacks and that now
    resolves, with the registry and the dump file holding it, by grep.

### Task 5: docs and CHANGELOG from Task 4's logs

**Files:**
- Modify:
  - `docs/routecheck.md`: a "Loading every registry" recipe near `-dump` (the order, `fetch-data.sh` or
    rpsl's `fetch-irr-dumps.sh`), and the "Load every registry" limitation (lines ~342–352);
  - `CLAUDE.md`: the real-data command, the two environment variables, `--registries`, and the
    registries in the Known limitations bullet;
  - `CHANGELOG.md` `[Unreleased]`:
    - Changed: `fetch-data.sh` and the real-data run;
    - Measured: the before-and-after table, the load figures, the missing sets left, the hygiene change,
      and wall time and peak RSS, each with its log.

- [ ] **Step 1: Write the docs.**
  - Every figure comes from a Task 4 log, and the log is named beside it.
  - Say that RADB's FTP dump is RPKI-filtered and the mirrors' are not, so route-object figures depend on
    it.
  - State the source order observed (the `LOAD:` line), and any `-NONAUTH` sources.

- [ ] **Step 2: Check**

  Run: `MEMGUARD_NORMAL_PRIORITY=1 GOMAXPROCS=4 ../rpsl/.superpowers/sdd/tools/memguard.sh 8 1800 scripts/check.sh > .data/check-every-registry-t5.log 2>&1; echo $?`
  Expected: `0`, `check: ok`.

- [ ] **Step 3: Commit**
  ```
  git add docs/routecheck.md CLAUDE.md CHANGELOG.md
  git commit -m "docs, real data: every registry loaded; before-and-after on the same files"
  ```
