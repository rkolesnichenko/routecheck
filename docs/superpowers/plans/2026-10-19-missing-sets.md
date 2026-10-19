# Missing-sets check Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** For every route the every-registry run at `-max-prefixes 2097152` rejects with a missing set in a
failing clause, say whether it is a gap in what routecheck loads, real, real for any IRR filter, or unknown.
Then publish the counts.

**Architecture:**
- The opt-in real-data test gains file outputs (run A's missing sets and rejected routes) and inputs (an
  extra dump, a pair selection, run A's routes to track in run B).
- A new opt-in test file does the live lookups (cached, capped) and the classification, from those files.
- The heavy runs and the lookups are driven round by round by a script under `.data/`. The engine's own
  "missing" list after each run B is the closure, so nothing parses set members.
- The command does not change.

**Tech Stack:** Go 1.23 (go.mod floor), rpsl v0.30.0 (`types.ParseSetRef`, `SetName.Class`), mrt
v0.1.0 (`mrt.Decompress`), the whois protocol on TCP 43, and zsh with rpsl's memguard.

**Spec:** `docs/superpowers/specs/2026-10-19-missing-sets-design.md`

## Global Constraints

- The command's behaviour, output, `api/*.txt` and go.mod do not change. Only `_test.go` files, docs and
  the CHANGELOG change in git.
- Live lookups:
  - only to `whois.radb.net:43` and `whois.ripe.net:43`;
  - one connection at a time per service, one query per connection;
  - at most 5,000 queries in the whole measurement;
  - every answer is cached under `.data/missing-sets/` with its query time, and a re-run asks nothing again.
- RADB sources queried: `RADB,LACNIC,IDNIC,AFRINIC,RIPE,RIPE-NONAUTH,BELL,NTTCOM,ALTDB,PANIX,NESTEGG,LEVEL3,ARIN,JPIRR,BBOI,CANARIE,REACH,TC,APNIC`
  (`!s-lc` of 2026-10-19 less RPKI). The unloaded ones are `IDNIC`, `RIPE-NONAUTH` and `LEVEL3`.
- The dump date is `2026-10-18`. An object goes into run B only if its newest date (`last-modified:`,
  `created:`, latest `changed:`) is on or before it. An undated object goes in, and is counted.
- Set classes: `held but refused`, `elsewhere`, `deleted`, `not found`, `inconclusive`, plus
  `not looked up` (the cap or the round limit was hit).
- Route classes: `gap`, `real`, `real for any IRR filter`, `unknown`. Each unknown route has exactly one
  reason, the first that applies in this order:
  1. `inconclusive set`
  2. `held-but-refused set`
  3. `newer set`
  4. `set not looked up`
  5. `found set still missing in B`
  6. `unevaluable in B`
  7. `undecided in B`
  8. `no verdict in B`
- "Found wins". Otherwise any failed or unparseable lookup makes the set `inconclusive`. `deleted` needs RIPE's
  history to say so. `not found` needs every lookup to answer "no entries".
- Heavy runs: one at a time, with `MEMGUARD_NORMAL_PRIORITY=1 ../rpsl/.superpowers/sdd/tools/memguard.sh 8 …`,
  `GOMAXPROCS=4` and `GOMEMLIMIT=6GiB`. Never beside check.sh. Never raise the 8 GB cap: shard pairs instead.
- Runs A and B: the 2026-10-18 dumps in `.data/realdata` (MANIFEST unchanged) and
  `ROUTECHECK_REALDATA_MAX_PREFIXES=2097152`.
- Fetched objects, caches and TSVs stay in `.data/` (git-ignored). Only counts, set names and dates go in docs.
- No local home-directory path in any committed file or commit message. Every published figure names its log.
- `scripts/check.sh` passes (run under the memory guard).

## Review Focus

1. **Two routes with the same key in one report:** two collector peers can send the same prefix and path. They must
   not silently merge. The key's uniqueness is checked, and a duplicate fails the run (Task 1's
   `TestRouteKeyUnique`).
2. **A scoped reference `RIPE::AS-X`:** it is looked up in that source only, and it is "held" only by an
   `AS-X` object with that source (Task 3's `TestLookupScoped`).
3. **An answer cut short** (connection reset, timeout, empty body): it is `inconclusive` after one retry,
   never "no entries" (Task 3's `TestWhoisCutShort`).
4. **Case and colons in set names** (`as-foo` in a dump, `AS-FOO` missing; `AS1:AS-X:AS2`): matching is
   case-insensitive, and cache file names round-trip (Task 3's `TestCacheName`).
5. **Merging shard files:** `none` in one shard and a verdict in another gives the verdict; two different
   verdicts are an error (Task 4's `TestMergeTracked`).

---

### Task 1: The real-data test writes its missing sets and tracked routes

**Files:**
- Modify: `realdata_test.go` (doc comment of `TestRealData`, `TestRealData`, `pairResult`, `(*pairResult).report`)
- Test: `realdata_registry_test.go`

**Interfaces:**
- Produces:
  - `routeKey(pair, dir, family, neighbour string, r verdict.Route) string`. Its fields are joined by `|`:
    `AS<L>-AS<X>`, `import` or `export`, the `types.AddrFamily` String, `AS<n>` (import: X; export:
    Toward), the prefix, and the path ASNs `AS1 AS2 …` with ` ?` appended when `!PathKnown`.
  - The TSV line `key\toutcome\tdetail\tsets`:
    - `outcome` is `accepted`, `rejected`, `undecided` or `none`;
    - `detail` is the Undecided reason kinds, sorted and comma-joined (empty otherwise);
    - `sets` is the union of `Fails[].Missing` (`SetRef.String()`), sorted and comma-joined.
  - With `ROUTECHECK_REALDATA_OUT=DIR`, the run writes:
    - `DIR/missing-sets.tsv`: `dir\tset\troutes`, sorted by dir then set, the same counts as `missingSets`;
    - `DIR/rejected-missing.tsv`: one TSV line per Rejected route whose sets are non-empty.
  - With `ROUTECHECK_REALDATA_TRACK=FILE` (a `rejected-missing.tsv`), it writes `DIR/tracked.tsv`: one
    line per key in FILE, in FILE's order, with this run's verdict, or `none` when that key's pair was not
    checked or timed out. TRACK without OUT fails the test.

- [ ] **Step 1: Write the failing tests** in `realdata_registry_test.go`:
  - `TestRouteKey`: an export route of AS6762 toward AS174, `ipv4.unicast`, `192.0.2.0/24`, path
    `[6762 3356]`, PathKnown, gives `AS9086-AS6762|export|ipv4.unicast|AS174|192.0.2.0/24|AS6762 AS3356`.
    The same route with PathKnown false ends `AS6762 AS3356 ?`.
  - `TestRouteKeyUnique`: `report` on a Report holding two routes with the same key records an error in
    `pairResult` (a new field `dupKeys int`, which is 1). `TestRealData` fails when any pair's `dupKeys > 0`.
  - `TestTrackedLines`: a Report with one Rejected route (Fails naming `AS-B` then `AS-A`, and `AS-A`
    again), one Undecided route (reasons `unevaluable`, `peval`) and one Accepted route.
    - The lines are `…\trejected\t\tAS-A,AS-B`, `…\tundecided\tpeval,unevaluable\t` and `…\taccepted\t\t`.
    - Only the first goes to the rejected-missing list.

- [ ] **Step 2: Run** `go test -run 'TestRouteKey|TestTrackedLines' .`. Expected: FAIL (undefined: routeKey).

- [ ] **Step 3: Implement.**
  - `report` gains a `pair, family, neighbour` context. Build it from the label's parts instead of
    parsing the label.
  - Each pair keeps its lines in a `map[string]string` (key → line) for the tracked lookup, and its
    rejected-missing lines in order. Free both once the pair is written out, so memory does not grow
    with pairs.
  - Write files with `bufio` and check every write and the `Close`.
  - Document the two env vars in `TestRealData`'s comment, in the existing style.

- [ ] **Step 4: Run** `go test -run 'TestRouteKey|TestTrackedLines|TestReportTallies' .` and then `scripts/check.sh` under the
  memory guard. Expected: PASS and check.sh `SUCCESS`.

- [ ] **Step 5: Commit**: `realdata: write missing sets and tracked routes (ROUTECHECK_REALDATA_OUT, _TRACK)`.

### Task 2: The real-data test takes an extra dump and a pair selection

**Files:**
- Modify: `realdata_test.go` (`TestRealData`, `loadRegistry`)
- Test: `realdata_registry_test.go`

**Interfaces:**
- Consumes: Task 1's OUT and TRACK, unchanged.
- Produces:
  - `ROUTECHECK_REALDATA_EXTRA=FILE`: an RPSL dump, gzip or plain, loaded after every MANIFEST dump,
    registry name `extra`, never feeding the selection maps. Its objects keep their own `source:`, so a new
    source ranks last.
  - `ROUTECHECK_REALDATA_PAIRS=SEL`: 1-based indices into the `PAIRS:` list, such as `1-20,31`. Only those
    pairs are checked, and the others are logged as `pair i/60: not selected`.
  - `parsePairSelection(s string, n int) (map[int]bool, error)`: `""` selects all n. An empty item, a
    non-number, 0, an index above n, or a reversed range is an error naming the item.

- [ ] **Step 1: Write the failing tests:**
  - `TestParsePairSelection`, table-driven:
    - `""` with n=3 gives {1,2,3};
    - `"1-2,3"` gives {1,2,3};
    - `"2"` gives {2};
    - errors: `"0"`, `"4"` (n=3), `"3-1"`, `"1,,2"`, `"x"`.
  - `TestLoadRegistryExtraDumpRanksLast`: in the style of `TestLoadRegistryPrecedenceAndSelection`
    (`writeGzip`):
    - an extra dump holding an `as-set: AS-NEW` with `source: LEVEL3`, and an `aut-num` with `source: RIPE`;
    - `AS-NEW` is found through `reg.src`;
    - `LEVEL3` is last in `reg.sources`;
    - the extra aut-num is not in `reg.autnums`.

- [ ] **Step 2: Run** `go test -run 'TestParsePairSelection|TestLoadRegistryExtra' .`. Expected: FAIL.

- [ ] **Step 3: Implement.**
  - `loadRegistry` takes the extra file as a separate argument rather than by name.
  - The `registry:` log line names `extra` when one is loaded.
  - Document both env vars in the test's comment.

- [ ] **Step 4: Run** the two tests and then `scripts/check.sh` under the guard. Expected: PASS and `SUCCESS`.

- [ ] **Step 5: Commit**: `realdata: an extra dump and a pair selection (ROUTECHECK_REALDATA_EXTRA, _PAIRS)`.

### Task 3: Look up the missing sets

**Files:**
- Create: `missingsets_test.go` (package `routecheck_test`)

**Interfaces:**
- Consumes:
  - Task 1's `missing-sets.tsv` format;
  - `openRealData` and `realData.dumps` (MANIFEST's dumps), for the held index.
- Produces (in `$ROUTECHECK_MISSINGSETS_DIR`):
  - `cache/radb/<name>.txt`, `cache/ripe/<name>.txt` and `cache/ripe-obj/<name>.txt`: raw answers.
  - `queries.log`: `RFC3339 time\tservice\tquery\tbytes\terror`, appended.
  - `sets.tsv`: `set\tclass\tsub\tcopies\tdeleted\tin_b`. The `sub` values are `unloaded source`,
    `loaded source, not in its dump`, `newer than the dumps`, `undated` or empty. `copies` lists
    `SOURCE@YYYY-MM-DD` (or `SOURCE@undated`), `;`-joined, and `in_b` is `yes` or `no`.
  - `extra.db.gz`: every copy whose date passes the rule, as returned, separated by blank lines.
- Types:
  - `type setLookup struct{ Set, Class, Sub, Copies, Deleted string; InB bool }`, one row of `sets.tsv`;
  - `readSets(path string) (map[string]setLookup, error)`, keyed by the case-folded `Set`.
- Functions (signatures fixed; bodies the implementer's):
  - `whoisQuery(ctx context.Context, dial func(ctx context.Context, network, addr string) (net.Conn, error), addr, query string) (string, error)`:
    - one connection, writes `query+"\r\n"`, reads to EOF;
    - 30 s deadline, and an answer over 4 MiB is an error.
  - `radbQuery(ref types.SetRef) string`:
    - `-r -s <sources> -T as-set,route-set,filter-set,peering-set,rtr-set <name>`;
    - `<sources>` is the Global Constraints list, or the ref's own source when it is scoped.
  - `ripeQuery(ref types.SetRef) string`: `--list-versions -T <class> <name>`, with the class from
    `SetName.Class()`. `ripeObjQuery` is `-r -B -T <class> <name>`.
  - `parseRADB(text string) (objs []string, kind string)`:
    - `found` when it holds an object whose class line names the set (case-insensitive);
    - `none` when it holds `No entries found` and no object;
    - `bad` otherwise.
  - `parseRIPEHistory(text string) (kind, deleted string)`:
    - `deleted` with the date from `% This object was deleted on <RFC3339>` (as YYYY-MM-DD);
    - `none` on `%ERROR:101: no entries found`;
    - `exists` on a version table;
    - `bad` otherwise.
  - `objectDate(obj string) (date string, ok bool)`: the newest of `last-modified:`, `created:` (both
    ISO 8601) and `changed:` (`… YYYYMMDD`).
  - `classifySet(held bool, radb string, radbObjs []string, ripe, ripeDeleted string, ripeObjs []string) setLookup`, applying
    the spec's rules and "found wins".
  - `cacheName(ref string) string`: an injective, case-folded, filesystem-safe name (`:` and `/` escaped).
- Entry: `TestMissingSetsLookup`.
  - It skips unless `ROUTECHECK_MISSINGSETS_LIVE=1`, and needs `ROUTECHECK_MISSINGSETS_DIR`,
    `ROUTECHECK_MISSINGSETS_IN` (comma-separated `missing-sets.tsv` files, all rounds so far) and
    `ROUTECHECK_REALDATA`.
  - It looks up every set not already in the cache, and writes `sets.tsv` and `extra.db.gz` from the whole
    cache.
  - When the cap would be passed, the rest are `not looked up`. It logs the counts per class and sub,
    queries made this run and in total, and undated copies.
- The held index scans each loaded dump's lines for
  `^(as-set|route-set|filter-set|peering-set|rtr-set):\s*NAME` (case-insensitive), keeping the name and
  the object's `source:`.

- [ ] **Step 1: Write the failing tests**, all offline:
  - `TestParseRADB`: the observed none text `%  No entries found for the selected source(s).` gives
    `none`; an `as-set: AS-X` object gives `found`; `""` gives `bad`.
  - `TestParseRIPEHistory`:
    - `% This object was deleted on 2024-02-09T21:50:56Z` gives `deleted 2024-02-09`;
    - `%ERROR:101: no entries found` gives `none`;
    - banner-only text gives `bad` (the AS-ISPSERVICES answer of 2026-10-19).
  - `TestObjectDate`: `created: 2020-01-01T00:00:00Z` with `last-modified: 2026-10-19T…` gives
    `2026-10-19`; `changed: a@b 20190305` gives `2019-03-05`; none gives `ok=false`.
  - `TestClassifySet`, table-driven, one row per class:
    - held;
    - found in LEVEL3, dated 2023 (`unloaded source`, in_b yes);
    - found in RADB, dated 2026-10-19 (`newer than the dumps`, in_b no);
    - RADB none plus RIPE deleted (`deleted`);
    - none plus none (`not found`);
    - none plus bad (`inconclusive`);
    - found plus bad (`elsewhere`: found wins).
  - `TestLookupScoped`: `radbQuery` of `RIPE::AS-X` uses `-s RIPE`, and an `AS-X` held with source RADB
    does not make `RIPE::AS-X` held.
  - `TestWhoisCutShort`: a localhost server that closes after half an answer, or sends nothing, makes the
    lookup `inconclusive` after exactly one retry. Count the connections.
  - `TestCacheName`: `AS1:AS-X:AS2` and `as1:as-x:as2` map to one name, `AS-A/B` stays distinct from
    `AS-A:B`, and names round-trip through a temp dir.
  - `TestQueryCap`: with a cap of 2 and 3 sets, the third is `not looked up`, and `queries.log` has 2
    lines (inject the cap and the dialer).

- [ ] **Step 2: Run** `go test -run 'TestParseRADB|TestParseRIPEHistory|TestObjectDate|TestClassifySet|TestLookupScoped|TestWhoisCutShort|TestCacheName|TestQueryCap' .`.
  Expected: FAIL.

- [ ] **Step 3: Implement**, with no goroutines in the lookup loop: services are queried in turn, one
  connection at a time. The retry waits 5 s.

- [ ] **Step 4: Run** the same tests and then `scripts/check.sh` under the guard. Expected: PASS and `SUCCESS`.
  `TestMissingSetsLookup` skips.

- [ ] **Step 5: Commit**: `missing sets: live lookup, cached and capped (opt-in)`.

### Task 4: Classify the tracked routes

**Files:**
- Modify: `missingsets_test.go`

**Interfaces:**
- Consumes:
  - Task 1's TSV line and `tracked.tsv`;
  - Task 3's `sets.tsv` and `setLookup`.
- Produces:
  - `type trackedLine struct{ Key, Outcome, Detail string; Sets []string }` and
    `readTracked(path string) ([]trackedLine, error)`.
  - `classifyRoute(b trackedLine, sets map[string]setLookup) (class, reason string)`, per the Global
    Constraints' order:
    - `unevaluable in B` is an `undecided` outcome whose Detail holds `unevaluable`;
    - a set absent from `sets` counts as `set not looked up`;
    - `newer set` is an `elsewhere` set with InB false;
    - `found set still missing in B` is a set with InB true.
  - `mergeTracked(files ...[]trackedLine) ([]trackedLine, error)`: per key, a non-`none` outcome beats
    `none`; two different non-`none` lines are an error naming the key.
  - `TestMissingSetsClassify`:
    - it skips unless `ROUTECHECK_MISSINGSETS_DIR` is set;
    - it reads `sets.tsv`, `ROUTECHECK_MISSINGSETS_TRACKED` (comma-separated tracked.tsv files) and
      `ROUTECHECK_MISSINGSETS_SUBSET` (comma-separated `AS<L>-AS<X>` pairs);
    - it logs one table per direction for all tracked routes and for the subset: the classes, the unknown
      reasons, and each sum checked against its total (an unequal sum fails);
    - it writes `routes.tsv` (`key\tclass\treason`).

- [ ] **Step 1: Write the failing tests:**
  - `TestClassifyRoute`, table-driven:
    - accepted gives `gap`;
    - rejected with no sets gives `real`;
    - rejected naming a deleted and a not-found set gives `real for any IRR filter`;
    - one row per unknown reason, including a route that has two reasons and gets the earlier one;
    - `none` gives `no verdict in B`.
  - `TestMergeTracked`: `none` + `accepted` gives `accepted`; `accepted` + `rejected` is an error.

- [ ] **Step 2: Run** `go test -run 'TestClassifyRoute|TestMergeTracked' .`. Expected: FAIL.

- [ ] **Step 3: Implement.**

- [ ] **Step 4: Run** the tests and then `scripts/check.sh` under the guard. Expected: PASS and `SUCCESS`.

- [ ] **Step 5: Commit**: `missing sets: classify the tracked routes`.

### Task 5: Measure and publish (controller)

**Files:**
- Create (git-ignored): `.data/missing-sets-rounds.zsh`, and logs under `.data/`
- Modify: `docs/routecheck.md` (Known limitations: replace "which of the newly rejected routes would be
  accepted if the missing sets existed" in **Not measured**), `CHANGELOG.md` (`[Unreleased]`,
  `### Measured, missing sets`), `CLAUDE.md` (the real-data env vars)

- [ ] **Step 1: Smoke the live queries.** Look up the five sets the spec names (`AS-ISPSERVICES`,
  `AS-STEFFANN-IPV4`, `AS44477:AS-DOWNSTREAMS`, `AS-INFRASIO`, `AS-3DATA-S21`) through
  `TestMissingSetsLookup`, with a hand-made `missing-sets.tsv`. Expected: `AS-STEFFANN-IPV4` is `deleted 2024-02-09`.
  Read every raw answer. If a query form is refused by the server (`-T` list, `--list-versions -T`), fix
  Task 3's query and its test before going on.
- [ ] **Step 2: Run A** under the guard: `ROUTECHECK_REALDATA_OUT=.data/missing-sets/A`, log
  `.data/missing-sets-A.log`. Expected: PASS. Its TOTALS equal `.data/realdata-max-prefixes.log`'s
  (808 export and 1 import distinct missing sets). The number of lines in `rejected-missing.tsv` equals
  the summed "rejected with a missing set" counts (106,526 export plus import).
- [ ] **Step 3: Rounds.** Round k = 1..5:
  1. lookup (IN = every round's `missing-sets.tsv` so far);
  2. run B_k with EXTRA = `extra.db.gz`, TRACK = A's `rejected-missing.tsv` and OUT = `B<k>/`;
  3. new names = B_k's missing sets less every set looked up.

  Stop when there are no new names, the cap is hit, or k = 5, and say which. If the guard stops a B
  run, rerun it in shards (`ROUTECHECK_REALDATA_PAIRS`) one at a time. Log each round to
  `.data/missing-sets-round<k>.log`.
- [ ] **Step 4: Classify** with the last B's tracked files and SUBSET = the 10 pairs
  `1 2 10 15 21 24 30 32 33 53`, mapped to their `AS<L>-AS<X>` ids through A's `PAIRS:` line. Log to
  `.data/missing-sets-classify.log`. Hand-check one route of each class against the raw answers and B's log.
- [ ] **Step 5: Docs.** Replace the not-measured line with the measured answer: route classes for all and for
  the 59,395, unknown reasons, set classes, rounds, queries, the caveat about route objects in unloaded
  sources, and each log. Add the CHANGELOG Measured section and the CLAUDE.md env bullets. Run
  `scripts/check.sh` under the guard. Expected: `SUCCESS`.
- [ ] **Step 6: Commit**: `docs: the missing-sets measurement`.
