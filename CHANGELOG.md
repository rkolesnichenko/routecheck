# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the module follows [Semantic Versioning](https://semver.org/): until v1.0.0,
a minor version may change the API.

## [Unreleased]

### Changed

- `scripts/fetch-data.sh` now fetches everything: RIPE, then 15 more IRR
  registries, then the RIBs and the VRPs. Every registry is required: one that
  still fails after its retries stops the script before `MANIFEST` is written,
  and a rerun fetches only what is missing. `--registries` adds the 15 to an
  existing pinned `MANIFEST` without touching its pinned lines. The registries
  are APNIC, ARIN, AFRINIC, LACNIC, RADB and RADB's
  mirrors altdb, bboi, bell, canarie, jpirr, nestegg, nttcom, panix, reach and
  tc, from the URLs of rpsl's `scripts/fetch-irr-dumps.sh`. The script's header lists the files and
  the precedence order.
- `TestRealData` loads every registry the `MANIFEST` pins, in that precedence
  order (RIPE, APNIC, ARIN, AFRINIC, LACNIC, RADB, then the mirrors), where it
  loaded RIPE alone. It still picks the pairs from RIPE's files only, so
  loading more registries changes what the checks resolve, never which pairs
  are checked.
  - `ROUTECHECK_REALDATA_REGISTRIES` (comma-separated registry names; empty
    means every pinned registry) loads only those. `ripe` reproduces 0.2.0's
    load.
  - `ROUTECHECK_REALDATA_LOAD_ONLY=1` loads the registries, logs a `LOAD:` line
    and stops before the RIBs.
  - The test now also tallies the missing sets left (distinct, per direction)
    and, for each direction, the route-object answers (yes, no, unknown).
  - The benchmarks load every pinned registry too. Set
    `ROUTECHECK_REALDATA_REGISTRIES=ripe` to compare them with 0.2.0's figures.

### Measured

These figures come from runs of 2026-10-18 on the same pinned files as 0.2.0's
(RIPE's 9 split files, route-views2's RIB of 2026-10-18 12:00, rrc00's bview of
2026-10-18 08:00 and NTT's VRPs), plus the 15 other registries fetched on
2026-10-18 (`.data/fetch-registries.log`). They ran under the memory guard with
an 8 GB cap at normal priority, with `GOMAXPROCS=4`, `GOMEMLIMIT=6GiB` and
`GOWORK=off`. The logs are kept by the maintainer and are not committed.

#### Loading the registries (`.data/load-ripe.log`, `.data/load-all.log`, `.data/every-registry-loads-summary.log`)

| | RIPE alone | all 16 registries |
|---|---|---|
| Objects | 659,819 | 4,866,879 |
| Load time | 7.468 s | 35.871 s |
| Heap in use after GC | 612 MB | 1,864 MB |
| Peak RSS | 1,130 MB | 3,534 MB |

- **Objects per source:** RIPE 659,819, APNIC 1,982,793, ARIN 221,880, AFRINIC
  132,775, LACNIC 25,879, RADB 1,370,610, ALTDB 40,777, BBOI 1,685, BELL
  29,521, CANARIE 1,888, JPIRR 16,526, NESTEGG 4, NTTCOM 292,911, PANIX 15,
  REACH 18,028, TC 71,768.
- **Source order** in the `LOAD:` line is the precedence order: RIPE, APNIC,
  ARIN, AFRINIC, LACNIC, RADB, ALTDB, BBOI, BELL, CANARIE, JPIRR, NESTEGG,
  NTTCOM, PANIX, REACH, TC. No `-NONAUTH` source occurs in any dump.
- **RPKI filtering.** rpsl's CLAUDE.md records RADB's and NTT's dumps as
  RPKI-filtered (invalid route objects removed), and the other mirrors on RADB's
  FTP as not, so the route-object figures below depend on which dump is loaded.

#### The memory gate (`.data/every-registry-gate.log`)

The projection for the every-registry run was 4,234 + (3,534 - 1,130) =
6,638 MB (0.2.0's peak RSS plus the extra load), over the 6,144 MB rule for
running it. The maintainer decided to run it anyway, under the unchanged guard
(8 GB cap). The run's peak RSS was 6,215 MB, at memory-pressure level 1 and
with swap growing by 0 MB.

#### `TestRealData`, RIPE alone and every registry

The sample is the same 60 pairs as 0.2.0's: the PAIRS lines of both runs are
identical and equal 0.2.0's (`.data/every-registry-checks.log`, step 6).

| | RIPE only (`.data/realdata-ripe-only.log`) | every registry (`.data/realdata-every-registry.log`) |
|---|---|---|
| Outcome | PASS: 60 of 60 pairs checked | PASS: 50 of 60 pairs checked; 10 set too large |
| Wall time | 3m31s, of which the checks took 29 s | 3m25s, of which the checks took 21 s |
| Peak RSS | 4,741 MB | 6,215 MB |

With `ROUTECHECK_REALDATA_REGISTRIES=ripe`, every TOTALS figure equals 0.2.0's
run (`.data/realdata-v0.2.log`) except the wall time and the slowest pair's
time.

**The 10 pairs over rpsl's default `MaxPrefixes` (1,048,576).** Each has at
least one filter whose set expansion passes the limit once every registry
resolves its sets (the table gives the first filter the check reached), so
peval returns a `*resolve.SetTooLargeError` and the test counts the pair as
"set too large". RIPE alone gives none. 8 are in X's export toward a large
neighbour (AS174, AS1299, AS1273, AS9121; pairs 1, 2, 10, 21, 24, 30, 32 and 33), for example AS6762's
`export: to AS174 announce AS-SEABONE`. 2 are in L's import (pairs 15 and 53),
for example AS44032's `import: from AS15645 accept AS-UAIX`
(`.data/over-limit-terms.log`, made by `.data/policy-lines.sh` from RIPE's
aut-num dump). A pair's name ("import, L from X") is its label, not where the
over-limit filter is.

| pair | set | expansion reached |
|---|---|---|
| 1 | AS-DELTA | 1,048,663 |
| 2 | AS-SEABONE | 1,048,960 |
| 10 and 33 | AS34984:AS-TELLCOM | 1,049,089 |
| 15 | AS-UAIX | 1,048,718 |
| 21 | AS-MF-MGSM | 1,049,165 |
| 24 | AS-TTK | 1,048,583 |
| 30 | AS-RTD | 1,048,694 |
| 32 | AS-ORANGERO | 1,048,694 |
| 53 | AS-DECIX AND NOT <...> | 1,053,142 |

**The comparison on the same 50 pairs** (`.data/same-pairs.log`, made by
`same-pairs.py` from the per-pair lines of the two logs). The parser reproduces
the RIPE-only log's TOTALS when run on that log alone. The comparison covers
the 50 pairs both runs checked.

| same 50 pairs | RIPE only | every registry |
|---|---|---|
| Observations | 2,640,901 | 2,640,901 |
| Import accepted / rejected / undecided | 2,108,348 / 146 / 0 | 2,108,348 / 146 / 0 |
| Export accepted / rejected / undecided | 2,591,904 / 47,522 / 225 | 2,592,840 / 47,317 / 225 |
| Export rejected with a missing set | 47,236 | 47,131 |
| X's export neighbour reports, with a policy | 1,249, 279 | 1,249, 285 |
| Decided export routes | 2,639,651 | 2,640,382 |
| L's observations with a route-object answer | 528,974 of 2,108,128 | 1,568,538 of 2,108,128 |

- **The premise did not hold.** The design expected most of 0.2.0's export
  rejections to be an artifact of loading RIPE alone. On the 50 pairs both runs
  checked, loading every registry changes the export rejections from 47,522 to
  47,317, under 1%. The rejections that remain mostly name sets no loaded
  registry holds.
- **Where 0.2.0's rejections were.** 341,891 of its 389,413 export rejections
  (389,413 - 47,522) are in the 10 pairs the every-registry run could not
  check.
- **By pair.** Export rejections fell in 17 of the 50 pairs and rose in one:
  AS31270 from AS25577, 30 to 37, with a missing set both times. In that pair 5
  of X's 12 no-policy reports gained a policy (12 to 7 of 30); the mechanism was
  not measured.
- **The export denominator moved.** X's neighbour reports are 1,249 in both
  runs, but those with a policy went from 279 to 285, so 731 more export routes
  were decided (2,639,651 to 2,640,382; `.data/same-pairs-v2.log`).
- **Route objects change the most.** L's observations with a route-object
  answer rose from 528,974 to 1,568,538 of 2,108,128 on the same pairs. The
  denominator is yes + no; L's observations are 2,108,494, of which 366 are
  unknown.

**Every-registry TOTALS over the 50 pairs it checked**
(`.data/realdata-every-registry.log`):

- import 2,108,348 accepted, 146 rejected, 0 undecided; export 2,592,840
  accepted, 47,317 rejected, 225 undecided;
- rejected with a missing set: 3 on import and 47,131 on export;
- missing sets left: 1 distinct on import and 116 distinct on export;
- route objects: import yes 1,568,538, no 539,590, unknown 366; export yes
  1,888,411, no 751,499, unknown 472;
- the top missing sets on export are AS-ISPSERVICES, AS-STEFFANN-IPV4,
  AS-STEFFANN-IPV6 and AS-TELFORT, at 46,052 routes each. They are one pair's:
  AS200184 from AS1136 holds 46,052 of the 47,317 remaining export rejections
  (`.data/same-pairs-v2.log`).

For comparison, the RIPE-only run over its 60 pairs
(`.data/realdata-ripe-only.log`) leaves 1 distinct missing set on import and
1,245 on export, and has route objects import yes 918,363, no 2,869,144,
unknown 631; export yes 1,197,092, no 3,800,460, unknown 836. These cover 60
pairs, not 50, so they are not comparable with the figures above.

#### Hand checks (`.data/every-registry-checks.log`)

- **The top missing sets are in no registry.** AS-ISPSERVICES,
  AS-STEFFANN-IPV4, AS-STEFFANN-IPV6 and AS-TELFORT are in none of the 32 dumps,
  by a line-based grep (`grep-sets.sh`). The control works: the same grep finds
  AS1887:AS-PEERINGS:AS8501 and AS-SEABONE once each, in RIPE. RIPE objects name
  these sets, but no registry loaded holds them.
- **A route-level check with the command itself** (`.data/handcheck-AS29632-ripe.log`,
  `.data/handcheck-AS29632-all.log`). The command was
  `routecheck -peer AS29632 -collector <AS29632's filtered RIB> -direction export -af ipv4 -routes rejected`,
  with RIPE's 9 dumps and then with all 32 in precedence order. It reproduces
  the test's figures for that pair: export rejections 34 with RIPE alone, 2
  with every registry.
  - The change is all in "export, AS29632 to AS33891"
    (`to AS33891 announce AS-NETASSIST`): 32 routes rejected, then 0.
  - All 32 routes have origin AS48031. AFRINIC and RADB each hold a route object
    for all 32; no other dump, RIPE's included, holds any
    (`.data/as33891-route-objects-v2.log`, made by `route-objects.sh`).
  - So with RIPE alone, no expansion of AS-NETASSIST could have contained them.
    They were counted as rejected with a missing set in the failing clause only
    because that clause also named missing sets. The tag names a clause's
    missing sets; it does not say a missing set caused the rejection.
  - Peak RSS: 1,356 MB with RIPE's dumps, 3,585 MB with all 32.

## [0.2.1] - 2026-10-18

### Changed

- The text output's report-block line for routes accepted through a set
  reaching AS-ANY gives the count in parentheses:
  `accepted through a set reaching AS-ANY (any AS): AS1887:AS-PEERINGS:AS8501 (2 routes)`,
  where 0.2.0 wrote `..., 2 routes`. The count is of routes, each once however
  many of the sets it names. The JSON output is unchanged.

## [0.2.0] - 2026-10-18

### Changed

- Requires rpsl v0.30.0 (`rpsl`, `rpsl/types`, `rpsl/resolve`; `ast` and
  `lexer` indirect at v0.30.0). mrt stays at v0.1.0.
- An AS-path regexp that names a set reaching AS-ANY (an as-set that reaches
  `AS-ANY`, directly or through nested sets) is now evaluated. rpsl's peval
  gives the set as a `resolve.ASNSet` whose `Any()` is true, and in a regexp it
  matches any one AS. In 0.1.0 such a policy was an "unevaluable" report with
  every route Undecided.
- `Report.Unevaluable` and the `unevaluable` reason (rulings R19, R21) now arise
  only from AS-ANY or RS-ANY in filter position (`accept AS-X`, `NOT AS-X`),
  which rpsl still refuses to expand.
- `pathre` needs no code change: it asks only `Has`, which is true for every AS
  of such a set. Its first oracle, `pathre/testdata/routemodel-vectors.jsonl`,
  is regenerated from rpsl's `routemodel` in format version 2, which names the
  sets reaching AS-ANY in `any_sets`; the reader refuses any other version. The
  second oracle's generator also names such a set (`AS-ALL`).
- The JSON output has one more key in every verdict, `"AnySets"` (see Added).

### Added

- `verdict.Verdict.AnySets`: on an Accepted verdict, the canonical names,
  sorted and deduplicated, of the sets reaching AS-ANY that the AS-path tests
  (either polarity) of the accepting conjunct name. It is nil otherwise, and
  always nil on Rejected and Undecided. The text output appends
  `(X reaches AS-ANY: any AS)`, or `(X, Y reach AS-ANY: any AS)`, to
  `accepted by clause N`, before any "after undecided" part. The JSON field is
  `"AnySets"`, `null` when there are none.
- The text output's report block has one more line when some accepted routes
  name a set reaching AS-ANY, whatever `-routes` asks for: the sets and the
  number of those routes, such as
  `accepted through a set reaching AS-ANY (any AS): AS1887:AS-PEERINGS:AS8501, 2 routes`.
- The real-data test counts, per direction, the accepted routes whose
  `AnySets` is not empty, and lists them by report and set.

### Measured

These figures come from runs of 2026-10-18 on an Apple M3 Max (darwin/arm64)
with go1.27.2 (`.data/goversion-v0.2.log`), `GOMAXPROCS=4`, `GOMEMLIMIT=6GiB`
and `GOWORK=off`, under the memory guard with an 8 GB cap at normal priority.
The logs are kept by the maintainer and are not committed.

The data was fetched again on 2026-10-18, so these figures are not compared one
to one with 0.1.0's:

- RIPE's split dumps (9 files), fetched 2026-10-18;
- route-views2's RIB of 2026-10-18 12:00;
- RIS rrc00's bview of 2026-10-18 08:00;
- NTT's VRP export, fetched 2026-10-18.

#### `TestRealData`, 60 pairs (`.data/realdata-v0.2.log`)

The sample, by the same seed as 0.1.0's, was again 50 aut-nums with a literal
`import: from X`, plus 10 more whose import from X has an AS-path regexp.

| | |
|---|---|
| Outcome | PASS: 60 of 60 pairs checked; 0 timed out, 0 over a set limit, 0 other errors |
| Wall time | 3m7s, of which the checks took 29s (the test's own TOTALS) |
| Memory guard | peak RSS 4234 MB, 188 s (the guard's figures, over the whole `go test` command) |
| Go heap in use | peak 3055 MB, the highest of the test's per-pair samples (after pair 2, AS9086 from AS6762) |
| Registry | 659,819 objects, 40,036 aut-nums, loaded in 7.4 s |
| RIB entries read | 73,145,509, with 0 malformed entries and 0 record errors |
| Observations | 4,540,048 (family × pair) |

Decisions:

| direction | accepted | rejected | undecided | no policy |
|---|---|---|---|---|
| Import | 3,787,992 | 146 | 0 | 49 families |
| Export (1,587 neighbour reports) | 4,608,749 | 389,413 | 226 | 1,182 reports |

- **Unevaluable reports:** 0 (0 routes).
- **Accepted with `AnySets`:** 2 routes on import, 0 on export, from one
  (report, set) pair: AS8308's ipv4 import from AS1887, through its clause
  `accept <AS1887:AS-Peerings:AS8501$>`, with `AnySets`
  `["AS1887:AS-PEERINGS:AS8501"]`. That report's other 37 routes were accepted
  by the clause before it, `accept <AS1887:AS-Customers:AS-Received$>`. This is
  the report that was unevaluable in 0.1.0.
- **Undecided reasons.** Import: none. Export: `peval: peer router not given`,
  226.
- **Missing sets.** Rejected routes whose failing clause names a set missing
  from RIPE: 3 on import and 389,127 on export.
- **Other figures.** 0 `path-too-expensive` verdicts over 640 routes decided
  under a policy with an AS-path test. 326,034 `OriginatedRoutes` reads for
  326,034 distinct (origin, family). The largest import prefix filter was
  415,768 ranges (AS42861 from AS6695, ipv4).
- **Speed.** The checks took 29 s here against 3m0s in 0.1.0, and the largest,
  AS9086 from AS6762, 8.7 s against 61 s. 0.1.0's published command did not ask
  the guard for normal priority, and the guard otherwise runs the command at
  background priority, which is the likely cause. That was not measured.
- **Memory.** 0.1.0's run was at the guard's background priority, so its peak
  RSS (2607 MB) is not comparable with this run's. The Go heap in use, sampled
  the same way after each pair, peaked at 3307 MB in 0.1.0's run
  (`.data/realdata-r19.log`) and at 3055 MB in this one.

#### Hand check, AS8308 from AS1887 (`.data/handcheck-AS8308-v0.2.log`)

The command was run in collector mode on both RIBs, with RIPE's dumps and the
VRPs: `-local AS8308 -peer AS1887 -af ipv4 -direction import -routes all`.

- Exit status 0. Peak RSS 1496 MB, 51 s.
- `import, AS8308 from AS1887: 39 routes: 39 accepted, 0 rejected, 0 undecided`.
  The test's log gives the same counts for that report.
- 2 of the 39 route lines read
  `accepted by clause 2 (AS1887:AS-PEERINGS:AS8501 reaches AS-ANY: any AS)`:
  148.81.248.0/24 and 195.187.76.0/24. The other 37 read
  `accepted by clause 1`.
- The JSON run of the same command (`.data/handcheck-AS8308-v0.2.json`) gives
  `"AnySets": ["AS1887:AS-PEERINGS:AS8501"]` on those 2 routes and
  `"AnySets": null` on the other 37.

## [0.1.0] - 2026-10-17

First version. It requires rpsl v0.29.0 (`rpsl`,
`rpsl/types`, `rpsl/resolve`) and mrt v0.1.0.

### Added

- `pathre`: an AS-path regular-expression matcher for real paths, under RFC 2622
  section 5.4 (`Match`, `MatchWith`).
  - It works on position sets with no backtracking, and has a work budget
    (`MatchOptions.MaxWork`, `DefaultMaxWork` = 10,000,000 steps).
    `ErrTooExpensive` past the budget.
  - `ErrNotSingleAS` for a same-AS repetition over more than one AS.
  - `ErrUnbound` for an unbound PeerAS.
  - Checked against two oracles:
    - 20,000+ vectors written by rpsl's `routemodel` (rpsl commit
      `bbe2c4b52886e41d9ca5ee975fe1dc46f50d67fc`, merged into rpsl's `main` in PR #35);
    - an in-repo translation to Go's `regexp` over AS tokens.
- `verdict`: one route against one `peval.Policy`.
  - Every test is three-valued.
  - The outcome is Accepted (the first clause that matched, with the undecided
    clauses and terms before it), Rejected (per clause, the first failing test
    and the sets missing from the registry), or Undecided (every reason).
  - `Compile` builds a prefix index once per clause and a path memo capped at
    64 MiB of keys.
  - Checked by:
    - table tests;
    - a model test against a naive evaluator;
    - a differential against bgpq4 on rpsl's fixed snapshot.
- `observe`: MRT records to routes as X announced them.
  - Session mode replays X's Adj-RIB-Out toward L: add-path, `-at`,
    re-establishment, and RFC 7606 treat-as-withdraw and session reset.
  - Collector mode cuts every path through X to X's own part. It keeps the
    neighbour, the direct-feed flag and the count of collector peers, and
    deduplicates by (prefix, suffix path).
- `hygiene`: the RPKI origin-validation state, and whether a route object
  exists, read once per (origin, family).
- `routecheck.Checker.Check`: both directions per address family. In collector
  mode, the export direction gives one report per neighbour. `ErrOptions` is
  returned for options the library refuses. `Report.Unevaluable` and the
  `unevaluable` reason cover a policy whose AS-path set reaches AS-ANY.
- `cmd/routecheck`: session and collector modes; `-dump` or `-irrd`; a
  `-policy` draft; `-vrps`; text and JSON output. Exit status:
  - 0: nothing Rejected;
  - 1: some route Rejected;
  - 2: a bad command line;
  - 3: could not complete, including a session-mode capture that holds no
    record of a session with X (`observe.SessionInfo.Selected` is 0), which
    is not read as "X announced nothing" (without `-local` such a capture
    names no local AS either, and the run stops earlier with exit 2, saying so).

  A `-local` that is not the capture's local AS is checked as given, with a
  warning.

  See docs/routecheck.md, which also says which OpenBGPD, BIRD 2 and GoBGP MRT
  dumps qualify for `-session`.
- Tooling:
  - `scripts/check.sh`: gofmt, build, vet, `-race` tests, coverage, no `net`
    outside the CLI, no home-directory path, the go.mod requirements, the API
    golden, staticcheck and govulncheck;
  - `scripts/fuzz.sh`, with three targets: FuzzMatch, FuzzDecide and FuzzObserve;
  - `scripts/fetch-data.sh` and `scripts/release.sh`;
  - CI with a `ci ok` job.

### Measured

These figures come from runs of 2026-10-17 on an Apple M3 Max (darwin/arm64)
with `GOMAXPROCS=4`, `GOMEMLIMIT=6GiB` and `GOWORK=off`, each under a memory
guard with an 8 GB cap. The logs are kept by the maintainer and are not
committed; each figure below names its log. The Go version of those runs is not
recorded in the logs.

The real-data inputs were:

- RIPE's split dumps (9 files);
- route-views2's RIB of 2026-10-16 22:00;
- RIS rrc00's bview of 2026-10-16 16:00;
- NTT's VRP export.

#### `TestRealData`, 60 pairs (`.data/realdata-r19.log`)

The sample was 50 seeded aut-nums with a literal `import: from X`, plus 10 more
whose import from X has an AS-path regexp. Each pair was checked in collector
mode, both directions, ipv4 and ipv6 unicast.

| | |
|---|---|
| Outcome | PASS: 60 of 60 pairs checked; 0 timed out, 0 over a set limit, 0 other errors |
| Wall time | 15m8s, of which the checks took 3m0s |
| Memory guard | peak RSS 2607 MB, 909 s |
| Registry | 659,741 objects, 40,036 aut-nums, loaded in 39.6 s |
| RIB entries read | 72,086,485, with 0 malformed entries and 0 record errors |
| Observations | 4,542,273 (family × pair) |

Decisions:

| direction | accepted | rejected | undecided | no policy |
|---|---|---|---|---|
| Import | 3,788,674 | 146 | 39 | 49 families |
| Export (1,577 neighbour reports) | 4,610,986 | 391,010 | 227 | 1,171 reports |

- **Undecided reasons.**
  - Import: `unevaluable`, 39. That is one report: AS8308's import from AS1887,
    whose regexp names `AS1887:AS-Peerings:AS8501`, and that set's `members:`
    is AS-ANY.
  - Export: `peval: peer router not given`, 227.
- **Missing sets.** Rejected routes whose failing clause names a set missing
  from RIPE: 3 on import and 390,727 on export.
- **Largest single check.** AS9086 from AS6762 took 61–69 s across the runs:
  - 1m1.176s (`.data/realdata-r19.log`);
  - 1m4.129s (`.data/realdata.log`);
  - 1m8.37s (`.data/realdata-run1.log`);
  - 1m9.09s (`.data/realdata-smoke.log`).
- **Hygiene.** 325,883 `OriginatedRoutes` reads for 325,883 distinct (origin,
  family): one read each.
- **pathre work budget.** 0 `path-too-expensive` verdicts, over 605 routes
  decided under a policy with an AS-path test. Coverage of regexps is thin:
  - only 69 RIPE aut-nums have an AS-path regexp toward a literal peer;
  - the two benchmarks below decide regexp-bearing policies, but count no
    reasons.
- **Path memo.** The largest bound on its keys in the run is 996 bytes (AS1887
  export to AS8501, ipv4: 3 path tests × 25 distinct paths). The benchmarks'
  bound is 2,983,392 bytes, for one path test over AS1299's 1,107,522 ipv4
  routes (`.data/bench-decide.log`). The cap is 64 MiB (67,108,864 bytes), so
  both are far below it. How the memo behaves for a policy with many path tests
  against a full table is unknown: no such pair was in the sample.

#### Full IPv4 table, collector mode (`.data/fullrun-AS3303.log`)

The command was run with these inputs:

- L: AS8763;
- X: AS3303, a route-views2 direct full-table peer;
- `-af ipv4 -direction both`;
- route-views2's RIB;
- RIPE's dumps and the VRPs.

| | |
|---|---|
| Wall time | 178.96 s |
| Peak RSS | 2197 MB |
| Exit status | 1: routes were Rejected |
| RIB entries read | 17,481,231 |
| Through AS3303 | 1,113,155, of which 1,096,048 on its own feed |
| Import routes | 1,096,441: 73,320 accepted, 1,023,121 rejected, 0 undecided |

The import rejections are mostly a missing-sets effect: `AS-SWCMGLOBAL` names
sets outside RIPE (see Known limitations).

#### Benchmarks

| benchmark | policy and input | result | log |
|---|---|---|---|
| `BenchmarkDecide` | AS42861's import from AS6695, ipv4: 415,717 ranges and one AS-path test. Routes: AS1299's 1,107,522 ipv4 routes | **669.8 ns/route**, 41 B/op, 1 alloc/op | `.data/bench-decide.log` |
| `BenchmarkDecide` | AS8657's import from AS1241, `<^AS1241+$>`. Routes: the same | **810.0 ns/route**, 69 B/op, 2 allocs/op | `.data/bench-decide-regexp.log` |
| `BenchmarkCollector` | route-views2's RIB as downloaded (bzip2 included), X = AS1299 | **109.4 s/pass**, 767,760 observations, 3.162 collector peers per observation, 230.2 retained bytes per observation, 11.0 GB and 74.5 M allocations per pass | `.data/bench-collector.log` |

Both `BenchmarkDecide` figures were measured with the routes cycled over `b.N`
and the path memo warm. A real check decides each route once, so its cost per
route can be higher.

### Known limitations

- **AS-ANY in an AS-path set.** A policy whose AS-path set reaches AS-ANY gives
  "unevaluable" (Undecided) routes for that report. The run goes on. This waits
  for rpsl's peval to handle such a term.
- **Load every registry a policy's sets reach.** In the RIPE-only run, 390,727 of
  the 391,010 export rejections named sets RIPE does not hold
  (`.data/realdata-r19.log`). They are reported as "missing from the registry"
  (D4), but they are rejections caused by the data you loaded, not by the policy.
- **Session-mode capture.** No real capture from OpenBGPD, BIRD or GoBGP is in
  the fixtures. Their qualification comes from their manuals (and, for GoBGP,
  its source).
- **Out of scope:** ASPA, BMP and RIS Live, transparent route servers,
  `import-via:`/`export-via:`/`default:`, L's own export, and clause actions.

[Unreleased]: https://github.com/rkolesnichenko/routecheck/compare/v0.2.1...HEAD
[0.2.1]: https://github.com/rkolesnichenko/routecheck/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/rkolesnichenko/routecheck/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/rkolesnichenko/routecheck/releases/tag/v0.1.0
