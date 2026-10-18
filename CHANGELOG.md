# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the module follows [Semantic Versioning](https://semver.org/): until v1.0.0,
a minor version may change the API.

## [Unreleased]

### Changed

- Requires rpsl v0.30.0 (`rpsl`, `rpsl/types`, `rpsl/resolve`; `ast` and
  `lexer` indirect at v0.30.0). mrt stays at v0.1.0.
- An AS-path regexp that names a set reaching AS-ANY (an as-set whose
  `members:` is `AS-ANY`) is now evaluated. rpsl's peval gives the set as a
  `resolve.ASNSet` whose `Any()` is true, and in a regexp it matches any one
  AS. In 0.1.0 such a policy was an "unevaluable" report with every route
  Undecided.
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
| Wall time | 3m7s, of which the checks took 29s |
| Memory guard | peak RSS 4234 MB, 188 s |
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

[Unreleased]: https://github.com/rkolesnichenko/routecheck/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/rkolesnichenko/routecheck/releases/tag/v0.1.0
