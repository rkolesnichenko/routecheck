# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the module follows [Semantic Versioning](https://semver.org/): until v1.0.0,
a minor version may change the API.

## [Unreleased]

First version, not yet released. It requires rpsl v0.29.0 (`rpsl`,
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
      `bbe2c4b52886e41d9ca5ee975fe1dc46f50d67fc`, branch `routemodel-vectors`);
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
  - 3: could not complete.

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

[Unreleased]: https://github.com/rkolesnichenko/routecheck/commits/main
