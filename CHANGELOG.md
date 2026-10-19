# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the module follows [Semantic Versioning](https://semver.org/): until v1.0.0,
a minor version may change the API.

## [Unreleased]

### Added (tests only)

- `TestProvenanceCompare` reads a run whose shards interleave (each pair from the shard that checked it).

### Measured, pair 2 in the registry provenance

The registry-provenance comparisons now include pair 2 (AS9086 from AS6762, 2,607,757 routes). R and V are read
as two shards: every pair but 2 (made at 2d5e24a) and pair 2 alone (made at ae7d034, which v0.6.0 showed gives
identical results). The logs are `.data/provenance-AR2.log` and `-AV2.log`. Run first without pair 2, the
extended comparer reproduces the published logs exactly, apart from timing, peak memory and source line numbers. The self-check reproduces 1,568,538.

| | with pair 2 | as first published, without it |
|---|---|---|
| route-object "yes" resting on unverified route objects alone | 2,308,425 of 6,400,790 (36.06%) | 1,660,441 of 4,549,769 (36.50%) |
| export accepted → rejected, A against R | 8,883 (0.18%) | 5,190 (0.15%) |
| export accepted → rejected, A against V | 10,604 (0.21%) | 5,399 (0.16%) |
| the three pairs with the most "yes" answers hold | 80.30% | 90.63% |

- Pair 2's own part is 647,984 of its 1,851,021 "yes" answers (35.01%). That equals v0.5.0's "yes (unverified
  only)" for the same pair.
- Pair 2's 400,748 export routes are unevaluable in A, because AS-SEABONE goes over the limit. Without the
  unverified route objects they are decided: 186,276 accepted and 214,472 rejected in R, and 176,449 and 224,299
  in V. (The comparison's cells are 186,277 and 176,450; each holds 1 limit-effect route from another pair, shown by
  `.data/provenance-AR.log` and `-AV.log` as "unevaluable → accepted 1": 186,277 − 1 = 186,276 and
  176,450 − 1 = 176,449.)
- Every pair-2 rejection fails against missing sets (1,276 distinct in R, 1,039 in V). The missing-sets lookup
  covered most of them: 807 of R's 1,276 and 568 of V's 1,039 were among the 842 looked up; 469 and 471 were not.
  In R, 739 sets are named by all 252,133 rejections, and all 739 were looked up (367 deleted, 347 not found,
  24 found elsewhere, 1 inconclusive: AS-CONCERTAP). In V, 712 sets are named by all 263,472 rejections, 476 of them
  looked up.
- Pair 2 alone holds 1,851,021 of the 6,400,790 "yes" answers (28.92%).
- Not measured: whether the 469 (R) and 471 (V) never-looked-up sets exist anywhere, and whether loading the "found
  elsewhere" sets would flip any of these rejections.

## [0.6.0] - 2026-10-19

### Added

- `Checker.CheckEach` runs the same check as `Check` but hands each finished `Report` to a function and keeps none,
  so a caller can let each report go. The family's `Result` comes with it, complete before its first report. The
  returned `Result`s carry no reports. `Check` is `CheckEach` plus collecting, with the same results as before.

### Changed

- The command and the real-data test take reports through `CheckEach`.
  - The command keeps only each report's rendered output. Its text and JSON output, stderr and exit status are
    byte-identical to v0.5.0, also on failure.
  - The real-data test writes each pair's `routes.tsv.gz` and `rejected-missing.tsv` lines to per-pair temporary
    files, appended only for a pair that was checked. Its per-report work now counts against the per-pair timeout.
- `Coverage.DirectNotChecked` is counted before a family's first report. Its value is unchanged.

### Added (tests only)

- `internal/memprof`, a heap sampler for tests only. The real-data test profiles with it under
  `ROUTECHECK_REALDATA_MEMPROF`, and `TestMemProfileCommand` profiles the command in-process. Neither ships in
  the binary.

### Measured, memory

The memory profile and its findings: `docs/superpowers/specs/2026-10-19-memory-profile-design.md` (the addendum).
After this change, on the 2026-10-18 files, under the memory guard (8 GB cap, `GOMAXPROCS=4`, `GOMEMLIMIT=6GiB`;
MB = MiB):

| run | before | after | log |
|---|---|---|---|
| the command, AS9086 from AS6762, every registry, `-max-prefixes 2097152` | 6,421 MB | 5,959 MB | `.data/stream-cli-2097152.log` |
| the real-data test's 60 pairs, `ROUTECHECK_REALDATA_OUT` | 7,148 MB | 6,635 MB | `.data/stream-A.log` |
| pair 2 alone, route objects from the RIRs only | stopped at 8,255 MB | 5,337 MB | `.data/stream-R2.log` |
| pair 2 alone, the RIRs only | stopped at 8,249 MB | 4,526 MB | `.data/stream-V2.log` |

- Output unchanged: the command's equals the v0.5.0 run's (`.data/verified-counts-2097152.log`, built at 6309e36 on the branch v0.5.0 was released from; the later code change, 13d47d3, validates `-verified-sources` names and moves the route-object note after the session check, and does not touch this collector run). The 60 pairs' TOTALS equal the earlier run's, and so do its
  decompressed `routes.tsv.gz`, `rejected-missing.tsv`, `missing-sets.tsv` and `pairs.tsv`.
- What remains is mostly the heap's room between collections (inferred: the 60-pair run was not profiled; the
  explanation rests on pair 2 alone and the command's profile). Pair 2's live heap is measured only at report
  boundaries (marks, after a forced GC): at most 2,212 MB there, against 4,232 MB before (`.data/memprof/A2`). Its
  in-use heap peaked at 4,359 MB during the first (import) report, 179 s in (`.data/memprof2/A2/series.tsv`).
- The design's targets for the command (5,120 MB) and the 60 pairs (6,144 MB) are not met.

## [0.5.0] - 2026-10-19

### Added

- Each route-object answer says whether a verified registry backs it. By default the verified sources are the
  five RIRs (RIPE, APNIC, ARIN, AFRINIC, LACNIC); `-verified-sources LIST` replaces them (an empty list, an empty
  item or a duplicate is refused with exit status 2). A "yes" that only other registries (by default RADB and its
  mirrors) back reads "yes (unverified only)": weaker evidence, not wrong. Verdicts, filters and exit status do not
  change.
  - The verified sources are those present: loaded with `-dump`, or, with `-irrd`, served (each probed alone at
    startup, within `-sources` when given). One stderr line names them and the absent ones; when none is
    present, the answers are not marked.
  - Library: `Checker.VerifiedRoutes`, `RouteVerdict.RouteObjVerified` (asked only when `RouteObj` is true),
    `Report.RouteObjYes`, `RouteObjUnverifiedOnly` and `RouteObjNo`; `hygiene.Checker.Verified` and
    `VerifiedRouteObject`.

### Changed

- The text report line ends with the route-object counts (`; route objects N yes (M unverified only), K no`; without
  the parenthesis when the answers are not marked), and a route listed by `-routes` reads `route object yes
  (unverified only)` where that applies. The JSON gains `RouteObjVerified` and the three counts.
- Every run that checks routes prints one `routecheck: route objects: ...` line on stderr after the check.
- With `-irrd`, a server that cannot be reached while the verified sources are probed is exit status 3 even when
  the capture would otherwise give a usage error (exit status 2): the probe comes first.

### Measured, verified marking

The command on AS9086 from AS6762, every registry, `-max-prefixes 2097152`, on the 2026-10-18 files, under the
memory guard (8 GB cap, normal priority, `GOMAXPROCS=4`, `GOMEMLIMIT=6GiB`), on the machine of v0.4.0's
figures (`.data/verified-counts-2097152.log`):

| | "yes" | of them unverified only | "no" |
|---|---|---|---|
| AS9086's import (1 report with routes) | 717,629 | 253,107 (35.27%) | 260,560 |
| AS6762's export (55 reports with routes) | 1,133,392 | 394,877 (34.84%) | 495,720 |

- Verdicts equal v0.4.0's (978,368 import routes accepted; export 1,194,673 accepted / 33,968 rejected / 400,748
  undecided over 75 reports).
- Peak RSS 6,421 MB (6,322 MB in a run without the text counts, `.data/verified-cli-2097152.log`; v0.4.0: 6,511 MB).

### Added (tests only)

- The opt-in real-data test writes its missing sets and its rejected routes (`ROUTECHECK_REALDATA_OUT`), tracks a
  given list of routes into a later run (`ROUTECHECK_REALDATA_TRACK`), loads one extra dump last in precedence
  (`ROUTECHECK_REALDATA_EXTRA`) and checks only some of its pairs (`ROUTECHECK_REALDATA_PAIRS`).
- `TestMissingSetsLookup` (opt-in, live, `ROUTECHECK_MISSINGSETS_LIVE=1`) classifies missing sets through
  whois.radb.net and RIPE's version history, cached and capped at 5,000 queries. `TestMissingSetsClassify`
  classifies the tracked routes. The command, the API and go.mod do not change.
- The real-data test keeps route objects only from named registries (`ROUTECHECK_REALDATA_ROUTES_FROM`) and, under
  `ROUTECHECK_REALDATA_OUT`, streams one line per route (`routes.tsv.gz`) and each pair's status (`pairs.tsv`).
  `TestProvenanceCompare` (opt-in, offline) compares two runs route by route.

### Measured, registry provenance

The runs of 2026-10-19, on the pinned 2026-10-18 files, `ROUTECHECK_REALDATA_MAX_PREFIXES=2097152`, the default
sample (60 pairs), under the memory guard (8 GB cap, normal priority, `GOMAXPROCS=4`, `GOMEMLIMIT=6GiB`, one run at
a time). The design is `docs/superpowers/specs/2026-10-19-registry-provenance-design.md`. The logs are kept by the
maintainer and are not committed. "Unverified" is RADB and its ten mirrors; "verified" is the five RIRs (an
assumption: JPIRR is grouped with RADB).

- Run A, every registry (`.data/provenance-A.log`): PASS, 60 of 60. Its TOTALS equal `.data/missing-sets-A.log`'s
  but for timing. Peak RSS 7,148 MB.
- Run R, route objects from the RIRs only (`ROUTECHECK_REALDATA_ROUTES_FROM=ripe,apnic,arin,afrinic,lacnic`):
  - Dropped 1,785,072 route objects: radb 1,341,392, nttcom 291,428, tc 49,767, altdb 36,272, bell 29,362,
    reach 18,021, jpirr 15,680, canarie 1,579, bboi 1,560, panix 9, nestegg 2. Of them, 23,655 were `member-of:`
    claimants.
  - The guard stopped the whole run on pair 2 (AS9086 from AS6762) at 8,224 MB (`.data/provenance-R-stopped.log`),
    and pair 2 alone at 8,255 MB (`.data/provenance-R2.log`). The other 59 pairs passed (`.data/provenance-R1.log`,
    peak 6,202 MB).
- Run V, the RIRs only (`ROUTECHECK_REALDATA_REGISTRIES=ripe,apnic,arin,afrinic,lacnic`): the other 59 pairs passed
  (`.data/provenance-V1.log`, peak 5,046 MB); pair 2 alone was stopped at 8,249 MB (`.data/provenance-V2.log`).
- Pair 2's 2,607,757 routes are therefore "no verdict" in R and V, and are left out of every share below. The likely
  cause, not measured: with fewer route objects its AS-SEABONE expansions may fit under 2,097,152 and be decided,
  costing more memory than giving up (design, settled 1). R2 and V2 were stopped before pair 2 logged a report, and no
  log gives AS-SEABONE's size in R or V.
- A against R (`.data/provenance-AR.log`), over the routes answered in both runs:

  | route-object "yes" in A | resting on unverified route objects alone | share |
  |---|---|---|
  | import 2,102,844 | 764,122 | 36.34% |
  | export 2,446,925 | 896,319 | 36.63% |
  | total 4,549,769 | 1,660,441 | 36.50% |

  - No answer went from "no" to "yes".
  - The RPKI state of the 1,660,441: 1,055,319 valid (63.56%), 605,079 not found, 43 invalid: most of these routes
    are RPKI-valid.
  - The totals-only shortcut, taken over the 59 pairs both runs checked: the denominators are equal (import 2,809,318,
    export 3,369,171) and it agrees with the route-by-route count (import 2,102,844 - 1,338,722 = 764,122, export
    2,446,925 - 1,550,606 = 896,319). Against V it does not apply on export: the denominators differ there (3,369,171
    and 3,368,732), because of the 439 routes whose report loses its policy (`.data/provenance-AV.log`).
  - On the 50 pairs of the every-registry caveat, A reproduces 1,568,538 "yes" answers. Of these, 551,873 (35.18%)
    rest on unverified route objects alone: 53.09% of the rise from 528,974.
- Verdicts:
  - A against R: 5,190 export routes go from accepted to rejected (RPKI 2,888 valid, 2,288 not found, 14 invalid),
    which is 0.15% of the 3,369,730 export routes in both runs. None go from rejected to accepted.
  - A against V (`.data/provenance-AV.log`): 5,399 go from accepted to rejected (3,092 valid, 2,293 not found,
    14 invalid). 439 (432 accepted, 7 rejected) have no verdict, because their report loses its policy.
  - Both comparisons: 3 routes unevaluable in A (2 import, 1 export) are accepted once their sets shrink, a limit
    effect. No other import verdict moves.
- Hand-checked: 44.31.178.0/24 from AS211776 and 81.208.192.0/19 from AS14544 are route objects only in
  `radb.db.gz`. Their answer is "yes" in A and "no" in R, and AS44306's export of each to AS3491 is accepted in A and
  rejected in R.
- The shares are weighted by routes, and this sample is concentrated (`.data/provenance-AR.log`, "concentration"):
  - AS213642-AS3257, AS48354-AS20485 and AS62120-AS1299 hold 4,123,600 of the 4,549,769 "yes" answers in both runs
    (90.63%). Without them, 117,962 of 426,169 become "no" (27.68%).
  - Over the 58 pairs with a "yes" answered in both runs, the median pair's share is 0.00%.
  - 4,910 of the 5,190 moves from accepted to rejected are in one report, AS31133's export to AS31500 (pair
    AS41446-AS31133); 19 pairs have at least one.
- Not measured: pair 2, and why it needs more memory without the unverified route objects; whether any unverified
  object is right; how JPIRR or another mirror verifies.

### Measured, missing sets

The runs of 2026-10-19, on the same pinned 2026-10-18 files, every registry, `ROUTECHECK_REALDATA_MAX_PREFIXES=2097152`,
under the memory guard (8 GB cap, normal priority, `GOMAXPROCS=4`, `GOMEMLIMIT=6GiB`, one run at a time), on the
machine of `.data/max-prefixes-machine.log`. The design is `docs/superpowers/specs/2026-10-19-missing-sets-design.md`.
The logs are kept by the maintainer and are not committed.

- Run A (`.data/missing-sets-A.log`): PASS, 60 of 60 pairs, every TOTALS line equal to
  `.data/realdata-max-prefixes.log`'s. It listed 106,529 routes rejected with a missing set in a failing clause
  (106,526 export + 3 import) and 809 missing sets (808 export + 1 import). Peak RSS 6,991 MB, 280 s (6,565 MB
  before the new outputs, `.data/realdata-max-prefixes.log`).
- Lookup (`.data/missing-sets-round1-lookup.log` to `-round4-lookup.log`, `.data/missing-sets-rounds.log`; the sets'
  classes, copies and dates are in `.data/missing-sets/lookup/sets.tsv`, the queries in `queries.log` beside it):
  - 4 rounds: 809 sets, then 22, 10, 1 and 0 new names after rounds 1 to 4.
  - The 842 sets: 407 deleted, 380 not found, 54 elsewhere, 1 inconclusive, 0 held but refused
    (407 + 380 + 54 + 1 = 842).
  - "Not found" cannot tell "deleted" from "never existed" outside RIPE, the one registry asked that publishes
    history: a set deleted from any other registry reads "not found".
  - Of the 54 found elsewhere, 51 are in a source routecheck does not load (copies: LEVEL3 33, IDNIC 17,
    RIPE-NONAUTH 1) and 3 in a loaded registry but not in its dump (copies: RIPE 2, ARIN 1). The copies are dated
    2014-03-20 to 2026-10-18: none is dated after 2026-10-18 (the design's rule is by day), and none is undated.
    - The two RIPE copies (AS204464:AS-JUSTINFRANKE, AS204464:AS-DOWNSTREAMS) were created on 2026-10-18 at
      03:23:29Z and 03:24:49Z (`.data/missing-sets/lookup/extra.db.gz`), after RIPE's snapshot (its newest
      `last-modified:` is 2026-10-17T21:04:19Z, `.data/realdata/ripe.db.as-set.gz`). 59,397 listed routes name
      AS204464:AS-JUSTINFRANKE (`.data/missing-sets/A/rejected-missing.tsv`); B still rejected them with both loaded.
    - The ARIN copy, AS-RACKIFI (2025-11-19, from whois.radb.net), is likely a stale mirror copy, not proven: ARIN's
      own dump has no AS-RACKIFI, and has AS-RACK with the same `mnt-by:` and `last-modified:`
      (`.data/realdata/arin.db.gz`).
  - 110 of the 407 deletions are from 2026, none after 2026-10-18.
  - 1,641 queries of the 5,000 cap (10 of them a five-set smoke run first, `.data/missing-sets-smoke.log`). None
    failed in transport (the error column of `queries.log` is empty on all 1,641 lines), and no service was stopped.
    The round-1 lookup ran three times: the memory guard refused run B twice for lack of free memory
    (`.data/missing-sets-rounds-try1.log`, `-try2.log`).
  - The one inconclusive set is AS-CONCERTAP. RIPE's history answers it with an empty table and no deletion line
    (the answer kept: `.data/missing-sets/lookup/cache/ripe/as-concertap.bad.txt`), and it stayed inconclusive each
    of the 12 times it was asked, over 6 lookup runs. RIPE holds no object of that name: one query by hand to
    whois.ripe.net, `-r -B -T as-set AS-CONCERTAP`, outside `queries.log`; the answer is
    `.data/missing-sets/concertap-ripe-obj.txt`, and its time, 2026-10-19T10:22:37Z, is that file's mtime.
- Runs B1 to B4 (`.data/missing-sets-round1-B.log` to `-round4-B.log`): PASS, 60 of 60, peak RSS 7,382, 7,229,
  7,456 and 7,480 MB.
  - B4 loaded the 54 found objects (sources IDNIC 17, LEVEL3 33, RIPE-NONAUTH 1, beside the loaded ones).
  - Every route count in its TOTALS equals run A's: 106,712 export rejections, and the same 24 unevaluable reports
    with the same routes. Distinct export missing sets fell from 808 to 787: 406 deleted, 380 not found and
    AS-CONCERTAP (`.data/missing-sets/B4/missing-sets.tsv`, with the classes from `sets.tsv`). Only the "reached" figures of the 24
    moved (AS-SEABONE 2,097,154 to 2,097,153; AS-UAIX 2,100,534 to 2,100,684; AS-DECIX 2,097,192 to 2,097,225).
  - All 106,529 tracked routes are still rejected. 59,403 of them had a found set in a failing clause, and each of
    those routes' lists of missing sets got shorter (`.data/missing-sets/A/rejected-missing.tsv` against
    `.data/missing-sets/B4/tracked.tsv`).
- Classification (`.data/missing-sets-classify.log`):

  | | gap | real | real for any IRR filter | unknown | sum |
  |---|---|---|---|---|---|
  | all tracked routes | 0 | 0 | 72,561 | 33,968 | 106,529 |
  | export | 0 | 0 | 72,558 | 33,968 | 106,526 |
  | import | 0 | 0 | 3 | 0 | 3 |
  | the 59,395 0.4.0 newly decided (10 pairs) | 0 | 0 | 25,427 | 33,968 | 59,395 |

  - No route is a gap; all 33,968 unknown routes are AS9086-AS6762's ipv6 export, for one reason: an inconclusive
    set (AS-CONCERTAP).
  - Of the 842 sets, 54 were found and loaded; the sets still missing in B are ones none of the sources asked holds.
    Over both directions 787 of the 842 are deleted or not found (407 + 380, the import set FLTR-BOGONS-V6 among the
    deleted; not the same 787 as B's export count above, which holds AS-CONCERTAP instead), and 407 of them (51.7%)
    were deleted.
  - Hand-checked (`.data/missing-sets/B4/tracked.tsv`, with the classes from `sets.tsv`):
    - AS20771 to AS174, 37.143.152.0/22 is "real for any IRR filter": its 247 missing sets in B4 are 176 deleted
      and 71 not found, and the first three answer "no entries" at both services.
    - AS6762 to AS1257, 2803:57c0:ff00::/48 is "unknown": its 727 sets are 370 deleted, 356 not found and
      AS-CONCERTAP.
- Not measured:
  - route objects that live only in IDNIC, RIPE-NONAUTH or LEVEL3;
  - any sample other than the 60 pairs.

## [0.4.0] - 2026-10-19

### Added

- `-max-prefixes N` sets the most prefixes one set's expansion may reach
  (rpsl's `MaxPrefixes`). The default is rpsl's limit. 0, negative numbers and
  non-numbers are refused with exit status 2. It applies with `-dump` and with
  `-irrd`.

### Measured, max-prefixes

These figures come from the runs of 2026-10-18 on the branch that adds `-max-prefixes`, on the same pinned
files as v0.3.0's measurements, every registry loaded in precedence order, under the memory guard (8 GB cap,
normal priority, `GOMAXPROCS=4`, `GOMEMLIMIT=6GiB`, one run at a time). Memory is peak RSS on an Apple M3 Max (darwin/arm64) with 36 GiB of memory (`.data/max-prefixes-machine.log`).
The default stays rpsl's 1,048,576. The logs are kept by the maintainer and are not committed.

#### The command on AS9086 from AS6762, `-af both`, no `-vrps`

| `-max-prefixes` | result | peak RSS | time | reports over MaxPrefixes | AS6762's export, both families (75 reports) | log |
|---|---|---|---|---|---|---|
| absent (1,048,576) | exit 0 | 5,848 MB | 47 s | 34 | 1,181,044 accepted / 0 rejected / 448,345 undecided | `.data/max-prefixes-cli-default.log` |
| 2,097,152 | exit 1 (routes rejected) | 6,511 MB | 63 s | 21 | 1,194,673 accepted / 33,968 rejected / 400,748 undecided | `.data/max-prefixes-cli-2097152.log` |
| 4,194,304 | stopped by the guard (over 8 GB) | 8,411 MB when stopped | 82 s | not known | not known | `.data/max-prefixes-cli-4194304.log` |

- 8,388,608 and 16,777,216 were not tried, after the guard stopped 4,194,304.
- The import line is the same in both completed runs: 978,368 accepted, 0 rejected, 0 undecided. Every
  unevaluable report was a MaxPrefixes one.
- The absent run reproduces v0.3.0: its ipv4 part equals `.data/set-limits-cli.log` (44 reports, 21 over,
  1,160,277 / 0 / 400,748), and its ipv6 part (31 reports, 13 over, 20,767 / 0 / 47,597) equals pair 2's ipv6
  line in `.data/realdata-set-limits.log`. 1,160,277 + 20,767 = 1,181,044; 400,748 + 47,597 = 448,345; reports over the limit 34 = 21 + 13; reports 75 = 44 + 31.
- At 2,097,152 every ipv6 report is decided. The 13 reports that were over hold 47,597 routes, now 13,629
  accepted and 33,968 rejected (13,629 + 33,968 = 47,597). ipv6 as a whole (31 reports, 68,364 routes) is
  34,396 accepted (20,767 + 13,629), 33,968 rejected and 0 undecided (34,396 + 33,968 = 68,364). Each of the 33,968 rejections is "prefix not in filter" against
  `AS-SEABONE-V6`, whose expansion has 748 missing sets. The 21 ipv4 reports, all naming `AS-SEABONE`, stay
  over ("reached 2,097,154").
- The command at 2,097,152 equals pair 2 of the every-registry run below: ipv4 1,160,277 / 0 / 400,748, ipv6
  34,396 / 33,968 / 0.

#### `TestRealData`, 60 pairs, every registry, `ROUTECHECK_REALDATA_MAX_PREFIXES=2097152` (`.data/realdata-max-prefixes.log`)

PASS; the log's `limits: MaxPrefixes 2097152` line confirms the limit; 60 of 60 pairs checked, 0 timed out,
0 set too large. Wall time 4m38s (the checks 1m28s; the slowest pair, AS9086 from AS6762, 27.83 s). Peak RSS
6,565 MB; pressure level 1; swap grew 0 MB.

| | default (v0.3.0, `.data/realdata-set-limits.log`) | 2,097,152 |
|---|---|---|
| observations | 4,540,048 | 4,540,048 |
| import accepted / rejected / undecided | 3,787,990 / 146 / 2 | 3,787,990 / 146 / 2 |
| export accepted | 4,401,731 | 4,491,432 |
| export rejected | 47,317 | 106,712 |
| export undecided | 550,071 | 400,975 |
| export rejected with a missing set in a failing clause | 47,131 | 106,526 |
| distinct missing sets left, export | 116 | 808 |
| unevaluable reports, distinct | 81 | 24 |
| unevaluable report instances, counted per pair | 82 | 24 |
| routes in unevaluable reports | 549,847 | 400,751 |
| wall time | 3m45s | 4m38s |
| peak RSS | 6,482 MB | 6,565 MB |

- Routes decided that were unevaluable: 549,847 - 400,751 = 149,096, equal to the export undecided drop
  (550,071 - 400,975). Export accepted rose by 89,701 (4,491,432 - 4,401,731) and export rejected by 59,395
  (106,712 - 47,317); 89,701 + 59,395 = 149,096.
- Every one of the 59,395 newly rejected routes is counted "rejected with a missing set in a failing clause"
  (106,526 - 47,131 = 59,395): their filters were decided from what the registries hold, and those lack
  sets the filters name. They are rejections against incomplete filters, not proven policy violations.
- The 24 reports left (`.data/max-prefixes-pairs-unevaluable.log`), in 3 pairs: pair 2 (AS9086 from
  AS6762), 21 export reports naming `AS-SEABONE`, "reached 2,097,154"; pair 15 (AS44032 from AS15645), 2
  reports of 1 route each, "reached 2,100,534" (AS15645's export to AS25372, and AS44032's `accept AS-UAIX`);
  pair 53 (AS42861 from AS6695), 1 import report of 1 route, `accept AS-DECIX AND NOT <...>`, "reached
  2,097,192". The other 7 of v0.3.0's 10 over-limit pairs (1, 10, 21, 24, 30, 32, 33) have none.

#### The 50 pairs that never reached the limit did not move (`.data/max-prefixes-same-pairs.log`)

Every line but the timing header of every pair's block, `.data/realdata-set-limits.log` against
`.data/realdata-max-prefixes.log`: 60 pairs, 50 identical, 10 differing (1, 2, 10, 15, 21, 24, 30, 32, 33,
53), exactly the 10 over the limit at the default (`.data/set-limits-pairs-unevaluable.log`).

#### Not measured

- Limits between 2,097,152 and 4,194,304, and anything above 4,194,304 (the guard's cap).
- How large `AS-SEABONE`'s full expansion is; it is above 2,097,154.
- Memory on a machine without the 8 GB cap.
- Which of the newly rejected routes would be accepted if the missing sets existed.

## [0.3.0] - 2026-10-18

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
- `Check` no longer returns a `*resolve.SetTooLargeError` (any of rpsl's four
  limits: MaxPrefixes, MaxVisited, MaxDepth, MaxConjuncts); that report is
  unevaluable instead (ruling R27), and the run goes on. As under R19, its
  `policy not evaluable` line is printed whatever `-routes` asks.
- The command no longer exits 3 for a set over a limit; the exit status is 0 or
  1 by the Rejected routes.

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
- **Unchecked data.** Only the five regional registries check that whoever
  registers an object holds the resources; RADB and the mirrors do not, and a
  mirror may be stale. They hold 1,843,733 of the 4,866,879 objects loaded
  (RADB 1,370,610 and the ten mirrors 473,123, `.data/load-all.log`). A figure
  that rests on an object found only there rests on unchecked data; which
  registry supplied each newly resolved set or route object was not measured.

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
"set too large" (at that commit; see "Measured, set limits" for the behaviour
since R27). RIPE alone gives none. 8 are in X's export toward a large
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
  unknown. How much of the rise rests on RADB and the mirrors (unchecked data,
  above) was not measured.

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

### Measured, set limits

These figures come from the run of 2026-10-18 at the commit that made a set over a limit an unevaluable
report, on the same pinned files as the Measured block above, every registry loaded in precedence order,
under the memory guard (8 GB cap, normal priority, `GOMAXPROCS=4`, `GOMEMLIMIT=6GiB`, `GOWORK=off`). The
logs are kept by the maintainer and are not committed.

#### `TestRealData`, 60 pairs, every registry (`.data/realdata-set-limits.log`)

- 60 of 60 pairs checked: 0 timed out, 0 set too large, 0 other errors. In the previous every-registry run,
  10 pairs stopped at the `MaxPrefixes` limit.
- Wall time 3m45s, of which the checks took 38 s; the slowest pair, AS9086 from AS6762, took 10.593 s.
- Peak RSS 6,482 MB, against 6,215 MB in the previous every-registry run
  (`.data/realdata-every-registry.log`), where 10 pairs stopped early. The guard's 8 GB cap was not reached.
- Over the 60 pairs: 4,540,048 observations. Import 3,787,990 accepted, 146 rejected, 2 undecided. Export
  4,401,731 accepted, 47,317 rejected, 550,071 undecided (549,845 `unevaluable`, 226 `peval: peer router not
  given`).
- Route objects over the 60 pairs: import yes 2,820,473, no 967,034, unknown 631; export yes 3,580,317, no
  1,417,966, unknown 836. Rejected with a missing set: import 3, export 47,131.
- Unevaluable reports: 82 report instances, 81 distinct reports (AS34984's export to AS9121 appears in pairs
  10 and 33), holding 549,847 routes (549,845 export + 2 import; `.data/set-limits-pairs-unevaluable.log`).
  Per pair: 80 export reports in 9 pairs and 2 import reports in 2 pairs. All are `MaxPrefixes`;
  none hit MaxVisited, MaxDepth or MaxConjuncts. Distinct, 79 are X's export reports (AS6762 `AS-SEABONE` 34, AS31133
  19, AS9050 10, AS20485 8, AS8953 3, AS20771 2, AS15645 2, AS34984 1) and 2 are L's imports, one route each
  (AS44032 from AS15645, `accept AS-UAIX`; AS42861 from AS6695, `accept AS-DECIX AND NOT <...>`). The test
  counts a report once by its label and error text, so a report met in two pairs counts once while its routes
  are summed over both (pairs 10 and 33 share X = AS34984).

#### The 50 pairs checked before did not move (`.data/set-limits-same-pairs.log`)

Over the 50 pairs both every-registry runs checked, every figure is identical and no pair differs: 2,640,901
observations; import 2,108,348 accepted, 146 rejected, 0 undecided; export 1,249 reports (964 no policy),
2,592,840 accepted, 47,317 rejected, 225 undecided; 3 import and 47,131 export rejections with a missing set;
1,568,538 route-object answers of 2,108,128.

#### The 10 pairs checked for the first time

These are the 60-pair totals minus the 50-pair figures, both from the run above. 1,899,147 observations
(4,540,048 - 2,640,901). Import 1,679,642 accepted (3,787,990 - 2,108,348), 0 rejected, 2 undecided (both
`unevaluable`). Export 338 reports (1,587 - 1,249), 212 of them with no policy (1,176 - 964); 1,808,891
accepted (4,401,731 - 2,592,840), 0 rejected, 549,846 undecided (550,071 - 225): 549,845 `unevaluable` and 1
`peer router not given` (226 - 225). With every registry, these 10 pairs reject no export route: their export
routes are accepted or undecided, and 549,845 of the 549,846 undecided are unevaluable. The same 10 pairs
with RIPE alone had 341,891 export rejections (389,413 - 47,522). How many of those 341,891 became accepted
and how many undecided (unevaluable or not) was not measured route by route.

#### RIPE alone against every registry, all 60 pairs (`.data/realdata-ripe-only.log`, `.data/realdata-set-limits.log`, `.data/set-limits-same-pairs.log`)

| | RIPE only | every registry |
|---|---|---|
| export rejected | 389,413 | 47,317 |
| export undecided | 226 | 550,071 |
| export accepted | 4,608,749 | 4,401,731 |
| export reports with a policy (of 1,587) | 405 | 411 |
| import accepted / rejected / undecided | 3,787,992 / 146 / 0 | 3,787,990 / 146 / 2 |
| L's observations with a route-object answer (of 3,787,507) | 918,363 | 2,820,473 |

Peak RSS of the RIPE-only run: 4,741 MB.

#### Hand checks (`.data/set-limits-checks.log`, `.data/set-limits-cli.log`)

- Pair 2, AS9086 from AS6762, in the test log: AS6762's export reports naming `AS-SEABONE` (and its v6 set)
  are unevaluable and its other export reports are decided. ipv4: 978,368 observations, import 978,368
  accepted, export 44 neighbours (7 no policy), 1,160,277 accepted, 0 rejected, 400,748 undecided. ipv6:
  216,236 observations, import no policy, export 31 neighbours (13 no policy), 20,767 accepted, 0 rejected,
  47,597 undecided. The pair's export undecided are 448,345 `unevaluable`.
- The command on that pair (`routecheck -local AS9086 -peer AS6762 -collector <AS6762's filtered RIB> -af
  ipv4 -dump <the 32 dumps in precedence order>`, peak RSS 5,445 MB) exits 0; before this change it exited 3
  (`.data/maxprefixes-cli-both.log`). It prints `import, AS9086 from AS6762: 978368 routes: 978368 accepted,
  0 rejected, 0 undecided` and 44 export reports, 21 of them with `policy not evaluable, no route decided:
  ... expansion exceeds MaxPrefixes (1048576): reached 1048960`, for example `export, AS6762 to AS174:
  25622 routes: 0 accepted, 0 rejected, 25622 undecided`. Summed over its 44 export reports: 1,160,277
  accepted, 0 rejected, 400,748 undecided, equal to the test's pair-2 ipv4 export.

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

[Unreleased]: https://github.com/rkolesnichenko/routecheck/compare/v0.6.0...HEAD
[0.6.0]: https://github.com/rkolesnichenko/routecheck/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/rkolesnichenko/routecheck/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/rkolesnichenko/routecheck/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/rkolesnichenko/routecheck/compare/v0.2.1...v0.3.0
[0.2.1]: https://github.com/rkolesnichenko/routecheck/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/rkolesnichenko/routecheck/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/rkolesnichenko/routecheck/releases/tag/v0.1.0
