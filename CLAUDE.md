# routecheck — registered RPSL policy against real BGP routes, in Go

Design and rationale: `docs/superpowers/specs/2026-10-16-reconcile-design.md`. It is the source of
truth, and the rulings below amend it where they say so. The plan it was built from is
`docs/superpowers/plans/2026-10-16-routecheck-v0.1.md`. This file is the operating contract.

## What we're building

`github.com/rkolesnichenko/routecheck` checks a BGP session between a local AS L and a neighbour X.

- **Input.** X's real routes, from an MRT capture of the session (session mode) or from
  route-collector RIB dumps (collector mode).
- **Questions.** Which routes L's registered import policy accepts (through which clause), which it
  rejects (and why), and which it cannot decide (and why). Which routes X's own export policy does
  not permit.
- **Per-route hygiene.** Each route's RPKI state, and whether a route object exists.
- **Dependencies.** It requires the published rpsl v0.30.0 (`rpsl`, `rpsl/types`, `rpsl/resolve`)
  and mrt v0.1.0.
- **What is new here.** `pathre` (an AS-path regexp matcher over real paths) and `verdict`.
- **The "separate consumer".** rpsl's own rule ("never match an AS-path regexp against a live
  path") stays intact there. This repository is the separate consumer that rule names.

Packages, imports strictly downward:

| package | role |
|---|---|
| `pathre` | the AS-path regexp matcher |
| `verdict` | route × `peval.Policy` → `Verdict`; imports pathre and never mrt |
| `observe` | MRT → routes as X announced them |
| `hygiene` | RPKI and route-object checks |
| root `routecheck` | the façade, `Checker.Check` |
| `internal/cli` + `cmd/routecheck` | the command |
| `internal/mrtgen` | copied from mrt v0.1.0 (R3) |
| `internal/reoracle` | test-only regexp oracle (P2) |
| `internal/apisurface` | the API golden checker |

## Non-negotiable principles

1. **Never guess.** A test that cannot be decided from the data is undecided, with a reason. A
   route is Accepted or Rejected only when every test it rests on answered. A policy that `peval`
   cannot evaluate is an error for the run, never a verdict. The one exception is AS-ANY or
   RS-ANY in filter position (R19), which is reported as "unevaluable", not decided.
2. **No `net` outside the command.** `.`, `pathre`, `verdict`, `observe` and `hygiene` are pure:
   no `net`, no goroutines they don't own, and context-cancellable. Only `internal/cli` opens files
   and sockets (`-irrd`). `check.sh` enforces it.
3. **Errors are values; never panic.** A bad record or route is counted in the Result. Untrusted
   input is MRT, IRR dumps, IRRd answers, VRPs and `-policy`. Every decoder of it has a fuzz target.
4. **Streaming.** Routes are streamed. Held in memory are only X's routes (one Adj-RIB-Out, or the
   deduplicated observations through X) and the policy's filters.
5. **Go 1.23 floor, conventions C1–C3, API golden** (D9). Options are `X(in)` / `XWith(in,
   XOptions)`. Sentinels use `errors.New`. `api/*.txt` is every exported signature, held by
   `go run ./internal/apisurface -check`.
6. **go.mod.** It requires exactly rpsl, rpsl/types, rpsl/resolve at v0.30.0 and mrt at v0.1.0
   (plus rpsl/ast and rpsl/lexer, indirect). No `replace`, no `go.work`. A bump of rpsl or mrt is
   a decision: update check.sh's list in the same change.
7. **Never commit or push a local home-directory path.** No absolute path under a home directory
   (macOS's `Users`, Linux's `home`) may appear in a committed file; check.sh greps for one. Describe local tools generically, such as "a memory
   guard (8 GB cap)".

## Decisions (spec §2) — keep them

- **D2.** Session mode reads BGP4MP message captures. A RIB dump is refused there unless
  `-pre-policy` (`Options.PrePolicyRIB`) states it is X's Adj-RIB-In before import policy. Without
  it, the CLI exits 3 with a hint.
- **D3.** In collector mode, community tests are always undecided (`CommsKnown` false).
- **D4.** A route rejected only because a referenced set is missing from the registry is
  **Rejected**, and its `Fail.Missing` names the set.
- **D5.** A `~*`, `~+` or `~{m,n}` whose operand is not a single-AS atom is undecided
  (`ErrNotSingleAS` → `same-as-run`). It is refused only on a non-empty path.
- **D6.** There is no repetition-count limit. Instead there is a work budget: `MatchWith` /
  `MatchOptions.MaxWork`, and `DefaultMaxWork` = 10,000,000. Past the budget the result is
  `ErrTooExpensive`, which `verdict` turns into the Undecided reason `path-too-expensive` (R4).
- **D8.** ASPA path verification is not in this version.
- **D9.** The same Go floor, conventions, API golden, check script, CI shape and repository
  security settings as rpsl and mrt.
- Spec §2 has no D7.

## Rulings — each defines behaviour; keep them

- **R1. Compile once.** `verdict.Compile(p) *Compiled` builds the prefix index once per clause and
  holds the path memo. `Decide(p, r)` is `Compile(p).Decide(r)`. The façade compiles once per
  (family, direction, Toward).
- **R2. The bgpq4 snapshot.** The bgpq4 differential's snapshot is rpsl's
  `resolve/testdata/snapshot`, copied into `testdata/irr/snapshot/`. It is served by rpsl's
  `irrdq` + `irrdserver` on 127.0.0.1:0, as two registries, TEST and RADB (R7). bgpq4 gets
  `-h 127.0.0.1:PORT`. Each set is decided against its own clause, compiled alone.
- **R3. mrtgen.** `internal/mrtgen` is mrt v0.1.0's test encoder, copied (MIT, same author) and
  trimmed.
- **P1. The go.mod check.** check.sh asserts the four requirements and their versions, no
  `replace`, and no other module of ours. It does not run `go mod tidy`, and does not demand that
  the `// indirect` marker be absent.
- **P2. One regexp oracle.** Oracle 2 (Go `regexp` over `<n>` tokens, counts clamped at L+1) and
  the random generator live in `internal/reoracle`. Both pathre's tests and verdict's model test
  use it; nothing is copied.
- **P3. Goldens.** The goldens are `testdata/golden/{session,collector,nopolicy}.{txt,json}`.
  release.sh verifies `session.txt`.
- **P4. Model seeds under -race.** verdict's model test draws a quarter of its seeds under `-race`
  (`raceEnabled`), and all of them otherwise.
- **R4. The pathre work budget.** pathre counts steps: a 64-bit word of a position set allocated,
  read or written; an AS tested against an atom item; a node compiled. Past `MaxWork` it returns
  `ErrTooExpensive`, which becomes `ReasonPathTooExpensive` (Undecided), never a guess. An
  adversarial regexp is pinned to stop within 1 s.
- **R5. ReasonPathUnbound.** `ErrUnbound`, or any other unexpected pathre error reaching verdict,
  is a caller's bug: peval always binds PeerAS. The test is undecided with
  `ReasonPathUnbound`, never a silent "no".
- **R6. Accepted after undecided terms.** An Accepted verdict also carries, in `Reasons`, the
  `ReasonPeval` entries of `Policy.Undecided` terms whose `Index` is at most the accepting clause's
  `Index`. It lists the undecided clauses before it in `EarlierUndecided`.
- **Community values.** `local_as` and `no_export_subconfed` are both 0xFFFFFF03 and are read
  case-insensitively. `internet` has no value, so it is undecided. IRRToolSet's source has
  `no_export_subconfed` = 0xFFFFFF03u and no `local_as` (docs/routecheck.md).
- **The path memo cap.** The memo counts key bytes, capped at 64 MiB. Past the cap it is cleared
  and fills again.
- **R8. Session replay.**
  - An UPDATE whose NLRI do not parse resets the session state (counted `MalformedResets`).
  - An announcement skipped as "not X first" still deletes the key's earlier route (counted
    `NotFirstAS`). A path whose first segment is not AS_SEQUENCE counts as "not X first".
  - With `PrePolicyRIB`, RIB entries for the peer form the state and later UPDATEs apply on top.
    Without it, the first RIB record ends the sequence with `ErrRIBNotPrePolicy`.
  - Records with time ≤ `At` are included.
- **R9/R10. RFC 7606 classify** (observe, pinned by `TestClassify` rows):
  - **Session reset** on:
    - any ParseUpdate Error, or any Decode Error;
    - a Warning on MP_REACH/MP_UNREACH;
    - §5.2 (attributes other than MP_UNREACH, no reachable NLRI, and a non-discard attribute
      error);
    - `bgp/attr-truncated` when the NLRI cannot be located.
  - **Treat-as-withdraw** on:
    - any other Decode Warning, except duplicates and the attributes RFC 7606/6793 discard;
    - `attr-truncated` when the NLRI can still be located;
    - a missing ORIGIN, or a missing NEXT_HOP for v4 NLRI.
  - The discard rows assume eBGP. With iBGP (LocalAS == Peer), LOCAL_PREF, ORIGINATOR_ID and
    CLUSTER_LIST errors are treat-as-withdraw.
  - A reset sets `DownAtEnd` until the next UPDATE.
  - A RIB baseline clears the earlier state and `MidSession`.
- **Sessions per peer address.** Each peer address is its own session: two Adj-RIB-Outs, both
  Observations kept. `Evidence.PeerAddr` tells them apart (zero in collector mode). NOTIFICATION
  and OPEN do not clear state. 2-byte BGP4MP subtypes show a 4-byte X as AS_TRANS, so nothing is
  selected.
- **R11/R12. Collector mode.**
  - **Filtering.** It keeps PEER_INDEX_TABLE, RIB and TABLE_DUMP records. BGP4MP/BGP4MP_ET records,
    and RecordErrors of those types, are dropped and counted in `CollectorInfo.Ignored`.
  - **The suffix.** `PathKnown` and `OriginSet` are judged on the suffix from X's leftmost
    occurrence.
  - **The neighbour** is the AS immediately left of X when that AS is in an AS_SEQUENCE. When it is
    an AS_SET member, in a confederation segment, or AS_TRANS, there is no neighbour (counted
    `NoNeighbour`).
  - **Direct.** An entry whose path starts with X is Direct only when the collector peer's AS is X.
    When the peer is another real AS, the neighbour is that AS. When the peer is AS_TRANS or 0,
    there is no neighbour.
  - **Bad entries.** A RIB entry with a SeverityError, or a treat-as-withdraw-class warning, is
    skipped and counted `Malformed` (over the whole table). `ErrTruncated` or a read error ends the
    sequence.
  - **Evidence.** `Evidence.Time` is the latest sighting.
- **R13. The façade.**
  - In session mode, a zero `Options.Local` comes from the capture's LocalAS. If that is zero too,
    the run fails with an error.
  - Families map AFI 1/2 × SAFI 1/2. Families outside `Options.AF` are dropped and counted in
    `Coverage.OtherFamilies`.
  - In collector mode, the import report is over all observations. Export is one Report per
    neighbour AS, sorted.
  - One hygiene.Checker is used per Check.
- **R14. Options and cancellation.**
  - Every option error wraps `routecheck.ErrOptions`, and the CLI maps it to exit 2.
  - Check checks ctx every 4096 records and routes, and returns `context.Canceled` /
    `DeadlineExceeded` as is.
  - Collector-mode export with no neighbour is an empty, non-nil slice.
- **R15–R18. A `-policy` draft.**
  - **What the draft answers.** Only aut-nums and inet-rtrs come from a draft. They answer before
    the registry's under any `source:`, with `-dump` and with `-irrd` alike. With dumps they are
    also `Put` into the Corpus.
  - **What is skipped.** Sets, `route`/`route6` objects, and classes routecheck does not use are
    skipped with a warning, broken or not.
  - **What fails the run.** A parse or decode error in an aut-num or inet-rtr, a refused Put, or a
    file with no aut-num and no inet-rtr is exit 3, naming the file and the object. Diagnostics go
    to stderr.
- **R16. The command.**
  - `-local` is optional in session mode.
  - JSON is a view: outcomes and RPKI states as words, communities as `"hi:lo"`, clauses as
    `{Index, Term, Filter}`. A test decodes it back with `DisallowUnknownFields`.
- **R19/R21. Unevaluable.** peval returns a `*resolve.AnySetError` for AS-ANY or RS-ANY in filter
  position: `accept AS-X` or `NOT AS-X` where AS-X reaches AS-ANY (`members: AS-ANY`). It does not
  fail the run. That one report gets:
  - `Report.Unevaluable` = the error's text, set whatever the route count;
  - an empty `Policy`;
  - every route Undecided with the single reason `ReasonUnevaluable` (`"unevaluable"`, Why = the
    error text, Clause and Index -1).

  Every other peval error (a limit, ctx, a Source error, a missing aut-num) still fails the run.
  The same set inside an AS-path regexp (`<^AS-X$>`) is not an error: since rpsl v0.30.0 it is a
  `resolve.ASNSet` whose `Any()` is true, any one AS there (see AnySets).
- **AnySets.** `Verdict.AnySets` is, on an Accepted verdict only, the canonical names (sorted,
  deduplicated) of the sets reaching AS-ANY named by the AS-path tests, either polarity, of the
  conjunct that accepted the route: per conjunct, not per clause. It is nil otherwise, and always
  nil on Rejected and Undecided. Text: `accepted by clause N (X reaches AS-ANY: any AS)`, or
  `(X, Y reach AS-ANY: any AS)`, before any "after undecided" part. The report block also prints,
  whatever `-routes` asks for, `accepted through a set reaching AS-ANY (any AS): X, Y (N routes)`
  (the distinct sets, sorted, and the number of accepted routes with AnySets, each route once;
  ruling G1). JSON:
  `"AnySets"`, `null` when none. pathre asks only `Has`, which is true for every AS of such a
  set; never read `List`/`Len` of one without `Any()` first.
- **R23. No session selected.** `SessionInfo.Selected` counts the records selected for X; when it is 0 the CLI exits 3 ("no record of a session with AS X [from ADDR] in the capture ..."), and Check still returns its Result. Without `-local` such a capture names no local AS, so Check returns ErrOptions first and the CLI exits 2 with the same cause in the message (R26). A `-local` that is not the capture's LocalAS is checked as given, with a warning on stderr and in the text; the exit status is unchanged.
- **Transparent route server.** When the announcements skipped as "not X first" outnumber the
  routes held at the end (all families), the text output says X looks like a transparent route
  server. It is not judged when a family is "no policy" in every direction checked.
- **NoPolicy.** No clause and no undecided term means `NoPolicy`: no per-route verdicts, and it
  does not set exit 1.
- **Exit status.**
  - 0: nothing Rejected (Undecided alone is 0).
  - 1: some route Rejected.
  - 2: a bad command line or `ErrOptions`.
  - 3: could not complete.
- **Router addresses.** They are never taken from the capture. The text output only offers the
  capture's addresses as a hint for `-local-rtr`/`-peer-rtr`.

## Tests and oracles

- **pathre oracle 1.** `pathre/testdata/routemodel-vectors.jsonl`, written by rpsl's test-only
  `TestWriteVectors` (on rpsl's `main` since PR #35; commit in its README and header). Never
  edit it by hand.
- **pathre oracle 2.** `internal/reoracle`.
- **verdict.**
  - A table test per §6.4 rule.
  - A model test against a naive evaluator.
  - The bgpq4 differential (`bgpq4_test.go`). It skips without bgpq4, unless
    `ROUTECHECK_ORACLES_REQUIRED=1` (CI) makes that fatal.
- **observe.** Synthetic MRT from `internal/mrtgen`.
- **Goldens.** `internal/cli`'s goldens run from the repository root, so the file names printed
  are `testdata/...`. A golden is the command's output: rewrite it, never hand-edit it, and read
  the diff.
- **Real data before "done".** Before calling a change done that touches deciding, observing or
  loading, run the opt-in real-data test (below) and check one count by hand against the RIB
  (`mrtdump -m`) and `whois`.

## Commands

- `scripts/check.sh`. It runs:
  - gofmt, build, vet, `go test -race`, and coverage;
  - no `net` in the library packages;
  - no home-directory path in a committed file;
  - the go.mod requirements;
  - the API golden;
  - staticcheck and govulncheck when installed.

  `FUZZTIME=15s scripts/check.sh` also runs the fuzz targets. On a developer machine, run it alone,
  guarded, with output to a file and the status on the next line:
  `GOWORK=off GOMAXPROCS=4 memguard.sh 8 3600 env FUZZTIME=15s scripts/check.sh > .data/check.log 2>&1; echo "exit=$?"`.
  It must end `check: ok` and exit 0. `memguard.sh LIMIT_GB TIMEOUT_S CMD...` is the maintainer's
  memory guard (8 GB cap), such as rpsl's `.superpowers/sdd/tools/memguard.sh`. It is not part of
  this repo. Without it, use a memory cap of your own (`GOMEMLIMIT` and a watchdog).
- `scripts/fuzz.sh` runs three targets: FuzzMatch (pathre), FuzzDecide (verdict), FuzzObserve
  (observe). Set the duration with `FUZZTIME` (default 15s). `FUZZ_SHARD=i/n` picks a shard; CI
  runs two.
- `ROUTECHECK_API_UPDATE=1 go run ./internal/apisurface -check` rewrites `api/`. Review
  `git diff api/`: it is the API change list.
- `ROUTECHECK_GOLDEN_UPDATE=1 go test ./internal/cli` rewrites `testdata/golden/*` and
  `testdata/session/*.mrt`. Review the diff.
- **The pathre vectors.** Regenerate them from a checkout with `rpsl` and `routecheck` side by side,
  on rpsl's `main`, then update the commit in `pathre/testdata/README.md`:
  `cd ../rpsl/resolve && RPSL_ROUTEMODEL_COMMIT=$(git rev-parse HEAD) RPSL_ROUTEMODEL_VECTORS=$PWD/../../routecheck/pathre/testdata/routemodel-vectors.jsonl go test -count=1 -run TestWriteVectors ./internal/routemodel`
- **Real data (opt-in).** `scripts/fetch-data.sh` downloads into `.data/realdata/` and pins each
  file in `.data/realdata/MANIFEST`. It fetches RIPE's split dumps, the newest route-views2 RIB
  and RIS rrc00 bview, and NTT's VRPs. `scripts/fetch-data.sh --registries` adds the 15 other
  registries (APNIC, ARIN, AFRINIC, LACNIC, RADB and its ten mirrors) to an existing MANIFEST,
  keeping its other lines, in the precedence order the run loads them. Then, alone:
  `GOMAXPROCS=4 memguard.sh 8 6000 env GOWORK=off GOMAXPROCS=4 GOMEMLIMIT=6GiB ROUTECHECK_REALDATA=$PWD/.data/realdata go test -count=1 -timeout 100m -run TestRealData -v .`
  - It loads every registry the MANIFEST pins, but picks the pairs from RIPE's files only.
    Measured on 2026-10-18: every registry took 3m25s and a peak RSS of 6,215 MB
    (`.data/realdata-every-registry.log`), over the 6,144 MB projection threshold of the memory
    gate (`.data/every-registry-gate.log`), so ask before running it; RIPE alone took 3m31s and
    4,741 MB (`.data/realdata-ripe-only.log`).
  - `ROUTECHECK_REALDATA_REGISTRIES` (comma-separated registry names, case-insensitive; empty means
    every pinned registry) loads only those. `ripe` is 0.2.0's load.
  - `ROUTECHECK_REALDATA_LOAD_ONLY=1` loads the registries, logs a `LOAD:` line and stops before
    the RIBs (all 16: 35.871 s, peak RSS 3,534 MB, `.data/load-all.log`).
  - `ROUTECHECK_REALDATA_SAMPLE`, `_REGEXP_SAMPLE` and `_SEED` choose the sample.
  - `ROUTECHECK_CHECK_TIMEOUT` (default 600s) is the per-pair timeout.
  - The benchmarks (`BenchmarkDecide`, `BenchmarkCollector`; `ROUTECHECK_BENCH_LOCAL`, `_PEER`,
    `_AF` and `_ROUTES`) use the same data and load every pinned registry too. Their commands
    are in `bench_test.go`. Set `ROUTECHECK_REALDATA_REGISTRIES=ripe` to compare with 0.2.0's
    figures. Their memory peaks with every registry were not measured.
- `scripts/release.sh vX.Y.Z`: see the header of the script. Rehearse with `--dry-run`. Never run
  it without the user's go-ahead: it pushes a tag. Never query the Go proxy for an unpushed tag,
  since the proxy caches the miss.

## Heavy runs

Real-data runs and benchmarks hold the registries (TestRealData peak RSS 6,215 MB with all 16,
4,741 MB with RIPE alone). Run them one at a time, alone, under
the memory guard, never beside check.sh or each other. Every figure in a doc or the CHANGELOG
comes from a command run in this work, with its log named. Otherwise it is unknown. The logs live
in `.data/`, which is never committed.

## Known limitations (state them, don't paper over them)

- **AS-ANY in filter position.** A policy that accepts or announces a set reaching AS-ANY (or
  RS-ANY), `accept AS-X` or `NOT AS-X`, gives an "unevaluable" report: every route Undecided (R19).
  rpsl refuses to enumerate it, and routecheck gives it no meaning of its own. In an AS-path regexp
  such a set is decided (any one AS) and named in `Verdict.AnySets`.
- **Registries.** Load every registry a policy's sets reach. 0.2.0 loaded RIPE alone: 389,127 of
  its 389,413 export rejections named sets RIPE does not hold. Loading all 16 changed little on
  the 50 pairs both runs could check: export rejections 47,522 to 47,317. What remains mostly
  names sets no loaded registry holds (AS-ISPSERVICES, AS-STEFFANN-IPV4, AS-STEFFANN-IPV6,
  AS-TELFORT: 46,052 routes each). The "missing set" tag names a clause's missing sets; it does
  not say a missing set caused the rejection. 341,891 of 0.2.0's 389,413 export rejections were
  in the 10 pairs that could not be checked with every registry (389,413 - 47,522), see
  MaxPrefixes: 389k to 47k is not the registries' effect.
- **MaxPrefixes.** With every registry loaded, 10 of 60 pairs have one filter over rpsl's default
  1,048,576 prefixes: 8 in X's export toward a transit neighbour, 2 in L's import
  (`.data/over-limit-terms.log`). The command exits 3 when a checked direction holds the
  over-limit filter; check the other direction (`.data/maxprefixes-cli-export.log`,
  `.data/maxprefixes-cli.log`).

## Process

- Pre-v1: keep releasing 0.x, and break the API while it is cheap. Commit on a branch, never on
  `main`. Creating the GitHub repository, pushing, merging and tagging all wait for the user's
  explicit go-ahead.
- Judge a subagent's work by `git diff`. Before merging, an independent reviewer reads the whole
  diff.
