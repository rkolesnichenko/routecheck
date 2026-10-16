# routecheck v0.1.0: registered policy against real BGP routes — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A new Go module `github.com/rkolesnichenko/routecheck` and command `routecheck` that decide, for one BGP session, which routes a neighbour really announces (from an MRT session capture or from collector RIB dumps) the local AS's registered import policy accepts, rejects or cannot decide, and why, and which of them the neighbour's own export policy does not permit.

**Architecture:** `pathre` matches RFC 2622 AS-path regexps (rpsl's `policy.ASPathRE`) against real paths by position sets. `verdict` decides a route against a `peval.Policy` with three-valued tests and reasons. `observe` turns MRT records into routes as the neighbour announced them, in session mode (replay of its UPDATEs) and collector mode (path suffixes from RIB dumps). `hygiene` adds RPKI and route-object checks. The root package's `Checker` joins them per address family and direction; `internal/cli` is the command.

**Tech Stack:** Go 1.23 floor; `github.com/rkolesnichenko/rpsl`, `…/rpsl/types`, `…/rpsl/resolve` v0.29.0; `github.com/rkolesnichenko/mrt` v0.1.0; bgpq4 (Homebrew/apt) for the prefix differential.

**Spec:** `docs/superpowers/specs/2026-10-16-reconcile-design.md` (approved 2026-10-16). Read it first; this plan argues from it. Section numbers below (§6.4 …) are the spec's.

## Global Constraints

- Module path `github.com/rkolesnichenko/routecheck`; `go 1.23` in `go.mod`. Direct requirements are exactly `github.com/rkolesnichenko/rpsl v0.29.0`, `github.com/rkolesnichenko/rpsl/types v0.29.0`, `github.com/rkolesnichenko/rpsl/resolve v0.29.0`, `github.com/rkolesnichenko/mrt v0.1.0` (rpsl's `ast`/`lexer` come in indirectly). No `go.work`, no `replace`.
- Import direction: `internal/cli` → root (`routecheck`) → `verdict`, `observe`, `hygiene`; `verdict` → `pathre`. `verdict` and `pathre` never import `mrt`. Only `internal/cli` and `cmd/routecheck` may import `net` (check: `go list -deps . ./pathre ./verdict ./observe ./hygiene | grep -x net` prints nothing). Test files may use localhost listeners.
- `net/netip` only; ASNs are rpsl's `types.ASN` everywhere above `observe` (`observe` converts from `bgp.ASN`).
- Conventions C1–C3 as rpsl and mrt (`X`/`XWith`; whole-value parsers `(T, []Diagnostic)`, single values `(T, error)`; sentinels `errors.New`). Public signatures in `api/*.txt`; `ROUTECHECK_API_UPDATE=1 go run ./internal/apisurface -check` rewrites them; `go run ./internal/apisurface -check` passes at every commit.
- Never panic on any input; never guess — what cannot be decided is Undecided with a reason (spec §6.4).
- The spec's §7 names are binding: `pathre.Match`, `pathre.ErrNotSingleAS`, `pathre.ErrUnbound`, `verdict.Route`, `verdict.Decide`, `verdict.Verdict`/`Fail`/`Reason`/`Outcome` (`Accepted`, `Rejected`, `Undecided`), `routecheck.Checker`, `Check`, `Options`, `Mode` (`ModeSession`, `ModeCollector`), `Result`, `Report`, `RouteVerdict`, `observe.Session`, `observe.Collector`, `observe.Observation`, `observe.Evidence`.
- No committed file may contain a local home-directory path: `git grep -n -I -E '/(Users|home)/'` prints nothing (check.sh enforces it; the pattern is written so it does not match itself). The user's rule.
- All work is local in `routecheck` on branch `v0.1`. Creating the GitHub repository, pushing, opening PRs (including the rpsl PR of Task 2), tagging and releasing wait for the user's explicit go-ahead.
- Heavy runs (real data, large benchmarks) one at a time, alone, under `memguard.sh`, `GOMAXPROCS=4`.
- Every figure in docs or the CHANGELOG comes from a command run in this work, with its log named; anything not measured is called unknown.

## Rulings made while planning

- **R1. `verdict.Compile`.** §7's `Decide(p, r)` "holds no state", but §9 wants a prefix index built once per clause and a path memo. The plan adds `verdict.Compile(p peval.Policy) *Compiled` and `(*Compiled).Decide(r Route) Verdict` (safe for concurrent use); `Decide(p, r)` stays and is `Compile(p).Decide(r)`. The façade always compiles once per (family, direction, Toward).
- **R2. The bgpq4 snapshot.** §10 says "the same fixed snapshot rpsl's differential uses". That snapshot is RPSL text in `rpsl/resolve/testdata/snapshot/` (four files, synthetic, documentation ASNs and prefixes). It is copied into `testdata/irr/snapshot/` with its README and the rpsl version it came from, and served to bgpq4 by rpsl's public `resolve/irrdq` + `resolve/irrdserver` on `127.0.0.1:0`, as rpsld serves dumps. Reading it out of the module cache instead would tie the test to the cache layout.
- **R3. The MRT test encoder.** mrt's `internal/mrtgen` is internal to mrt. It is copied (MIT, same author) into `internal/mrtgen` here, with the header comment naming its origin (`mrt v0.1.0 internal/mrtgen`), and trimmed to what `observe`'s tests use.

## Review Focus

1. **Paths that are empty or do not start with X** (an iBGP-style capture, a transparent route server, X's own origination seen as `X`): an empty path or a first AS other than X is skipped and counted under "not starting with X", never decided; `X` alone is a normal route. → Task 7, `TestSessionNotFirstAS`; Task 8, `TestCollectorOriginIsX`.
2. **Families the run did not ask for** (IPv6 routes in an `-af ipv4` run, SAFI 2 multicast routes, a v4 prefix in MP_REACH): each route goes to the family its `bgp.Family` names; families not asked for are dropped and counted, never decided under the wrong `AddrFamily`. → Task 10, `TestCheckFamilies`.
3. **Add-path keys in replay**: two path IDs for one prefix are two routes; a withdrawal of one leaves the other; a capture mixing add-path and plain messages for one peer keys plain ones as path ID 0. → Task 7, `TestSessionAddPath`.
4. **One policy, many routes**: a 100,000-range filter decided for 100,000 routes builds its index once; `Compile` is called once per (family, direction, Toward). → Task 4, `TestCompileBuildsIndexOnce`; Task 10, `TestCheckCompilesOncePerReport`.
5. **`-at` at the edges**: a time before the first record gives an empty state and the coverage note "no records before -at"; a time after the last gives the end state; a record exactly at `-at` is included. → Task 7, `TestSessionAt`.

---

### Task 0: Repository

**Files:**
- Create: `routecheck/{go.mod,go.sum,LICENSE,README.md,.gitignore}` beside `rpsl/` and `mrt/`
- Move: `rpsl/docs/superpowers/specs/2026-10-16-reconcile-design.md` → `routecheck/docs/superpowers/specs/`; this plan → `routecheck/docs/superpowers/plans/2026-10-16-routecheck-v0.1.md`

- [ ] **Step 1: Create the repository with the docs as its first commit**

```bash
mkdir -p routecheck/docs/superpowers/specs routecheck/docs/superpowers/plans
cd routecheck && git init -b main
# both files are untracked in rpsl, so a plain mv removes them there
mv ../rpsl/docs/superpowers/specs/2026-10-16-reconcile-design.md docs/superpowers/specs/
mv ../rpsl/docs/superpowers/plans/2026-10-16-routecheck-v0.1.md docs/superpowers/plans/
```

`go.mod`: `module github.com/rkolesnichenko/routecheck`, `go 1.23`, then `go get github.com/rkolesnichenko/rpsl@v0.29.0 github.com/rkolesnichenko/rpsl/types@v0.29.0 github.com/rkolesnichenko/rpsl/resolve@v0.29.0 github.com/rkolesnichenko/mrt@v0.1.0` (run with `GOWORK=off`; check `go.mod` still says `go 1.23` and has no `toolchain` line). `LICENSE`: MIT, "Copyright (c) 2026 R. Kolesnichenko". `.gitignore`: `.data/`, `*.test`, `*.prof`, `.superpowers/`, `.idea/`. `README.md`: spec §1's two questions and a "status: pre-release" line.

- [ ] **Step 2: Commit on main, then branch**

```bash
git add -A && git commit -m "routecheck: design and v0.1 plan"
git checkout -b v0.1
git -C ../rpsl status --short   # expect: nothing about routecheck
```

---

### Task 1: Tooling (check.sh, fuzz.sh, apisurface, CI)

**Files:**
- Create: `scripts/check.sh`, `scripts/fuzz.sh`, `internal/apisurface/*` (copied from `../mrt/internal/apisurface/`), `.github/workflows/ci.yml`, `routecheck.go` (package doc), `pathre/doc.go`, `verdict/doc.go`, `observe/doc.go`, `hygiene/doc.go`, `api/{routecheck,pathre,verdict,observe,hygiene}.txt`

**Interfaces:**
- Produces: `scripts/check.sh` (exit 0 = green), `scripts/fuzz.sh` with a `targets` list of `"<dir> <pkg> <FuzzName>"` lines (empty here; Tasks 3, 4, 7 add theirs), `FUZZ_SHARD=i/n`, `FUZZTIME`.

- [ ] **Step 1: Copy apisurface from mrt** — packages `.`→`api/routecheck.txt`, `./pathre`, `./verdict`, `./observe`, `./hygiene` → `api/<name>.txt`; env var `ROUTECHECK_API_UPDATE`; keep the C1–C3 checks and their tests.
- [ ] **Step 2: Run** — `go test ./internal/apisurface && ROUTECHECK_API_UPDATE=1 go run ./internal/apisurface -check && go run ./internal/apisurface -check` → PASS, five goldens with package lines only.
- [ ] **Step 3: `scripts/check.sh`** — from mrt's: gofmt, `go build ./... && go vet ./... && go test -race -count=1 ./...`, coverage report, apisurface, the no-`net` check from Global Constraints, the no-home-path check (`git grep -n -I -E '/(Users|home)/'` must print nothing), `go.mod` direct requirements exactly the four of Global Constraints, staticcheck and govulncheck when installed, then `scripts/fuzz.sh` when `FUZZTIME` is set. Replace mrt's "no require" check with the requirement check.
- [ ] **Step 4: `scripts/fuzz.sh`** — mrt's, verbatim except the empty target list.
- [ ] **Step 5: `.github/workflows/ci.yml`** — mrt's shape: `check` (matrix `1.23.x`, `stable`; `GOTOOLCHAIN: local`; installs staticcheck and govulncheck as mrt does; installs bgpq4 with `sudo apt-get install -y bgpq4`; `ROUTECHECK_ORACLES_REQUIRED=1`), `fuzz` (two shards, `FUZZTIME=30s`), `ci ok` (needs both, fails unless both succeeded). Actions pinned by full SHA, the same SHAs mrt's workflow uses.
- [ ] **Step 6: Run** — `scripts/check.sh > .data/check-t1.log 2>&1; echo "exit=$?"` → `exit=0`.
- [ ] **Step 7: Commit** — `git add -A && git commit -m "tooling: check.sh, fuzz.sh, apisurface, CI"`

---

### Task 2: rpsl's routemodel vector generator, and the vectors

Work in `../rpsl` on a new branch `routemodel-vectors` from `main`; nothing in rpsl's API changes.

**Files (rpsl):**
- Create: `resolve/internal/routemodel/vectors_test.go`
- Modify: `resolve/internal/routemodel/routemodel_test.go` (lift `TestMatchPath`'s case table to a package-level `var matchPathCases` both use)

**Files (routecheck):**
- Create: `pathre/testdata/routemodel-vectors.jsonl`, `pathre/testdata/README.md`

**Interfaces:**
- Produces: a JSON-lines file; line 1 is a header `{"generator":"rpsl resolve/internal/routemodel TestWriteVectors","rpsl_commit":"<full sha>","seed":1}`; every other line `{"re":"<regexp text>","sets":{"AS-A":[64501,64502]},"path":[64500,64501],"match":true}` or with `"err":"too-complex"` / `"err":"not-single-as"` and no `match`.

- [ ] **Step 1: Write `TestWriteVectors`** — `t.Skip` unless `RPSL_ROUTEMODEL_VECTORS` names an output path. Cases, in this order: the five RFC 2622 §5.4 examples (`<AS3>`, `<^AS1>`, `<AS2$>`, `<^AS1 AS2 AS3$>`, `<^AS1 .* AS2$>` bodies) each over the paths `[1 2 3]`, `[3]`, `[1 9 2]`, `[2 1]`, `[]`; every `matchPathCases` entry; then 5,000 seeded (`rand.New(rand.NewPCG(1, 2))`) random regexps over ASes 64500–64505 and set names `AS-A` = {64501, 64502}, `AS-EMPTY` = {}, `AS-ANY` (no members; routemodel treats it as any AS), built from atoms (AS, `.`, set, `[…]`, `[^…]`, ranges), `* + ? {m} {m,n} {m,}`, `~* ~+ ~{m,n}`, alternation, grouping, `^`/`$`, depth ≤ 4, each against 4 random paths of length 0–8 over the same ASes; plus 20 with counts in 1001–5000 (routemodel's `ErrTooComplex`). The header's `rpsl_commit` is `git rev-parse HEAD` read by the test, passed in through `RPSL_ROUTEMODEL_COMMIT` (the test fails if it is unset when writing).
- [ ] **Step 2: Run rpsl's routemodel tests** — `cd ../rpsl/resolve && go test ./internal/routemodel` → PASS (the generator skips).
- [ ] **Step 3: Commit in rpsl** — `git add -A && git commit -m "routemodel: test-only generator of regexp vectors for routecheck"`.
- [ ] **Step 4: Generate** — `cd ../rpsl/resolve && RPSL_ROUTEMODEL_COMMIT=$(git rev-parse HEAD) RPSL_ROUTEMODEL_VECTORS=$PWD/../../routecheck/pathre/testdata/routemodel-vectors.jsonl go test -run TestWriteVectors ./internal/routemodel; echo "exit=$?"` → `exit=0`; the file has 1 + 25 + `len(matchPathCases)` + 20,000 + 20 lines (`wc -l`), and contains no home-directory path.
- [ ] **Step 5: README** — `pathre/testdata/README.md`: what the file is, the rpsl commit, the command of Step 4 with relative paths, "never edit by hand".
- [ ] **Step 6: Commit in routecheck** — `git add pathre/testdata && git commit -m "pathre: routemodel vectors from rpsl"`. The rpsl branch stays local; its PR waits for the user.

---

### Task 3: `pathre`

**Files:**
- Create: `pathre/pathre.go`, `pathre/pathre_test.go`, `pathre/oracle_test.go`, `pathre/vectors_test.go`, `pathre/fuzz_test.go`

**Interfaces:**
- Consumes: `policy.ASPathRE` and its node types (`ASPathASN`, `ASPathASNRange`, `ASPathAlt`, `ASPathAny`, `ASPathClass`, `ASPathEnd`, `ASPathPeerAS`, `ASPathRepeat{Inner, Op, Min, Max, Same}`, `ASPathSeq`, `ASPathSet`, `ASPathSetTemplate`, `ASPathStart`), `resolve.ASNSet`, `resolve.NewASNSet`.
- Produces: `func Match(re *policy.ASPathRE, sets map[types.SetName]resolve.ASNSet, path []types.ASN) (bool, error)`; `var ErrNotSingleAS`, `var ErrUnbound`.

- [ ] **Step 1: Table tests** (`TestMatch`): the RFC 2622 §5.4 examples with the results the RFC states (`<AS3>` matches `[1 3 2]`; `<^AS1>` not `[2 1]`; `<AS2$>` matches `[1 2]`; `<^AS1 AS2 AS3$>` matches only `[1 2 3]`; `<^AS1 .* AS2$>` matches `[1 2]` and `[1 7 7 2]`); the RFC's `[AS1 AS2]{2}` and `[AS1 AS2]~{2}` examples; `AS-ANY` matches any one AS; a set absent from `sets` matches no AS; an empty path matches `^$` and an unanchored `.*`, not `.`; `ASPathPeerAS` left in the regexp → `ErrUnbound`; `(AS1 AS2)~*` → `ErrNotSingleAS`; `^AS1{5000}$` against 5,000 × AS1 → true and against 4,999 → false (no count limit, D6); `^(AS1?){100000}$` against `[1 1]` → true.
- [ ] **Step 2: Oracle 2** (`oracle_test.go`, test-only): translate the regexp into a Go `regexp` over tokens `<n>` (written fresh from the RFC text, not from routemodel's source), with every repetition count clamped to `len(path)+1` (spec §10) and `.`/negated classes ranging over the path's own ASes. `TestMatchesOracle`: 20,000 seeded random regexps × paths (generator as in Task 2 Step 1, own code) — `Match` and the oracle agree whenever both answer.
- [ ] **Step 3: Vectors** (`TestMatchesRoutemodel`): every line of `testdata/routemodel-vectors.jsonl`: `match` vectors → `Match` agrees; `not-single-as` → `ErrNotSingleAS`; `too-complex` → `Match` answers and agrees with oracle 2. Fails if the file has fewer than 20,000 vectors.
- [ ] **Step 4: Run to verify failure** — `go test ./pathre` → FAIL (undefined `Match`).
- [ ] **Step 5: Implement `Match`** by position sets (spec §6.5): for node n and start i, the set of end positions, memoized on (n, i); a repeat's reachable ends are iterated to a fixed point, so an operand matching the empty path terminates and counts above `len(path)+1` cost nothing more; `~` repeats require the operand to be a single-AS atom (`ASPathASN`, `ASPathASNRange`, `ASPathAny`, `ASPathClass`, `ASPathSet`), else `ErrNotSingleAS`; unanchored = try every start, accept if any end is reached (with `^`/`$` as zero-width tests at 0 and `len(path)`). No `regexp`, no recursion deeper than the AST.
- [ ] **Step 6: Fuzz** — `FuzzMatch(f, body string, path []byte)`: parse with `policy.ParseASPathRegexp`, skip on error; path = bytes mod 6 + 64500; must not panic; when both `Match` and oracle 2 answer they agree. Add to `scripts/fuzz.sh`.
- [ ] **Step 7: Run** — `go test ./pathre && go test -run '^$' -fuzz FuzzMatch -fuzztime 30s ./pathre` → PASS.
- [ ] **Step 8: API golden, commit** — `ROUTECHECK_API_UPDATE=1 go run ./internal/apisurface -check`; `git add -A && git commit -m "pathre: RFC 2622 AS-path regexps against real paths"`

---

### Task 4: `verdict`

**Files:**
- Create: `verdict/verdict.go`, `verdict/community.go`, `verdict/index.go`, `verdict/verdict_test.go`, `verdict/fuzz_test.go`

**Interfaces:**
- Consumes: `peval.Policy{Clauses []peval.Clause; Undecided []peval.Undecided}`, `peval.Clause{Index; Term; Actions; Filter resolve.NormalFilter; Remote}`, `resolve.Conjunct`, `pathre.Match`.
- Produces: spec §6.1's `Route`, with one more field, `OriginSet bool` ("the path's last segment was an AS_SET; Path's last AS is not the origin", for `hygiene`), and §7's `Outcome`, `Verdict`, `Fail`, `Reason`, `Decide`; plus (R1) `func Compile(p peval.Policy) *Compiled`, `func (*Compiled) Decide(r Route) Verdict`, `func (*Compiled) Policy() peval.Policy`; reason kinds `ReasonPathNotSequence`, `ReasonCommsUnknown`, `ReasonCommInternet`, `ReasonCommValue`, `ReasonSameASRun`, `ReasonPeval` as string constants.

- [ ] **Step 1: Table tests** (`TestDecide`), each rule of spec §6.4, building `peval.Policy` values by hand from `resolve.NormalFilter`s obtained with `resolve.Expander.NormalizeFilter` over a small `resolve.NewMemSource` (so the filters are real normal forms): prefix in / not in / in `NotPrefixes`; `AnyPrefix`; empty `Prefixes` matches nothing; path test yes/no/negated; `PathKnown` false → undecided path test, but a clause without path tests still decides; `ErrNotSingleAS` → `ReasonSameASRun`; community contains/equals/negated with `hi:lo`, a 4-byte integer, `no_export` (0xFFFFFF01), `no_advertise` (0xFFFFFF02), `local_as` (0xFFFFFF03); `internet` → `ReasonCommInternet`; `CommsKnown` false → `ReasonCommsUnknown`; an unparsable value → `ReasonCommValue`; conjunct AND / filter OR three-valued; first-match `Clause` and `EarlierUndecided`; Rejected needs every clause no and `Undecided` empty; a peval `Undecided` term turns a would-be Rejected into Undecided with `ReasonPeval`, `Why` as given, `Clause` −1, `Index` the term's; `Fail.Test` is the first failing test's filter text and `Fail.Missing` lists the clause filter's `Missing()` (D4); clause `Pos` differs from `Index` for a flattened REFINE (two clauses, one `Index`).
- [ ] **Step 2: `TestCompileBuildsIndexOnce`** (Review Focus 4): a policy with one clause of 100,000 /24 ranges; `Compile` once, `Decide` 100,000 routes; an unexported build counter (`indexBuilds`, read by the test) is 1; also `TestDecideMatchesCompiled` (the two entry points agree on the Step 1 table).
- [ ] **Step 3: Run to verify failure** — `go test ./verdict` → FAIL.
- [ ] **Step 4: Implement.** Prefix index per conjunct: a binary trie over each family's ranges (`PrefixRange.Prefix()`, `Lo()`, `Hi()`), a lookup walks the prefix's bits and tests each stored range's length bounds; one trie for `Prefixes`, one for `NotPrefixes`. Path memo per (`*policy.ASPathRE`, path as string key) behind a mutex. Communities parsed once at `Compile` (values → `uint32` or a reason). `Decide` never allocates per clause beyond the verdict.
- [ ] **Step 5: Fuzz** — `FuzzDecide`: a fixed compiled policy with prefix, path and community tests; route from fuzz bytes (prefix, path, communities, flags); never panics; `Outcome` is one of the three; Accepted ⇒ `Clause` within `len(Clauses)`. Add to `scripts/fuzz.sh`.
- [ ] **Step 6: Run** — `go test -race ./verdict` → PASS.
- [ ] **Step 7: API golden, commit** — `git commit -m "verdict: three-valued decision of a route against a policy"`

---

### Task 5: Verdict model test and the bgpq4 differential

**Files:**
- Create: `verdict/model_test.go`, `testdata/irr/snapshot/{as-sets,route-sets,routes,claims}.txt` and `README.md` (copied from rpsl v0.29.0 `resolve/testdata/snapshot/`, R2), `testdata/irr/policies.txt` (aut-nums using the snapshot's sets), `bgpq4_test.go` (root, package `routecheck_test`)

**Interfaces:**
- Consumes: `verdict.Compile`, `peval.Evaluator`, `resolve.NewMemSource`, `irrdq.NewRegistry`, `irrdq.NewSnapshot`, `irrdserver.Server`.

- [ ] **Step 1: Model test** (`TestDecideModel`): 2,000 seeded random policies (1–4 clauses; conjuncts of prefix literals with operators, as-set references, `<…>` regexps from Task 3's generator, community tests, NOT, AND, OR) over a generated `MemSource`, normalized through `peval`; 50 random routes each; an in-test naive evaluator (direct recursion over the *unnormalized* `policy.Filter`, expanding sets with `Expander`, path tests through oracle 2's translation copied into this test file) must give the same Outcome, treating its own "can't" exactly as §6.4's undecided cases.
- [ ] **Step 2: Copy the snapshot** — the four files and README from `$(GOWORK=off go list -m -f '{{.Dir}}' github.com/rkolesnichenko/rpsl/resolve)/testdata/snapshot/`, adding to the README: "copied from rpsl v0.29.0 resolve/testdata/snapshot; synthetic". `policies.txt`: aut-num AS64496 with `import: from AS64500 accept <set>` for each as-set and route-set in the snapshot (one term each, family-specific `mp-import:` for the v6 sets), `source: TEST`.
- [ ] **Step 3: `TestPrefixPolicyMatchesBgpq4`**: skip unless `bgpq4` is on PATH (fail instead when `ROUTECHECK_ORACLES_REQUIRED=1`). Load snapshot + policies into a `resolve.Corpus` (`KeepPolicy`), serve it with `irrdserver.Server{Snapshot: …}` on `127.0.0.1:0` (registry name `TEST`, sources `TEST,RADB` as rpsl's differential). For each set S: run `bgpq4 -h 127.0.0.1 -p <port> -S TEST,RADB -j -l x [-6] S` (IPv6 sets with `-6`), read its prefixes with their ranges; build candidate routes: every listed prefix, each prefix's /len+1 halves, and its covering /len−1; `Decide` each against AS64496's import from AS64500 for the right family; Accepted ⇔ the prefix is in bgpq4's list (respecting bgpq4's `exact`/`greater-equal`/`less-equal` fields). Log the number of routes compared per set; fail on any disagreement with the first 10 listed.
- [ ] **Step 4: Run** — `go test -run 'TestDecideModel|TestPrefixPolicyMatchesBgpq4' -v . ./verdict > .data/t5.log 2>&1; echo "exit=$?"` → `exit=0`; the log shows a non-zero comparison count for every set.
- [ ] **Step 5: Commit** — `git commit -m "verdict: model test and bgpq4 prefix differential"`

---

### Task 6: `internal/mrtgen` (test-only MRT encoder, R3)

**Files:**
- Create: `internal/mrtgen/mrtgen.go`, `internal/mrtgen/mrtgen_test.go`

**Interfaces:**
- Produces (internal only), with mrt's signatures: `Header`, `PeerIndexTable`, `RIB`, `BGP4MP`, `StateChange`, `Update`, `Raw`, `Origin`, `ASPath(as4 bool, segs ...bgp.Segment)`, `AS4PathAttr`, `Seq`, `Set`, `NextHop`, `MPReach`, `Communities`, plus `ConfedSeq(asns ...bgp.ASN) bgp.Segment`.

- [ ] **Step 1: Copy** mrt v0.1.0's `internal/mrtgen/mrtgen.go` (from the module cache: `$(GOWORK=off go list -m -f '{{.Dir}}' github.com/rkolesnichenko/mrt)/internal/mrtgen/`), drop what the list above does not name, add `ConfedSeq`, header comment naming the origin.
- [ ] **Step 2: `TestGenDecodes`** — each builder's output decodes through `mrt.Records`/`mrt.Routes` to the values passed in.
- [ ] **Step 3: Run, commit** — `go test ./internal/mrtgen` → PASS; `git commit -m "internal/mrtgen: test encoder from mrt"`

---

### Task 7: `observe` — session mode

**Files:**
- Create: `observe/observe.go` (shared types, path conversion), `observe/session.go`, `observe/session_test.go`, `observe/fuzz_test.go`

**Interfaces:**
- Consumes: `mrt.Records`' iterator, `mrt.BGP4MPMessage` (`PeerAS, LocalAS, PeerAddr, LocalAddr, Local, AddPath`, `Context()`, `MessageType()`), `mrt.BGP4MPStateChange`, `bgp.ParseUpdate`, `bgp.Attrs.Decode`, mrt's RIB records for `-pre-policy`.
- Produces:
  - `type Evidence struct { Neighbours []types.ASN; Direct bool; CollectorPeers int; Time time.Time }`
  - `type Observation struct { Route verdict.Route; Evidence Evidence; Family bgp.Family }`
  - `type SessionSel struct { Peer types.ASN; PeerAddr netip.Addr; At time.Time; PrePolicyRIB bool }`
  - `type SessionInfo struct { LocalAS types.ASN; LocalAddr, PeerAddr netip.Addr; MidSession, DownAtEnd, NoRecordsBeforeAt bool; NotFirstAS, Malformed, Skipped int }`
  - `func Session(records iter.Seq2[mrt.Record, error], sel SessionSel) (iter.Seq2[Observation, error], func() SessionInfo)` — the info function is valid after the sequence is drained.
  - `func Route(prefix netip.Prefix, p *bgp.Path, commsKnown bool) verdict.Route` (shared conversion, spec §6.1).
  - `var ErrRIBNotPrePolicy = errors.New("observe: a RIB dump is a post-policy table; pass PrePolicyRIB if it is an Adj-RIB-In")`

- [ ] **Step 1: Tests** with `internal/mrtgen` captures:
  - `TestRouteConversion`: ASSequence concatenated with prepends kept; a last segment AS_SET sets `OriginSet`; an AS_SET, an AS_CONFED_SEQUENCE, an AS_CONFED_SET or an AS 23456 after merge → `PathKnown` false; communities copied.
  - `TestSessionReplay`: announce, re-announce (replaces), withdraw (deletes), MP_REACH/MP_UNREACH for v6; result in prefix order.
  - `TestSessionStateChanges`: Established→Idle clears; Idle→Established clears; capture ending down → empty, `DownAtEnd`; first UPDATE before any Established → `MidSession`.
  - `TestSessionAddPath` (Review Focus 3).
  - `TestSessionMalformed`: an UPDATE with a malformed attribute withdraws its NLRI's earlier routes and counts `Malformed`.
  - `TestSessionNotFirstAS` (Review Focus 1).
  - `TestSessionSelects`: other peers' messages, LOCAL messages and other peer addresses (when `PeerAddr` set) are ignored; `LocalAS`/addresses reported from the first selected record.
  - `TestSessionAt` (Review Focus 5).
  - `TestSessionRIB`: a TABLE_DUMP_V2 input → `ErrRIBNotPrePolicy` unless `PrePolicyRIB`, then its entries for the peer are the state.
- [ ] **Step 2: Run to verify failure** — `go test ./observe` → FAIL.
- [ ] **Step 3: Implement.** Read `mrt.Records` directly (mrt's `Routes` skips state changes and LOCAL messages, spec §3); decode each selected UPDATE with `bgp.ParseUpdate(m.Message, m.Context())` and `Attrs.Decode()`; state keyed by (prefix, path ID). A diagnostic with `Severity == bgp.SeverityError` from `ParseUpdate` or `Attrs.Decode` makes the UPDATE malformed; warnings and info (`bgp/as4path-ignored` and the like) do not.
- [ ] **Step 4: Fuzz** — `FuzzObserve(f, data []byte)`: `Session` over `mrt.Records(bytes.NewReader(data))`; never panics. Add to `scripts/fuzz.sh`.
- [ ] **Step 5: Run, API golden, commit** — `go test -race ./observe` → PASS; `git commit -m "observe: session-mode replay"`

---

### Task 8: `observe` — collector mode

**Files:**
- Create: `observe/collector.go`, `observe/collector_test.go`

**Interfaces:**
- Produces: `type CollectorInfo struct { Entries, Through, Direct, NotSequence int }`; `func Collector(records iter.Seq2[mrt.Record, error], x types.ASN) (iter.Seq2[Observation, error], func() CollectorInfo)`. Observations come out after the input is read (dedup needs all of it), in prefix order then path order.

- [ ] **Step 1: Tests**
  - `TestCollectorSuffix`: `P1 P2 X Y O` → path `X Y O`, neighbour P2; `X X X Y` from a direct feed → path kept with prepends, `Direct`, no neighbour.
  - `TestCollectorPoisoning`: `P X Y X O` cuts at the leftmost X.
  - `TestCollectorOriginIsX` (Review Focus 1): `P X` → path `X`.
  - `TestCollectorDedup`: the same (prefix, suffix) via two collector peers and two neighbours → one observation, both neighbours (sorted), `CollectorPeers` 2; across two concatenated RIB files with their own PEER_INDEX_TABLEs.
  - `TestCollectorNotSequence`: X inside an AS_SET only → not an observation, counted `NotSequence`; X in the sequence part with an AS_SET after it → observation with `PathKnown` false.
  - `TestCollectorComms`: every observation has `CommsKnown` false.
  - `TestCollectorIgnoresUpdates`: BGP4MP records in the input are skipped and counted in `Entries` only if RIB.
- [ ] **Step 2: Run to verify failure, implement** (stream `mrt.Routes`, keep only routes whose path contains X, map keyed by (prefix, suffix string)); add `Collector` (X = 64500) to `FuzzObserve`.
- [ ] **Step 3: Run, API golden, commit** — `git commit -m "observe: collector-mode suffixes"`

---

### Task 9: `hygiene`

**Files:**
- Create: `hygiene/hygiene.go`, `hygiene/hygiene_test.go`

**Interfaces:**
- Produces: `type Checker struct { VRPs *rpki.VRPs; Src resolve.Source }`; `func (*Checker) RPKI(r verdict.Route) *rpki.State`; `func (*Checker) RouteObject(ctx context.Context, r verdict.Route, afi types.AFI) (*bool, error)` (nil when the origin is an AS_SET or `Src` is nil; reads `OriginatedRoutes` once per origin and family, cached in the Checker, safe for concurrent use). The origin is `r.Path[len(r.Path)-1]` unless `r.OriginSet`, which makes it AS0 for RPKI and skips the route-object check.

- [ ] **Step 1: Tests** — `TestRPKI`: Valid, Invalid (wrong origin; too long), NotFound; AS_SET origin with a covering VRP → Invalid, without → NotFound (AS0, RFC 6811 §2); nil VRPs → nil. `TestRouteObject`: exact (prefix, origin) found; a covering route object only → false; AS_SET origin → nil; `OriginatedRoutes` called once for many routes of one origin (counting Source wrapper).
- [ ] **Step 2: Run to verify failure, implement, run** — `go test -race ./hygiene` → PASS.
- [ ] **Step 3: API golden, commit** — `git commit -m "hygiene: RPKI and route-object checks"`

---

### Task 10: The `Checker` façade

**Files:**
- Create: `check.go`, `check_test.go`

**Interfaces:**
- Consumes: everything above; `peval.Evaluator.Import/Export`, `peval.Session{Local, Peer, LocalRtr, PeerRtr, AF}`, `types.ParseAddrFamily`.
- Produces: spec §7's `Mode`, `Options`, `Checker`, `Check`, `Result`, `Report`, `RouteVerdict`; `type Direction uint8` with `DirImport = 1`, `DirExport = 2`, `DirBoth = 3` (zero means both); `type Coverage struct { Session *observe.SessionInfo; Collector *observe.CollectorInfo; OtherFamilies int; DirectNotChecked int; HintLocalAddr, HintPeerAddr netip.Addr }`.

- [ ] **Step 1: Tests** over a `MemSource` + `KeepPolicy` corpus built in the test and `internal/mrtgen` inputs:
  - `TestCheckSessionImport`: L=AS64496 imports from X=AS64500 two clauses; a capture with accepted, rejected and undecided routes; counts and per-route verdicts as expected; `Report.Toward` = X.
  - `TestCheckSessionExport`: X's `export: to AS64496 announce AS64500` against the same capture: a route originated elsewhere is Rejected ("announced beyond its registered policy").
  - `TestCheckCollectorExportPerNeighbour`: observations announced to neighbours N1 and N2 → two export Reports ordered by AS; X has no term for N2 → that Report `NoPolicy`, no route verdicts; direct-feed observations counted in `DirectNotChecked`.
  - `TestCheckNoPolicy`: L has no import term for X → `Import.NoPolicy`, no verdicts.
  - `TestCheckFamilies` (Review Focus 2).
  - `TestCheckCompilesOncePerReport` (Review Focus 4): an unexported compile counter.
  - `TestCheckRouterHint`: a peering naming a router and no `LocalRtr`/`PeerRtr` → Undecided with `peval.WhyLocalRouter`; `Coverage.HintLocalAddr`/`HintPeerAddr` are the capture's addresses.
  - `TestCheckPevalError`: a `resolve.SetTooLargeError` from peval → `Check` returns the error, no Results.
  - `TestCheckHygiene`: RPKI and route-object fields filled when VRPs and `Routes` are set, nil otherwise.
- [ ] **Step 2: Run to verify failure, implement, run** — `go test -race .` → PASS.
- [ ] **Step 3: API golden, commit** — `git commit -m "routecheck: Checker, one session in both directions"`

---

### Task 11: The command

**Files:**
- Create: `cmd/routecheck/main.go` (shim), `internal/cli/{cli.go,load.go,text.go,json.go,cli_test.go,golden_test.go}`, `testdata/golden/*.{txt,json}`, `testdata/mrt/` (one RouteViews slice copied from mrt v0.1.0 `testdata/mrt/` with its attribution lines in `testdata/README.md`), `testdata/session/*.mrt` (from `internal/mrtgen`), `testdata/irr/golden-policy.txt`

**Interfaces:**
- Produces: `func Run(ctx context.Context, args []string, stdout, stderr io.Writer) int` (exit status per spec §8).

- [ ] **Step 1: Tests** (`cli_test.go`): every flag of spec §8; bad command lines exit 2 (no `-local`/`-peer`; both `-session` and `-collector`; neither `-dump` nor `-irrd`; `-local` = `-peer`; `-pre-policy` with `-collector`; `-at` with `-collector`; an unknown `-af`); a missing dump file, a missing aut-num, an unreachable `-irrd` (a closed localhost port) exit 3; any Rejected route exits 1; only Undecided exits 0; `NoPolicy` exits 0. `-policy` with `-dump` replaces the dump's aut-num of the same key and source (`TestPolicyOverridesDump`); with `-irrd` (an `irrdserver` over a snapshot on localhost) answers `AutNum`/`InetRtr` from the file and sets from the server (`TestPolicyOverIRRd`). The irrd client is `irrd.Source{Addr, Sources}` (rpsl's public backend).
- [ ] **Step 2: Goldens** (`TestGoldens`, `ROUTECHECK_GOLDEN_UPDATE=1` rewrites): text and JSON for (a) a session capture with all three outcomes and a mid-session start, (b) collector mode over the RouteViews slice for one X seen in it, with `golden-policy.txt` (a hand-written aut-num AS64496 importing from X: one as-set clause listing ASes seen behind X, one `<^X+ .*>` clause, one community clause — undecided in collector mode), (c) `NoPolicy`.
- [ ] **Step 3: Implement.** `load.go`: dumps via `rpsl.Parse` + `object.Decode` + `Corpus.Put` with `KeepPolicy`, precedence in flag order; `-policy` loaded last into the same Corpus, or wrapped over `irrd.Source` (a `resolve.PolicySource` whose `AutNum`/`InetRtr` try the file's MemSource first); VRPs via `rpki.ReadJSON`; inputs via `os.Open` + `mrt.Decompress` + `mrt.Records`. Text output as spec §8 (Rejected grouped by first failing test with up to 5 examples each; Undecided grouped by reason; coverage warnings, including the collector-mode meaning line of §6.3 and the router-address hint); JSON is `[]routecheck.Result` encoded with field names as in Go.
- [ ] **Step 4: Run** — `go test -race ./internal/cli` → PASS; `go run ./cmd/routecheck -h` prints the usage.
- [ ] **Step 5: Commit** — `git commit -m "cmd/routecheck: the command"`

---

### Task 12: Real data and performance

**Files:**
- Create: `scripts/fetch-data.sh`, `realdata_test.go` (root, `ROUTECHECK_REALDATA`), `bench_test.go`

**Interfaces:**
- Produces: `TestRealData` (skips unless `ROUTECHECK_REALDATA` names a directory), `BenchmarkDecide`, `BenchmarkCollector`.

- [ ] **Step 1: `scripts/fetch-data.sh`** downloads into `.data/realdata/` the RIPE split dumps (`ripe.db.aut-num.gz`, `ripe.db.as-set.gz`, `ripe.db.route-set.gz`, `ripe.db.route.gz`, `ripe.db.route6.gz`), the latest RouteViews route-views2 RIB and the latest RIS rrc00 bview, and an NTT or rpki-client VRP JSON if one is publicly downloadable (else skip RPKI and say so); writes name, URL, size, sha256 to `.data/realdata/MANIFEST`. RIS files are never committed.
- [ ] **Step 2: `TestRealData`**: load RIPE with `KeepPolicy`; pick 50 aut-nums (seeded) that have `import: from X` for an X seen in the RIBs; for each, collector mode, both directions, both families; asserts no error other than a counted `SetTooLargeError` or per-check context timeout (`ROUTECHECK_CHECK_TIMEOUT`, default 60 s); logs per AS: observations, Accepted/Rejected/Undecided per direction, Undecided reasons tallied, wall time; totals at the end.
- [ ] **Step 3: Run alone under the memory guard**

```bash
GOMAXPROCS=4 memguard.sh 8 4000 env ROUTECHECK_REALDATA=$PWD/.data/realdata \
  go test -count=1 -timeout 60m -run TestRealData -v . > .data/realdata.log 2>&1
echo "exit=$?"
```
Expected: `exit=0`, the memguard line SUCCESS. Then by hand: pick one Rejected route from the log, confirm with `whois -h whois.ripe.net AS<L>` that the import term and set say what the verdict says, and with `bgpdump -m` (or `mrtdump`) on the RIB that the path appears as observed; and check one observation count for one X against `mrtdump -m <rib> | awk -F'|' '$7 ~ / X( |$)/' | wc -l` (the denominator, before dedup). Write both checks into the log's summary.

- [ ] **Step 4: Benchmarks** — `BenchmarkDecide` (a real policy from the run with the largest filter; ns/route), `BenchmarkCollector` (one RIB, one X); and one timed full run of the command, in session-like shape, against a full IPv4 table: take a route-views2 direct feed of a full-table peer as X, `-collector` over that RIB under memguard, record wall time and peak RSS (memguard's report). Figures go to the CHANGELOG with the log names.
- [ ] **Step 5: Commit** — `git commit -m "real-data test, benchmarks"` (logs stay under ignored `.data/`).

---

### Task 13: Docs, repository files, release script, final review

**Files:**
- Create: `CLAUDE.md`, `docs/routecheck.md`, `CHANGELOG.md`, `SECURITY.md`, `.github/dependabot.yml`, `.github/ISSUE_TEMPLATE/config.yml`, `scripts/release.sh`
- Modify: `README.md`

- [ ] **Step 1: Capture qualification (spec §13)** — from each daemon's own manual (fetch the current pages): OpenBGPD `bgpd.conf(5)` `dump` (which of `all in`, `updates in`, `table`, `table-v2` are pre-policy, and whether a `dump` starts at session establishment), BIRD 2 `mrtdump messages` and `mrt dump` (table dumps of a channel's import table, if any), GoBGP's `mrt` config (`dump-type: updates|table`). Write a table in `docs/routecheck.md`: daemon, setting, qualifies for `-session` yes/no/with `-pre-policy`, the manual's sentence quoted. Also `local_as`'s value from IRRToolSet's source (`src/rpsl/` community handling); if it differs from 0xFFFFFF03, fix `verdict/community.go` and its test first.
- [ ] **Step 2: Docs** — `README.md` (what, install, the two questions, a session example and a collector example with their real output from the goldens, status pre-v1, "what collector mode means"); `docs/routecheck.md` (every flag, output, exit status, the capture table); `CHANGELOG.md` (`## [Unreleased]` with Task 12's figures and their logs); `CLAUDE.md` (the operating contract: spec decisions D2–D9 and R1–R3, "never guess", "never push a local home-directory path", commands: check.sh, fuzz.sh, the vector regeneration of Task 2, the real-data run under memguard, API golden update, goldens update); `SECURITY.md`, `dependabot.yml`, `ISSUE_TEMPLATE/config.yml` as mrt's, adapted (untrusted inputs: MRT files, IRR dumps, IRRd answers; the hardened invariants: no panics, fuzz targets, streaming, no `net` outside the CLI).
- [ ] **Step 3: `scripts/release.sh vX.Y.Z`** — mrt's, with `cmd/routecheck` in place of `cmd/mrtdump` and the golden it verifies being `testdata/golden/session.txt`. Not run in this plan.
- [ ] **Step 4: Full check** — `GOMAXPROCS=4 memguard.sh 8 3600 env FUZZTIME=15s scripts/check.sh > .data/check-final.log 2>&1; echo "exit=$?"` → `exit=0`, `check: ok`.
- [ ] **Step 5: Whole-branch review** — dispatch an independent reviewer on `git diff main...v0.1` with the spec; fix Critical and Important findings (test first), re-run check.sh.
- [ ] **Step 6: Commit** — `git add -A && git commit -m "docs, repository files, release script"`
- [ ] **Step 7: Stop and report to the user.** Each of these waits for the user's go-ahead:
  - pushing rpsl's `routemodel-vectors` branch and opening its PR;
  - creating `github.com/rkolesnichenko/routecheck` and applying the security settings rpsl and mrt have;
  - pushing `v0.1` and opening a PR;
  - merging it;
  - releasing v0.1.0.
