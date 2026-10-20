# Pair 2's V Rejections Against R Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Count how many of pair 2's 263,472 export rejections in run V are accepted in run R (rescued by the non-RIR registries' objects other than route objects), check the controls, hand-check one rescued route, and publish.

**Architecture:**
- **Task 1 (subagent):** an offline join in test code, `pair2v_test.go`. It reads V2's, R2's and A's `routes.tsv.gz` and writes a cross table and the rescued keys. Unit tests on small fixtures; the real files only under an opt-in variable.
- **Task 2 (controller):** the run under the guard, and the aut-num check, from a script under `.data/`.
- **Task 3 (controller):** the hand-check of one rescued ipv6 route.
- **Task 4 (subagent):** the docs.

**Tech Stack:** Go (test code only), `compress/gzip`; zsh scripts under `.data/` (not committed).

**Spec:** `docs/superpowers/specs/2026-10-20-pair2-v-rejections-design.md`

## Global Constraints

- **No live queries.** Nothing in this plan touches the network.
- **No heavy run.** Nothing reruns pair 2. The join still runs under the guard, alone, never beside check.sh:
  `MEMGUARD_NORMAL_PRIORITY=1 ../rpsl/.superpowers/sdd/tools/memguard.sh 8 TIMEOUT env GOWORK=off GOMAXPROCS=4 GOMEMLIMIT=6GiB …`
- **Inputs are the published files, read only:** `.data/stream/V2/routes.tsv.gz`, `.data/stream/R2/routes.tsv.gz` (both made at ae7d034), `.data/provenance/A/routes.tsv.gz`, and the 2026-10-18 dumps in `.data/realdata`. Never the `rejected-missing.tsv` files whole (3.7 GB and 5.1 GB).
- **Code:** only `_test.go` files, docs, `CHANGELOG.md` and `CLAUDE.md` change.
- **Controls:** any failure stops the work and goes to the maintainer. No figure is published from a failed run.
- **Figures:** every figure comes from a command run and names its log. The design's preliminary table is not a source. No local home-directory path in anything committed or pushed.
- **Words:** the rescued routes are "rescued by the non-RIR registries' objects", never "gaps". Which set rescues which route is not measured.
- **Branch:** `pair2-v-rejections`, from `main` at aeae843. Commit on the branch, never on main.

## Review Focus

1. **A malformed or truncated input line.** Expected: an error naming the file and line, never a silently short count. *Test:* `TestJoinVRErrors` (Task 1), a 4-field line and a truncated gzip.
2. **A key twice in one run's file.** Expected: an error naming the key; a duplicate would double-count a rejection. *Test:* `TestJoinVRErrors`, the duplicate case.
3. **V's or R's file holding a line of another pair.** Expected: an error naming the key (the stream shards hold pair 2 alone). A's lines of other pairs are skipped. *Test:* `TestJoinVRErrors` and `TestJoinVR` (an A line of another pair).
4. **A key in one run only, or a route-object answer that differs.** Expected: listed, and a failed control, not dropped from the table. *Test:* `TestJoinVR` (an R-only key, a differing answer) and `TestVRControls`.
5. **The cross table's rows depending on map order.** Expected: the same bytes on every run. *Test:* `TestJoinVR` compares `writeVRCross`'s output exactly.

---

### Task 1: The join

**Files:**
- Create: `pair2v_test.go`

**Interfaces:**
- Consumes (existing, `provenance_test.go`): `parseProvLine(line string) (pair, key string, r provRoute, err error)`, `provRoute{Outcome, RouteObj, RPKI, Detail string}`, `provDirOf(key string) (string, error)`. From `missingsets_classify_test.go`: `writeGz(t, path, lines...)` for fixtures.
- Produces (used by Task 2's run): the opt-in `TestPair2VAgainstR` and its variables `ROUTECHECK_PAIR2V_V`, `ROUTECHECK_PAIR2V_R`, `ROUTECHECK_PAIR2V_A` (each a `routes.tsv.gz` path) and `ROUTECHECK_PAIR2V_OUT` (a directory: it writes `pair2-v-cross.txt` and `pair2-v-rescued.tsv` there).

```go
// vrCell is one cell of the cross table over pair 2's export routes rejected in V.
type vrCell struct {
	Family string // the key's 3rd field: "ipv4.unicast" or "ipv6.unicast"
	Obj    string // V's route-object answer (equal to R's when the controls hold)
	A      string // A's outcome: accepted, rejected or undecided
	R      string // R's outcome
}

type vrJoin struct {
	Cells     map[vrCell]int
	Rescued   []string       // export keys rejected in V and accepted in R, sorted
	AccRej    int            // export keys accepted in V and rejected in R
	ImportV   map[string]int // import keys by V's outcome
	ImportR   map[string]int // import keys by R's outcome
	VOnly     []string       // keys in V's file only (any direction), sorted
	ROnly     []string       // keys in R's file only, sorted
	ObjDiffer []string       // keys whose route-object answer differs between V and R, sorted
	NotInA    []string       // export keys rejected in V that A's file lacks, sorted
}

// joinVR reads V's and R's routes.tsv.gz (pair's lines only; any other pair is an
// error), and A's (other pairs skipped).
func joinVR(vPath, rPath, aPath, pair string) (*vrJoin, error)

type vrWant struct {
	VRejected, RRejected int // export
	Rescued4, Kept4      int // ipv4: A undecided; R accepted, R rejected
	Rescued6, Kept6      int // ipv6, A accepted: R accepted, R rejected
	ARejected6           int // ipv6, A rejected: R rejected
	ImportAccepted       int // in V and in R, nothing else
}

// controlErrors lists every control that fails, empty when all hold.
func (j *vrJoin) controlErrors(w vrWant) []string

// writeVRCross writes the table: a header line, one tab-separated row per cell
// sorted by family, Obj, A, R, then a "sum" row.
func writeVRCross(w io.Writer, j *vrJoin) error
```

Memory: hold V's keys (about 1.63M export and 0.98M import) in one map, stream R against it, then stream A keeping only V's rejected keys. Never hold A's other pairs.

- [ ] **Step 1: Write the failing tests**

`TestJoinVR`, on fixtures written with `writeGz` in `t.TempDir()` for pair `AS1-AS2` (5-field lines: key, outcome, route object, RPKI, detail):
- V: `AS1-AS2|export|ipv6.unicast|AS3|2001:db8::/32|AS3 AS4` rejected/yes; `…|export|ipv4.unicast|AS3|192.0.2.0/24|AS3` rejected/no; `…|export|ipv4.unicast|AS3|198.51.100.0/24|AS3` accepted/yes; `…|import|ipv4.unicast|AS2|203.0.113.0/24|AS2` accepted/no; `…|export|ipv4.unicast|AS3|10.0.0.0/8|AS3` accepted/yes; `…|export|ipv4.unicast|AS3|10.1.0.0/16|AS3` rejected/no.
- R: the same keys with outcomes accepted, rejected, accepted, accepted, rejected, rejected; the last with route object `yes`; plus one R-only key `…|export|ipv4.unicast|AS3|10.2.0.0/16|AS3` accepted/no.
- A: the ipv6 key accepted, the 192.0.2.0/24 key undecided, the 10.1.0.0/16 key absent, and one line of pair `AS5-AS6`.

Assert:
```go
want := map[vrCell]int{
	{"ipv4.unicast", "no", "", "rejected"}:          1, // 10.1.0.0/16, not in A
	{"ipv4.unicast", "no", "undecided", "rejected"}: 1,
	{"ipv6.unicast", "yes", "accepted", "accepted"}: 1,
}
// j.Cells == want; j.Rescued == ["AS1-AS2|export|ipv6.unicast|AS3|2001:db8::/32|AS3 AS4"]
// j.AccRej == 1; j.ImportV == j.ImportR == {"accepted": 1}
// j.VOnly == nil; j.ROnly == [the 10.2.0.0/16 key]
// j.ObjDiffer == [the 10.1.0.0/16 key]; j.NotInA == [the 10.1.0.0/16 key]
```
A key A lacks has `A` "" in its cell. Then `writeVRCross` gives exactly:
```
family	route object	A	R	routes
ipv4.unicast	no		rejected	1
ipv4.unicast	no	undecided	rejected	1
ipv6.unicast	yes	accepted	accepted	1
sum				3
```

`TestJoinVRErrors`: each returns an error whose text contains the given substring:
- a 4-field line in V → the V path and `:1`;
- the same key twice in R → the key;
- a V line of pair `AS5-AS6` → `AS5-AS6`;
- R's file cut to half its gzip bytes → the R path.

`TestVRControls`: a `vrJoin` built by hand that meets a small `vrWant` gives no errors; then each of these, changed alone, gives exactly one error that names it: `AccRej` 1; `ROnly` one key; `ObjDiffer` one key; `NotInA` one key; one ipv4 cell with `A` "accepted"; one ipv6 cell with `A` "rejected" and `R` "accepted"; `ImportR` `{"accepted": n, "rejected": 1}`; `Rescued4` off by one.

- [ ] **Step 2: Run them to see them fail**

Run: `GOWORK=off go test -count=1 -run 'TestJoinVR|TestVRControls' .`
Expected: FAIL (undefined: joinVR).

- [ ] **Step 3: Implement `joinVR`, `controlErrors` and `writeVRCross` in `pair2v_test.go`**

`controlErrors` checks, each failure one line naming the figure, the want and the got:
- `VOnly`, `ROnly`, `ObjDiffer`, `NotInA` empty; `AccRej` 0;
- V's export rejections (the sum of `Cells`) = `VRejected`; R's export rejections (cells with `R` rejected, plus `AccRej`) = `RRejected`;
- ipv4 cells: every `A` is undecided; `R` accepted sums to `Rescued4`, rejected to `Kept4`;
- ipv6 cells: `A` accepted gives `Rescued6` and `Kept6`; `A` rejected gives `ARejected6` with `R` rejected and 0 with `R` accepted; no other `A`;
- `len(Rescued)` = `Rescued4 + Rescued6`;
- `ImportV` and `ImportR` are each `{"accepted": ImportAccepted}`.

- [ ] **Step 4: Add the opt-in `TestPair2VAgainstR`**

Skips unless `ROUTECHECK_PAIR2V_V` is set; needs the other three variables (a missing one is `t.Fatal`). Pair `AS9086-AS6762`. It logs the cross table and every control error, writes both files to `_OUT` (the rescued keys one per line), and fails with `t.Errorf` per control error, after writing. The want, the design's published figures:
```go
vrWant{VRejected: 263472, RRejected: 252133, Rescued4: 9827, Kept4: 214472,
	Rescued6: 1512, Kept6: 3693, ARejected6: 33968, ImportAccepted: 978368}
```

- [ ] **Step 5: Run the tests and the checks**

Run: `GOWORK=off go test -count=1 -run 'TestJoinVR|TestVRControls|TestPair2VAgainstR' -v .`
Expected: PASS, `TestPair2VAgainstR` SKIP.
Then `scripts/check.sh` (alone, under the guard): passes.

- [ ] **Step 6: Commit**

```bash
git add pair2v_test.go
git commit -m "test: pair 2's V rejections joined with R"
```

### Task 2: The run and the aut-num check (controller)

**Files:**
- Create (not committed): `.data/pair2-v-runs.zsh` with steps `join` and `autnum`, modelled on `.data/provenance-pair2-runs.zsh` (prints the head commit, stops on a non-zero status).

- [ ] **Step 1: `join`**

`TestPair2VAgainstR` under the guard (TIMEOUT 1800, `go test -timeout 25m`) with V = `.data/stream/V2/routes.tsv.gz`, R = `.data/stream/R2/routes.tsv.gz`, A = `.data/provenance/A/routes.tsv.gz`, OUT = `.data`. Log: `.data/pair2-v-join.log`.
Expected: `ok`, guard `SUCCESS`, no control error; `.data/pair2-v-cross.txt` and `.data/pair2-v-rescued.tsv` written; `wc -l < .data/pair2-v-rescued.tsv` is 11339.

- [ ] **Step 2: `autnum`**

For every `.data/realdata/*.gz`, count the lines matching `^aut-num: *AS6762$` (`LC_ALL=C`, case-insensitive on the class name), and print each file's count. Log: `.data/pair2-v-autnum.log`.
Expected: only `ripe.db.aut-num.gz` holds it. If a non-RIR dump also does, the RIRs-first order (`realdata_registry_test.go`, `TestLoadRegistryPrecedenceAndSelection`) still decides; record it and the docs say so.

- [ ] **Step 3: Record**

Any control failure: stop and report to the maintainer. Otherwise note the logs in the ledger.

### Task 3: The hand-check (controller)

**Files:**
- Create (not committed): `.data/pair2-v-handcheck.txt`, every command and its output.

- [ ] **Step 1: Pick the route**

The first ipv6 key in `.data/pair2-v-rescued.tsv`. Its 4th field is the neighbour N; its 5th the prefix; the last AS of its 6th the origin.

- [ ] **Step 2: Show the clause**

AS6762's `mp-export:` (or `export:`) line toward N in `ripe.db.aut-num.gz`; it should name AS-SEABONE-V6 or AS-SEABONE.

- [ ] **Step 3: Trace the chain**

From that set, through the dumps, to the route: the route6 object for the prefix and origin (an RIR's, since both runs load only those), and the chain of sets from AS-SEABONE(-V6) to the origin. Name the link only a non-RIR dump holds, and show the RIR dumps lack it. One `LC_ALL=C grep -F -m1` of the key in `.data/stream/V2/rejected-missing.tsv` may show the sets V named missing for this route; nothing else reads that file.

- [ ] **Step 4: Record**

If no link held only by a non-RIR registry is found, say so in the file and report it: the docs then state the hand-check did not confirm the attribution.

### Task 4: The docs

**Files:**
- Modify: `docs/routecheck.md` (the "In V, each of 712 sets" item, about line 717; "What this means", about line 796; the "Not measured" V item, about lines 836-838), `CHANGELOG.md` (`[Unreleased]`, beside "Measured, pair 2's rejections without RADB"), `CLAUDE.md` (the pair-2 lines, about 366-368).
- Modify: `docs/superpowers/specs/2026-10-20-pair2-v-rejections-design.md`: an "Outcome" section at the top, with the figures and their logs.

**Interfaces:**
- Consumes: `.data/pair2-v-join.log`, `.data/pair2-v-cross.txt`, `.data/pair2-v-rescued.tsv`, `.data/pair2-v-autnum.log`, `.data/pair2-v-handcheck.txt`. Every figure comes from these; the logs are named beside them.

- [ ] **Step 1: Write**

- **The new item, under the V line:** of V's 263,472 rejections, how many R accepts, by family and A's outcome, and the controls that held. What R adds to V, in the design's words ("What R adds to V"). The rescue is by those objects as a whole; which set rescues which route is not measured. The hand-checked route, in one sentence.
- **The rest carry R's classes:** they are exactly R's 252,133, and run B rescues none of them, so: no gap; all unknown on AS-CONCERTAP; real for an RIR-objects filter if it is taken as not found.
- **"What this means":** after "V, which loads the RIRs alone, rejects 224,299", how many of those the non-RIR objects rescue.
- **"Not measured":** the V item becomes "which of the non-RIR objects rescues which of V's rejections".
- **CHANGELOG:** a section "Measured, pair 2's rejections in V", in the style of its neighbours; and line ~51's open question now points to it.
- **CLAUDE.md:** one sentence with the figures and the log.

- [ ] **Step 2: Check**

`grep -n "$HOME"` over every changed file: nothing. Each figure grep'd back to its log. `scripts/check.sh` passes (alone).

- [ ] **Step 3: Commit**

```bash
git add docs/routecheck.md CHANGELOG.md CLAUDE.md docs/superpowers/specs/2026-10-20-pair2-v-rejections-design.md
git commit -m "docs: pair 2's V rejections against R"
```
