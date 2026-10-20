# AS-CONCERTAP REST History Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Find out from RIPE's REST version history whether AS-CONCERTAP was deleted. If it was, make that the lookup method's own answer, and reclassify the two measurements it holds "unknown".

**Architecture:**
- **Task 1 (controller, live):** a probe, at most 2 HTTPS GETs. It decides whether any code is written.
- **Task 2 (subagent):** if the probe shows a dated deletion, a RIPE REST step added to the lookup in `missingsets_test.go`. It covers a whois history that is complete but empty, with offline tests against `httptest`.
- **Task 3 (controller):** one live lookup run on a new copy of the lookup directory and two offline reclassifications, each checked key by key against the published output.
- **Task 4 (subagent):** the docs.

**Tech Stack:** Go (test code only), `net/http`, `net/http/httptest`, `encoding/json`; zsh scripts under `.data/` (not committed).

**Spec:** `docs/superpowers/specs/2026-10-20-concertap-design.md`

## Global Constraints

- **Live queries** (rest.db.ripe.net, whois.ripe.net) only after the maintainer's explicit go-ahead, which approving this plan is not.
  - One query at a time.
  - HTTPS GET with `Accept: application/json` and no credentials.
  - Every query is a line of the copy's `queries.log`, under the shared cap of 5,000 (`queryCap`).
- **The bar (the maintainer's):** "deleted" only when RIPE's own answer shows a dated deletion.
  - An empty list, a 404, an undated entry, an error, or a deletion followed by a re-creation leaves AS-CONCERTAP "inconclusive", and the docs' figures and classes unchanged.
- **Files the work must not touch:** `.data/missing-sets/lookup` and `.data/pair2-rejections/lookup`. The work uses `.data/concertap/lookup`.
- **Code:** only `_test.go` files, docs, `CHANGELOG.md` and `CLAUDE.md` change. The real network is reached only under `ROUTECHECK_MISSINGSETS_LIVE=1`.
- **Runs under the guard,** one at a time, never beside check.sh:
  `MEMGUARD_NORMAL_PRIORITY=1 ../rpsl/.superpowers/sdd/tools/memguard.sh 8 TIMEOUT env GOWORK=off GOMAXPROCS=4 GOMEMLIMIT=6GiB …`
- **Figures:** every figure comes from a command run and names its log. No local home-directory path in anything committed or pushed.
- **Branch:** `concertap`, from `main` at 58c2dc4. Commit on the branch, never on main.

## Review Focus

1. **The JSON shape of a deleted entry is not quite as fixtured.** For example the `deleted` field is a string date on one entry and `null` on the others, or the entries arrive with no revision number. Expected: decoding reads it right or calls it "bad", never "deleted" by accident. *Test:* `TestParseRIPEVersions` (Task 2) has the probe's real answer and the "deletion without a date" and "unknown shape" cases.
2. **A re-created object.** A deletion followed by an ADD/UPD must read as "exists", not "deleted". *Test:* `TestParseRIPEVersions`, the "re-created" case.
3. **A redirect or an HTML error page from the REST service.** Expected: "bad", never "none" and never "deleted". *Test:* `TestRESTGet` (Task 2): a 302 is not followed, and an HTML 200 reads as "bad".
4. **The REST step widening the whois method by accident.**
   - A whois history with version rows must still be "exists" and never reach REST.
   - A whois `%ERROR` other than 101 must still be "bad".
   - *Test:* `TestParseRIPEHistory` gains the "empty" case, and the existing cases must pass unchanged; `TestLookupREST` checks the REST service is never asked unless whois said "empty".
5. **A cached `.bad.txt` from earlier runs.** The copy's `cache/ripe/as-concertap.bad.txt` holds the empty answer. Expected: whois is asked again (as today), and "empty" is now conclusive, so it is cached as `.txt`. *Test:* `TestLookupREST`, a "prior .bad.txt" case.

---

### Task 1: The probe (controller; live; needs the go-ahead)

**Files:**
- Create (uncommitted): `.data/concertap-runs.zsh` with subcommands `copy | probe | lookup | classify-ms | classify-p2`.
- Answers: `.data/concertap/probe/ripe.txt` and `.data/concertap/probe/ripe-nonauth.txt`.

- [ ] **Step 1: `copy`.** `cp -Rp .data/pair2-rejections/lookup .data/concertap/lookup`, refused if the target exists. Print the line counts of `queries.log` and `sets.tsv` (expected: 2,579 and 1,311) to `.data/concertap-copy.log`.
- [ ] **Step 2: ask the maintainer for the go-ahead.** One message: the URLs, at most 2 queries, the bar. Wait for the answer.
- [ ] **Step 3: `probe`.** Ask `curl -sS --max-time 30 -H 'Accept: application/json' -w '\n%{http_code}' https://rest.db.ripe.net/ripe/as-set/AS-CONCERTAP/versions`, with no redirect following.
  - Save each answer as `HTTP <code>\n<body>` (the layout Task 2's `restGet` writes).
  - Append each query to `.data/concertap/lookup/queries.log` as `time\tripe-rest\t/ripe/as-set/AS-CONCERTAP/versions\t<bytes>\t<error or empty>`.
  - Ask `/ripe-nonauth/as-set/AS-CONCERTAP/versions` (service `ripe-nonauth-rest`) only if the first answer is not a dated deletion. No retry.
  - Log: `.data/concertap-probe.log`.
- [ ] **Step 4: decide, by reading the answers against the bar.** Record it in the ledger as `Probe: <answers in one line each> → <go | stop | shape>`.
  - **stop** (no dated deletion): tell the maintainer, and end the plan here. Keep `.data/concertap/`, and commit nothing beyond the design and plan. Whether that branch is merged is the maintainer's call.
  - **shape** (a dated deletion in a shape that "the last entry is a deletion with a date" does not read): stop and show the maintainer the answer before Task 2.
  - **go:** Task 2. The dispatch carries both answer files' paths, to be used verbatim as fixtures.

### Task 2: The RIPE REST step (subagent; offline)

**Files:**
- Modify: `missingsets_test.go`:
  - `parseRIPEHistory` (~:930);
  - `lookupRun` (~:1081);
  - `newLookupRun` (~:1107);
  - `ask` (~:1137);
  - `lookupSet` (~:1224);
  - `testRun` (~:209);
  - `TestMissingSetsLookup`'s call (~:638) and its doc comment (~:596).
- Test: `missingsets_test.go` (new tests beside the existing ones).

**Interfaces:**
- **Consumes:** the probe's answer files (Task 1), each `HTTP <code>\n<body>`.
- **Produces** (Task 3 runs these unchanged):
  - `parseRIPEHistory` returns a new kind, `"empty"`;
  - `parseRIPEVersions(text string) (kind, deleted string)`;
  - `restVerdict(ripe, ripeDate, nonauth, nonauthDate string) (kind, date string)`;
  - a `lookupRun.get func(ctx context.Context, url string) (string, error)` field and `lookupRun.restBase string`;
  - `newLookupRun(dir string, dial dialFunc, get func(context.Context, string) (string, error), radbAddr, ripeAddr, restBase string, limit int)`;
  - `restGet(client *http.Client) func(context.Context, string) (string, error)`;
  - the constant `ripeRESTBase = "https://rest.db.ripe.net"`;
  - cache directories `cache/ripe-rest` and `cache/ripe-nonauth-rest` (one per source, so the two answers for one set
    never share a file; the spec's single `cache/ripe-rest/` is split this way);
  - the live test's optional `ROUTECHECK_MISSINGSETS_MAX_QUERIES`;
  - `queries.log` service names `ripe-rest` and `ripe-nonauth-rest`.

- [ ] **Step 1: Write the failing tests.**
  - **`TestParseRIPEHistory`** gains a case: the copy's `.data/pair2-rejections/lookup/cache/ripe/as-concertap.bad.txt` text, inlined as a constant `ripeHistEmpty` (recorded 2026-10-19), gives `("empty", "")`.
    - A header with no "served by" line stays `"bad"`.
    - Every existing case is unchanged.
  - **`TestParseRIPEVersions`**, table-driven, `(kind, deleted)`:
    - the probe's real answer(s), inlined as constants with the fetch date: the decided kind and date;
    - documented-layout answers in the same JSON shape as the probe's: one ADD/UPD → `"exists"`; a dated deletion → `"deleted", "YYYY-MM-DD"` (UTC); a deletion then an ADD/UPD → `"exists"`; an empty version list → `"bad"`; a deletion entry with an empty or unparseable date → `"bad"`;
    - `HTTP 404` → `"none"`; `HTTP 500` → `"bad"`; `HTTP 200` with an HTML body → `"bad"`; a truncated JSON body → `"bad"`; `HTTP 302` → `"bad"`.
  - **`TestRESTVerdict`**:
    - (deleted d, -) → (deleted, d);
    - (none, deleted d) → (deleted, d);
    - (none, none), (none, exists), (none, bad), (exists, -), (bad, -) → not "deleted" (kind `"inconclusive"`, date `""`).
    - `-` means not asked, the empty string.
  - **`TestRESTGet`** against `httptest.NewServer`:
    - it sends `Accept: application/json`;
    - it returns `HTTP 200\n<body>`, `HTTP 404\n<body>`;
    - it does not follow a 302 (returns `HTTP 302\n…`);
    - it cuts at `whoisMaxAnswer` with an error;
    - a closed server gives an error.
  - **`TestLookupREST`**, through `lookupSet` with the fake whois (`fakeWhois`) and an `httptest` REST server, checking `sets.tsv` row, `queries.log` lines and cache files:
    - whois RADB none + RIPE empty + REST ripe deleted → `Class "deleted"`, `Sub "REST history"`, `Deleted` the date. One `ripe-rest` line, no `ripe-nonauth-rest` line.
    - RADB none + RIPE empty + ripe 404 + nonauth deleted → "deleted", two REST lines.
    - RADB none + RIPE empty + ripe exists → "inconclusive", no nonauth line.
    - RADB none + RIPE empty + ripe 500 twice → "inconclusive"; `.bad.txt` kept; `fails` counts toward the stop rule on the REST base.
    - RIPE history with version rows, or the deletion line, or 101 → no REST line at all (Review Focus 4).
    - A prior `cache/ripe/<name>.bad.txt` holding the empty answer: whois asked again, the answer cached as `.txt` (Review Focus 5).
    - Cap: with `limit` reached after the whois queries, REST is not asked and the set is "not looked up".
- [ ] **Step 2: Run them; they fail.** Run `GOWORK=off go test -count=1 -run 'TestParseRIPEHistory|TestParseRIPEVersions|TestRESTVerdict|TestRESTGet|TestLookupREST' .`. They should fail to compile (the new names are undefined).
- [ ] **Step 3: Implement.**
  - **`parseRIPEHistory`:** a complete answer with the "Version history for" header, no version row, no deletion line and no `%ERROR` is `"empty"`.
  - **`ask`:** takes `do func(context.Context) (string, error)` in place of building a whois query itself; `addr` stays the stop-rule key and `query` the logged text. The whois callers pass a closure over `whoisQuery`.
  - **`lookupSet`:** when the RIPE history kind is `"empty"`:
    - ask `ripe-rest` (`restBase + "/ripe/" + class + "/" + name + "/versions"`, logged as the path);
    - if that is `"none"`, ask `ripe-nonauth-rest`;
    - combine with `restVerdict`;
    - on `"deleted"`, pass `ripe = "deleted"` and the date to `classifySet`, and set `Sub = "REST history"` on the row; otherwise `"empty"` reaches `classifySet` and falls to "inconclusive" (no change to `classifySet`).
    - The conclusive test for both REST services is `kind != "bad"`; for whois `ripe` it stays `kind != "bad"`, so `"empty"` is conclusive.
  - **`restGet`:** `CheckRedirect` returns `http.ErrUseLastResponse`; the body is read through `io.LimitReader(whoisMaxAnswer+1)` and is an error past it.
  - **The live test** passes `restGet(&http.Client{Timeout: 30 * time.Second})` and `ripeRESTBase`. It reads
    `ROUTECHECK_MISSINGSETS_MAX_QUERIES` (optional, a positive integer: the most queries this run may ask). When it
    is set, `r.limit = min(queryCap, r.used+n)`; a bad value fails the test.
  - **The doc comment** of `TestMissingSetsLookup` says when REST is asked and how it is read.
- [ ] **Step 4: Run them; they pass.** Same command as Step 2: PASS. Then `GOWORK=off go test -count=1 .` (every existing lookup and classify test unchanged), then `GOMAXPROCS=4 scripts/check.sh` → `check: ok` (log `.data/check-concertap-t2.log`).
- [ ] **Step 5: Commit.** `git add missingsets_test.go && git commit -m "missingsets: ask RIPE's REST history when the whois history is empty"`.

### Task 3: The lookup run and the reclassifications (controller)

**Files:**
- Scripts and logs (uncommitted):
  - `.data/concertap-runs.zsh lookup | classify-ms | classify-p2`;
  - logs `.data/concertap-lookup.log`, `-classify-ms.log`, `-classify-p2.log`;
  - outputs `.data/concertap/routes-ms.tsv`, `.data/concertap/routes-p2.tsv` (each `routes.tsv` copied out after its run, since both runs write `DIR/routes.tsv`).

- [ ] **Step 1: `lookup`** (live; covered by the Task 1 go-ahead).
  - Run `TestMissingSetsLookup` with:
    - `ROUTECHECK_MISSINGSETS_DIR=.data/concertap/lookup`;
    - IN the same list as `.data/pair2-rejections-runs.zsh rounds` (the base list plus `.data/pair2-rejections/B1/missing-sets.tsv`);
    - `ROUTECHECK_MISSINGSETS_MAX_QUERIES=8` (Task 2).
  - Expected:
    - AS-CONCERTAP "deleted / REST history" with the probe's date;
    - every other row of `sets.tsv` byte-identical to `.data/pair2-rejections/lookup/sets.tsv` (`diff` shows one line);
    - 3 to 6 queries, recorded.
  - Anything else: stop and tell the maintainer.
- [ ] **Step 2: `classify-ms`** (offline, under the guard).
  - Run `TestMissingSetsClassify` with `DIR=.data/concertap/lookup`, `TRACKED=.data/missing-sets/B4/tracked.tsv` and the published run's `SUBSET`, recovered from that run's record. If it cannot be recovered, say so in the ledger and compare the "all" column only.
  - Expected, against `.data/missing-sets/lookup/routes.tsv` key by key: exactly the 33,968 keys move from "unknown" to "real for any IRR filter", and no other line changes. The "all" table reads 0 / 0 / 106,529 / 0.
- [ ] **Step 3: `classify-p2`** (offline, under the guard).
  - Run with `TRACKED=.data/pair2-rejections/B1/tracked.tsv`, `_RIR_ONLY=1` and the same `_A_ROUTES`/`_R_ROUTES` as `.data/pair2-rejections-runs.zsh classify`, without `_TAKE_NOT_FOUND`.
  - Expected:
    - all 252,133 are "real for an RIR-objects filter";
    - key by key against `.data/pair2-rejections/lookup/routes.tsv`, every key moves from "unknown" to that class;
    - the split tables equal the published what-if tables in `.data/pair2-rejections-classify.log`.
- [ ] **Step 4: Ledger.** One line per step with its log and figures. Any mismatch stops the work and goes to the maintainer.

### Task 4: The docs (subagent)

**Files:**
- Modify: `docs/routecheck.md`:
  - the missing-sets section: "The listed routes" table and its sums, "What this means", the AS-CONCERTAP paragraph;
  - the pair-2 "Classified" block and "What this means";
  - the provenance "Not measured" line about AS-CONCERTAP.
- Modify: `CHANGELOG.md` `[Unreleased]` (a new "Measured, AS-CONCERTAP" entry, and "Added" for the test code), and `CLAUDE.md` (the missing-sets and pair-2 notes).

- [ ] **Step 1: Write.** The brief carries the Task 3 ledger lines and log paths.
  - Each figure names its log.
  - The earlier figures stay, as what the whois answer alone gave, beside the new ones.
  - The what-if table becomes the measured result; the docs keep saying it was first a what-if.
  - The plain style of the missing-sets section; no local home-directory path.
- [ ] **Step 2: Check.** Every number in the diff is traced to a log, and the controller recounts three of them by hand. `GOMAXPROCS=4 scripts/check.sh` gives `check: ok` (`.data/check-concertap-t4.log`).
- [ ] **Step 3: Commit.** `git commit -m "docs: AS-CONCERTAP was deleted; the two measurements reclassified"`. Adjust the wording if the class names differ.
