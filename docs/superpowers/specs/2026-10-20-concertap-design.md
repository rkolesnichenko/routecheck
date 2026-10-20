# routecheck: was AS-CONCERTAP deleted? — design

Status: draft, 2026-10-20. A measurement, not a feature: the command and the library do not change.

## Why

One set keeps two published results "unknown": AS-CONCERTAP.

- **The missing-sets measurement** (docs/routecheck.md, "The listed routes", `.data/missing-sets-classify.log`):
  - 33,968 of its 106,529 tracked routes are "unknown";
  - all of them are pair 2's ipv6 export, against AS-SEABONE-V6, for one reason: AS-CONCERTAP is inconclusive.
- **Pair 2's rejections without RADB** (PR #19, `.data/pair2-rejections-classify.log`):
  - all 252,133 rejections in run R are "unknown" on AS-CONCERTAP alone;
  - taken as not found, all of them are "real for an RIR-objects filter". That is the labelled what-if table, not the
    headline.

**RIPE's whois history for it is an answer the lookup cannot read.** `--list-versions -T as-set AS-CONCERTAP` returns:

- the header "Version history for AS-SET object "AS-CONCERTAP"";
- an empty table: no version row, no "This object was deleted on" line, no `%ERROR`;
- the closing "served by" line.

`parseRIPEHistory` (missingsets_test.go) calls that "bad", so the set is "inconclusive" (cached answer:
`.data/missing-sets/lookup/cache/ripe/as-concertap.bad.txt`).

- RIPE's documentation says history goes back only to an object's last creation, and an object deleted long ago may
  show a deletion date with no rows before it.
- RIPE's REST interface has the same history as a structured list (`GET /{source}/{type}/{key}/versions`), each
  entry with a date, an operation and a `deleted` field. It may carry the deletion date that the whois text leaves
  out.

## The bar (the maintainer's)

**AS-CONCERTAP counts as "deleted" only if RIPE's own answer shows a dated deletion.**

Anything short of that leaves it "inconclusive" and the docs' figures and classes unchanged:

- an empty list;
- "not found" (404);
- an entry without a date;
- an error;
- a deletion followed by a later re-creation.

## Goal

Ask RIPE's REST history for AS-CONCERTAP.

- **If it shows a dated deletion:** put that answer into the lookup's method, so the tool says "deleted", not a hand
  check. Then reclassify both measurements and publish.
- **If it does not:** stop. Record the answer, and leave the method and the docs unchanged.

## Steps

1. **Probe** (live; needs the maintainer's go-ahead).
   - Ask `https://rest.db.ripe.net/ripe/as-set/AS-CONCERTAP/versions` for JSON.
   - If that does not show a dated deletion, also ask the same path with source `ripe-nonauth`. It is RIPE's too, and
     the whois query asked source RIPE alone.
   - At most 2 queries, one at a time, and no retry: an error or timeout on ripe is "no dated deletion" for this
     step, and ripe-nonauth is asked next.
   - Each query gets a line in the new lookup copy's `queries.log`, in its format, so the cap stays honest. Each
     answer is saved whole, with its HTTP status, under `.data/concertap/`.
2. **Decide.** Read each answer against the bar.
   - No dated deletion: stop after step 1. Record the answers in `.data/concertap/`, tell the maintainer, and change
     no code and no docs.
   - A dated deletion that step 3's reading rule already reads as "deleted": go on.
   - A dated deletion in some other shape (a top-level field, entries out of date order, a deletion entry without
     an operation): stop and show the maintainer the answer before any code. Only they may widen the reading rule,
     because a looser rule is how "inconclusive" could become "deleted".
3. **The method** (test code only, `missingsets_test.go`). A new RIPE REST step in the lookup.
   - **When it is asked:** only when RIPE's whois history is complete (it has the "served by" line) but empty: a
     header, no version row, no deletion line, no `%ERROR`.
     - Such an answer gets its own kind from `parseRIPEHistory`, "empty", instead of "bad".
     - Any other whois answer is read as today.
   - **What it asks:** the ripe source first, then ripe-nonauth only if the first gives no dated deletion. It uses
     the same cap, `queries.log`, per-query timeout and stop-after-5-inconclusive rule as the whois services, and its
     own cache directory, `cache/ripe-rest/`.
   - **How the answer is read** (`parseRIPEVersions`):
     - "deleted" with the date (UTC, `YYYY-MM-DD`): a version list whose last entry is a deletion with a date.
     - "exists": any ADD/UPD entry after the last deletion, or no deletion at all.
     - "none": a 404.
     - "bad": anything else, including a deletion entry without a parseable date.
   - **How the two sources combine** into one REST kind:
     - "deleted": at least one source says "deleted" and neither says "exists" or "bad". A 404 from the other
       source is fine; the date is the deleting source's.
     - Anything else, such as ripe "exists" with ripe-nonauth "deleted", is not "deleted".
   - **How it combines** in `classifySet`, as the whois deletion line combines today:
     - RADB "none" + whois "empty" + REST "deleted" is "deleted", with the date in the Deleted column.
     - Every other combination with "empty" stays "inconclusive".
   - **Tests** (offline, against an `httptest` server and fixtures):
     - The fixtures are the probe's real answers, plus answers built from RIPE's documented layout: a deleted entry,
       a re-created object, an empty list, a 404, a 500, a truncated body and a deletion without a date.
     - Each maps to its kind and its class.
     - The cap, the cache, the re-asking of an inconclusive answer and the stop rule are pinned for the REST service
       as they are for whois.
4. **The lookup run** (live; the same go-ahead covers it, as one measurement).
   - Run `TestMissingSetsLookup` on a new copy, `.data/concertap/lookup`, made from `.data/pair2-rejections/lookup`
     with its cache and `queries.log`.
   - IN names every list so far, as before.
   - Only AS-CONCERTAP is inconclusive (1 of 1,311 rows in that copy's `sets.tsv`), so the run asks only about it:
     RIPE whois, then RIPE REST. RADB's cached "none" is conclusive and is not asked again. With `ask`'s one retry
     of an inconclusive answer that is 3 to 6 queries; 2,579 of the 5,000 are used. The figure is an estimate. The
     hard bound is the run's limit, set to the lines already in `queries.log` plus 8, and the real count is
     recorded.
   - It must give AS-CONCERTAP "deleted" with the probe's date. If it does not, stop and tell the maintainer.
5. **Reclassify** (offline, `TestMissingSetsClassify`, with `ROUTECHECK_MISSINGSETS_DIR` set to the new copy).
   - **The missing-sets measurement:** its tracked routes, as in `.data/missing-sets-classify.log`. The 33,968 should
     move from "unknown" to "real for any IRR filter".
   - **Pair 2 in R:** its tracked routes, as in `.data/pair2-rejections-classify.log`, with `_RIR_ONLY`,
     `_A_ROUTES` and `_R_ROUTES`. The 252,133 should all become "real for an RIR-objects filter", which must equal
     the earlier what-if table.
   - No run B is needed: a deletion adds no set to load.
   - Any other change in a class's count stops the work and goes to the maintainer.
6. **Publish.**
   - In docs/routecheck.md: the missing-sets section's table and "What this means"; the pair-2 "Classified" block and
     "What this means"; and the provenance section's "Not measured" line about AS-CONCERTAP.
   - The CHANGELOG's `[Unreleased]` and CLAUDE.md.
   - Every figure names its log. The earlier figures stay, as what the whois answer alone gave.

## Constraints

- **Live queries** go to rest.db.ripe.net, and in step 4 also to whois.radb.net and whois.ripe.net. They need the
  maintainer's go-ahead before step 1, and approving this design is not that go-ahead.
  - One query at a time.
  - Plain HTTPS GET with `Accept: application/json` and no credentials.
  - Under the shared cap of 5,000.
- **The earlier measurements' files are not touched.** `.data/missing-sets/lookup` and
  `.data/pair2-rejections/lookup` stay as published; the work uses the copy `.data/concertap/lookup`.
- **The dumps stay the 2026-10-18 files.** The deletion date is recorded as RIPE gives it. As with the whois
  deletion line today, the method does not compare it with the dumps' day.
- **Code:** only `_test.go` files, docs, the CHANGELOG and CLAUDE.md change.
  - The parsers stay pure and are tested offline. The real network is touched only under
    `ROUTECHECK_MISSINGSETS_LIVE=1`.
  - The fixtures from the probe are RIPE's public data. They are committed as test data, with the date they were
    fetched.
- **Runs:** the classifier runs are light (about 400 MB, about 30 s), but go under the guard all the same, one at a
  time, never beside check.sh:
  `MEMGUARD_NORMAL_PRIORITY=1 ../rpsl/.superpowers/sdd/tools/memguard.sh 8 TIMEOUT env GOWORK=off GOMAXPROCS=4 GOMEMLIMIT=6GiB …`.
- **Figures:** every figure comes from a command run and names its log. No local home-directory paths in anything
  pushed.

## Non-goals

- Asking REST about any other set. None other is inconclusive.
- Changing the classes, the cap or the limit.
- Run V, other pairs, a release.

## Anti-goals

- Calling AS-CONCERTAP "deleted" from the probe alone: the published class comes from the lookup tool's own run
  (step 4).
- Reading a deletion into an empty list, a 404 or an undated entry.
- Building the REST step when the probe shows it would change nothing.

## Decided by me (the maintainer can overrule while reading)

1. **Probe before building.** The JSON layout of a deleted entry is documented only as "may include a `deleted`
   field". A parser written blind could call the real answer "bad". Looking first costs 1–2 queries, and no code
   gets written for an answer that settles nothing.
2. **ripe-nonauth as a second source.** The whois query asked source RIPE only. A deletion in RIPE-NONAUTH is still
   RIPE's own dated answer.
3. **The REST step is a general rule, not a special case for one name.** Any set whose RIPE whois history is
   complete but empty gets it. Today that is only AS-CONCERTAP.
4. **A new lookup copy,** `.data/concertap/lookup`, so both published measurements stay reproducible from their own
   directories.
5. **No date check against the dumps' day,** to match how the whois deletion line is read today.

6. **The base.** The work builds on `main` once the pair-2 wording fixes (branch `pair2-wording`) are merged, since
   step 6 rewrites the same paragraphs.
7. **The settled reading of the reviewer's questions** (above, in steps 2 to 4): no retry in the probe; an
   unexpected shape stops for the maintainer; how the two sources combine; the query counts are estimates under a
   hard limit.

## Left to the builder

- The step 1 probe script and where it writes, under `.data/concertap/`.
- The HTTP client's details: timeout, redirects refused or followed, and the `.json` suffix against the Accept header.
- How the REST service plugs into `lookupRun` (a second dial-like hook for HTTP, so tests use `httptest`).
- The docs' wording, in the plain style of the missing-sets section.
