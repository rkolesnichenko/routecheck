# routecheck: do pair 2's rejections without RADB stand? — design

Status: draft, 2026-10-19. A measurement, not a feature: the command and the library do not change.

## Why

The registry-provenance comparison with pair 2 (PR #18, docs/routecheck.md "How much rests on unverified
registries") found the largest single effect of the measurement:

- **The rejections.** Without the unverified route objects (run R), 252,133 of pair 2's export routes are rejected:
  - 214,472 that are undecided in A (AS-SEABONE over the limit);
  - 3,693 that are accepted in A;
  - 33,968 that are rejected in A too.

  Their sum is 252,133 (`.data/stream-R2.log`; `.data/provenance-AR2.log`).
- **The missing sets.** Every one of the rejections names missing sets in a failing clause:
  - 1,276 distinct sets in all. Every rejection names the same 739, all of them looked up earlier (367 deleted, 347
    not found, 24 found elsewhere, 1 inconclusive: AS-CONCERTAP).
  - 469 of the 1,276 were never looked up (`.data/stream/R2/missing-sets.tsv` against
    `.data/missing-sets/lookup/sets.tsv`).

The docs cannot yet say whether these rejections stand. A rejection against a missing set is one of two things:

- **A gap:** the route would be accepted if routecheck loaded a set it does not hold (24 known, maybe more among the
  469).
- **Real for any IRR filter:** the missing sets exist nowhere, so bgpq4 or rpslq would reject the route too.

The maintainer wants to know which, before the "What this means" paragraph leans on the 214,472.

## Goal

Classify pair 2's 252,133 R rejections with the missing-sets measurement's method and classes (design
`docs/superpowers/specs/2026-10-19-missing-sets-design.md`; docs/routecheck.md "The rejections against missing
sets"). The classes are gap, real, real for any IRR filter and unknown, each with its reasons, renamed for R (see "Settled after the builder check", 1).

1. **Look up the sets never looked up,** live, with the existing `TestMissingSetsLookup`. Its cache answers every
   set already looked up without a query. AS-CONCERTAP's inconclusive answer is asked again, as the tool does
   every run.
2. **Run B on pair 2 in R:** the real-data test with `ROUTECHECK_REALDATA_PAIRS=2`, `_ROUTES_FROM` the five RIRs,
   `_EXTRA` the found copies and `_TRACK` R2's `rejected-missing.tsv`.
   - Round by round, as before: lookup → B → the new names B still misses. It stops at closure, at the cap, or
     after 5 rounds.
3. **Classify** with `TestMissingSetsClassify`. The figures are split three ways by A's outcome:
   - undecided in A (214,472);
   - accepted in A (3,693);
   - rejected in A too (33,968). These were already classified "unknown" from A's run; the reclassification is a
     cross-check.
4. **Publish** in docs/routecheck.md (the pair-2 part of the provenance section, and "What this means"), the
   CHANGELOG's `[Unreleased]` and CLAUDE.md. Every figure names its log.

## Constraints

- **Live queries, to whois.radb.net and whois.ripe.net.** These go to other people's services, so they need the
  maintainer's go-ahead, and approving this design is not that go-ahead. The plan asks for it explicitly before the
  first lookup.
  - The tool's own limits stay: one query at a time and one connection per query; after 5 inconclusive answers in a
    row from one service, the run stops asking that service.
  - **The cap stays at 5,000 queries,** counted across both measurements (`queries.log` already holds 1,641). That
    leaves 3,359.
  - Each new set costs at most 3 queries, so the 469 need at most 1,407; later rounds add a little.
- **The earlier measurement's files are not touched.** The lookup works on a copy, `.data/pair2-rejections/lookup`,
  made from `.data/missing-sets/lookup` with its cache and `queries.log`. The published 842-set `sets.tsv` stays as
  it is.
- **The dumps stay the 2026-10-18 files,** with the same pairs and seed. "Found elsewhere" counts only copies dated
  on or before the dumps' day, as the earlier design settled.
- **Runs:** every heavy run under the guard, one at a time, never beside check.sh:
  `MEMGUARD_NORMAL_PRIORITY=1 ../rpsl/.superpowers/sdd/tools/memguard.sh 8 TIMEOUT env GOWORK=off GOMAXPROCS=4 GOMEMLIMIT=6GiB …`.
  - Pair 2 alone in R peaked at 5,337 MB. The extra objects are a few hundred.
  - R2's `rejected-missing.tsv` is 5,067,157,084 bytes. TRACK and the classifier must stream it, or keep only its
    keys and set lists. The builder checks this before running.
- **Code:** only `_test.go` files, docs, the CHANGELOG and CLAUDE.md change. The real-data test today refuses
  `_ROUTES_FROM` together with `_EXTRA`. That refusal is lifted:
  - the extra dump's route and route6 objects are dropped like any other registry's not named in `_ROUTES_FROM`;
  - its sets are loaded;
  - a test pins both.
- **Figures:** every figure comes from a command run and names its log. No local home-directory paths in anything
  pushed.

## Non-goals

- Run V. Its missing sets include 362 that exist in the non-RIR dumps V does not load. That is a different question.
- Other pairs.
- Changing the method, the classes, the cap, or the limit (2,097,152).
- A release.

## Anti-goals

- Calling a rejection "real" or "a gap" beyond what the method measured. "Unknown" is a valid answer and is
  published as such.
- Promoting AS-CONCERTAP from inconclusive on the strength of the earlier hand check alone (see "Decided by me", 2).

## Decided by me (the maintainer can overrule while reading)

1. **R only, not V.** The question is "without RADB's route objects", which is R.
2. **AS-CONCERTAP stays inconclusive under the method,** so any rejection still naming it is "unknown".
   - It is named by every rejection, so under the method no rejection can be "real for an RIR-objects filter" while it
     stays inconclusive. The figures would then be "gap" and "unknown" only.
   - The docs therefore also give a labelled sensitivity line: the split if AS-CONCERTAP is taken as not found. The
     earlier hand check found no object of that name in RIPE (`.data/missing-sets/concertap-ripe-obj.txt`), nor in
     any of whois.radb.net's 19 sources. The method's figures stay the headline.
3. **The copy of the lookup directory** keeps both measurements reproducible. Sharing `queries.log`'s history keeps
   the cap honest.
4. **The split by A's outcome** comes from the keys: A's outcome per key in `.data/provenance/A/routes.tsv.gz`,
   joined with R2's tracked keys.

## Settled after the builder check *(my calls)*

1. **In R, the classes mean "for a filter built from RIR route objects only".** A rejection in R can come from
   the route objects R drops, not only from missing sets, so the earlier labels do not transfer as they are:
   - **gap:** accepted in run B, once the found sets are loaded;
   - **real without the unverified route objects:** rejected in B, with no missing set left;
   - **real for an RIR-objects filter:** rejected in B, and every missing set left is deleted or not found;
   - **unknown:** with its reasons.

   A's outcome does not override a class. It stays a dimension of the split, so a route accepted in A and "real" in
   R reads correctly: it rests on unverified route objects.
2. **Every class also gets a sub-count by the route-object answer, in A and in R** (yes → no, no → no, and the
   rest). This shows how much of each class is about the dropped objects at all.
   - The builder check's join found that of the 214,472 ipv4 routes undecided in A, 82,415 are "yes" in A and
     "no" in R, and 125,607 are "no" in both. That is preliminary and must be recounted. A route with "no" in both
     is not rejected because RADB was dropped; it is undecided in A only because of the limit.
     Corrected after the final review: the route-object answer is exact (prefix, origin) and says nothing about filter membership; 212 ipv6 'no → no' routes accepted in A are rejected in R.
   - The "What this means" paragraph must say this. The 214,472 are not all a RADB effect.
3. **The split by A's outcome follows the address family.** The 214,472 are ipv4, and the 3,693 and the 33,968
   are ipv6. The docs say so.
4. **The 33,968 are a control.** R2's ipv6 set list equals A's pair-2 list (the same 748 sets, all looked up
   before), so the classifier must again give "unknown, inconclusive set" for all of them. A mismatch stops the
   work, and it goes to the maintainer.
5. **A second control, with an empty `_EXTRA`.** Run B on pair 2 in R without the found copies must reproduce R2's
   TOTALS and its rejected keys, before any B with the found copies is trusted. It runs on the current code, against
   R2 made at ae7d034 (since then only docs and `provenance_test.go` changed).
6. **Memory: tracked lines carry set lists by reference.** R2 has two distinct set lists, 1,267 sets on every ipv4
   line and 748 on every ipv6 line. Held whole, B's tracked lines (in the test's `realOut`) and the classifier's
   `readTracked` would each take about 5 GB, which is over the guard with pair 2's 5,337 MB.
   - The test code interns the lists (or writes a list id) in both places.
   - The output must stay what the earlier measurement's tests pin, or those tests change with it.
7. **The lookup's IN names every list so far:** A's, B1–B4's, R2's and this measurement's rounds. `lookupAll`
   rewrites `sets.tsv` and `extra.db.gz` from its IN alone, so leaving out the earlier lists would drop the 842 rows
   and the found copies.

## Left to the builder

- How the split by A's outcome is computed: a key-file option for the classifier, or an offline join in test code.
- The rounds script, modelled on `.data/missing-sets-rounds.zsh`.
- The wording of the docs, in the plain style of the missing-sets section.
