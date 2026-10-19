# routecheck: are the rejections against missing sets real? — design

Status: draft, 2026-10-19. A measurement, not a feature: the command's behaviour and output do not change.

## Why

The maintainer wants to know whether routecheck's rejections are real.

The every-registry run at `-max-prefixes 2097152` (`.data/realdata-max-prefixes.log`, 2026-10-18 dumps)
rejected 106,712 export routes. 106,526 of them are counted "rejected with a missing set in a failing
clause": the filter that said no names a set that none of the 16 loaded registries holds. 59,395 of
those are new since v0.4.0 lets the over-limit filters be decided. The log names 808 distinct missing
sets on export and 1 on import (`FLTR-BOGONS-V6`, 3 routes).

A missing set contributes nothing to its filter, so each of those rejections is one of two things:

- a gap in what routecheck loads: the set exists somewhere, and with it the route would be accepted;
- what the registered data says: the set exists nowhere, or exists and still does not cover the route.

Today the docs can only say "read them as rejections against incomplete filters" and list "which of
the newly rejected routes would be accepted if the missing sets existed" as not measured. This design
measures it.

### What a first look found (2026-10-19, by hand)

- Five of the most-cited sets (`AS-ISPSERVICES`, `AS-STEFFANN-IPV4`, `AS44477:AS-DOWNSTREAMS`,
  `AS-INFRASIO`, `AS-3DATA-S21`) are not objects in any loaded dump. Two of them occur in `radb.db.gz`
  only as `members:` values.
- `whois.radb.net` `!s-lc` lists 20 sources: RADB, LACNIC, IDNIC, AFRINIC, RIPE, RIPE-NONAUTH, BELL,
  NTTCOM, ALTDB, PANIX, NESTEGG, LEVEL3, ARIN, JPIRR, BBOI, CANARIE, REACH, TC, APNIC, RPKI.
  routecheck loads none of IDNIC, RIPE-NONAUTH and LEVEL3.
- RADB has neither `AS-ISPSERVICES` nor `AS-3DATA-S21` in any of its sources.
- RIPE's version history (`--list-versions`):
  - `AS-STEFFANN-IPV4`: "This object was deleted on 2024-02-09T21:50:56Z".
  - `AS-3DATA-S21`: "no entries found".
  - `AS-ISPSERVICES`: an answer with the banner and nothing else, which is neither of the above.

So the sets fall into more than "exists / doesn't exist", and one blank answer already shows that a
lookup can be inconclusive.

## Goals

1. **The full list.** Every distinct missing set on both directions, with the number of rejected routes
   whose failing clauses name it, written to a file by the real-data test. The log today prints only
   the top 20.

2. **Each set classified** into exactly one class, with the evidence kept (source, `created:`,
   `last-modified:`, deletion date, the raw answer):

   | class | meaning |
   |---|---|
   | held but refused | an object of that name is in a loaded dump, but rpsl treats it as missing (another class, a scope from another registry) |
   | elsewhere | found in a source routecheck does not load; marked "newer than the dumps" when it was created after 2026-10-18 |
   | deleted | RIPE's history says it was deleted, with the date |
   | not found | no source on `whois.radb.net` has it, and RIPE has no history of it |
   | inconclusive | a lookup failed, timed out, or answered with neither an object nor "no entries" |

   "Deleted" versus "never existed" can be told apart only where history is published (RIPE). Elsewhere
   the class is "not found", and the docs say so.

3. **The closure.** A set found elsewhere names further sets. Look those up too, round by round, until no
   new name appears or a bound is hit. Each round's count is reported, and hitting a bound is reported.

4. **Each rejected route classified.** Run the real-data test twice on the same dumps at 2,097,152:

   - run A, as today;
   - run B, with the objects found elsewhere (the whole closure) added as one extra dump, last in
     precedence.

   Every route A rejected with a missing set in a failing clause then gets exactly one class:

   | class | condition in run B |
   |---|---|
   | gap | accepted |
   | real | rejected, and no failing clause names a missing set |
   | real for any IRR filter | rejected, and every missing set in its failing clauses is "deleted" or "not found" |
   | unknown | anything else: rejected with a set in a failing clause that is not "deleted" or "not found", the report unevaluable, the route Undecided, or no verdict in B; each reason has its own sub-count (see "Settled after the builder check") |

   Report the counts for all 106,526 export routes (and the import ones), and separately for the 59,395
   that v0.4.0 newly decided. Each set of counts sums to its total, and the docs show the sum.

   "Real for any IRR filter" is its own class on purpose. A filter built from the IRR (bgpq4, rpslq)
   would drop these routes too, so they are rejected in practice. What the policy's author meant cannot
   be read from the data.

5. **Published.** The answer replaces the "not measured" line in docs/routecheck.md's Known
   limitations. The CHANGELOG's `[Unreleased]` gets a Measured section. Every figure names its log.

## Constraints

- **Live lookups are polite.**
  - One connection at a time to each service: `whois.radb.net` and `whois.ripe.net`.
  - At most 5,000 queries in the whole measurement (the closure included); hitting the cap is reported.
  - Every answer is cached under `.data/` with its query time, so a re-run asks nothing again.
- **Heavy runs as always:** the real-data runs go one at a time under the memory guard, at normal
  priority (`MEMGUARD_NORMAL_PRIORITY=1`), with an 8 GB cap, `GOMAXPROCS=4` and `GOMEMLIMIT=6GiB`.
  Never beside check.sh.
- **Same inputs:** runs A and B use the 2026-10-18 dumps in `.data/realdata` (MANIFEST unchanged) and
  `ROUTECHECK_REALDATA_MAX_PREFIXES=2097152`.
- **Third-party objects stay out of git.** The fetched RPSL and the extra dump stay in `.data/`. Only
  counts, set names and dates go into docs.
- **No local home-directory paths** in anything committed or pushed.
- **Every figure comes from a command run, and names its log.**

## Non-goals

- Changing the command: no new option, no new class of result, no loading of extra sources.
- Loading IDNIC, RIPE-NONAUTH or LEVEL3 whole. Route objects that live only there remain unseen. The
  results say that a route counted "real" could still be covered by such a route object. Measuring that
  is a separate question.
- Deciding what to do about the answer. "Load more registries" and "say 'filter incomplete'" are
  follow-ups, chosen after the numbers are in.
- A release. The change is test code, a script and docs; whether it ships in a release is the
  maintainer's call after the PR.

## Anti-goals

- Counting "not found" as "never existed" outside RIPE's namespace.
- Turning an inconclusive or failed lookup into any other class.
- Hiding a bound: a query cap or closure round limit that was hit must show in the results.
- Mixing in the passage of time silently. An object created after the dumps is marked as such, and is
  not counted as a registry gap.

## Decided by me (the maintainer can overrule while reading)

- Both directions and all 106,526 export routes, with the 59,395 as a subset. The method costs the same,
  and the question "are the rejections real" is wider than the newly decided ones.
- Lookups go to `whois.radb.net` (all 20 of its sources) and `whois.ripe.net` (version history). No other
  services.
- Run B adds only the found objects (the closure), not whole extra registries.
- The four route classes and the five set classes above.
- The query cap of 5,000 and one connection per service.
- No release unless the maintainer asks.

## Settled after the builder check *(my calls)*

1. **Objects newer than the dumps stay out of run B.**
   - An object's date is its newest of `last-modified:`, `created:` and the latest `changed:` date.
   - It goes into B only if that date is 2026-10-18 or earlier, so B holds only what existed in that
     form when the dumps were taken.
   - An object with no date at all goes in, and the number of undated objects is reported (LEVEL3, for
     one, is frozen).
   - A route rejected in B because its failing clause names a newer set is "unknown". That reason gets its
     own sub-count (see 3).
2. **A set found live in a source routecheck does load, but absent from that source's dump, is "elsewhere".**
   - It is reported as its own sub-count, "in a loaded source, not in its dump", beside the IDNIC,
     RIPE-NONAUTH and LEVEL3 ones.
   - It follows the same date rule for run B. It is still a gap in what routecheck loaded.
3. **"Unknown" is reported with a sub-count per reason**, so no bound is hidden. The reasons:
   - an inconclusive set;
   - a held-but-refused set;
   - a newer set;
   - a set never looked up because the query cap or the round limit was hit;
   - a found set rpsl still treats as missing in B;
   - a report unevaluable in B;
   - the route Undecided in B;
   - the pair with no verdict in B (a timeout).

   A route with more than one reason goes to the first in this order. The sub-counts sum to "unknown".
4. **If the guard stops run B, the cap stays at 8 GB.**
   - B is rerun in shards of pairs, one shard per process, each under the guard. The test needs a way to
     select pairs for this.
   - If a shard still does not fit, its pairs' routes are "unknown (no verdict in B)", and the docs say
     why.
5. **When the services disagree, found wins.**
   - Otherwise any inconclusive lookup makes the set "inconclusive". "Deleted" needs RIPE's history to
     say so, and "not found" needs every lookup to answer "no entries".

Also answered by the data: the 59,395 are the export rejections in the 10 pairs that were over the limit
at the default. Those pairs rejected 0 export routes at the default (`.data/realdata-set-limits.log`)
and 59,395 at 2,097,152 (`.data/realdata-max-prefixes.log`), summed over their 20 export lines. The
other 50 pairs are identical (`.data/max-prefixes-same-pairs.log`).

## Left to the builder

- How the test writes the set list and the per-route verdicts (env var names, file format). The
  existing pattern is `ROUTECHECK_REALDATA_*`.
- How run B gets its extra dump into the registry list, and how a route in A is matched to its verdict
  in B. The key must at least name the pair, direction, neighbour, family, prefix and path.
- Whether the lookup is an opt-in Go test or a script under `.data/`.
- The closure's round limit.
