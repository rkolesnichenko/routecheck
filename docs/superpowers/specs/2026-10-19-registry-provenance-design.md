# routecheck: how much rests on unverified registries? — design

Status: draft, 2026-10-19. A measurement, not a feature: the command's behaviour and output do not change.

## Why

The maintainer wants to know how much of routecheck's answers rests on registries that do not check who holds
the address space.

routecheck loads 16 registries. Five are the RIRs (RIPE, APNIC, ARIN, AFRINIC, LACNIC). Each checks that a route
object's creator holds the resource, for the resources it manages. The other eleven are RADB and the ten
mirrors RADB serves (ALTDB, BBOI, BELL, CANARIE, JPIRR, NESTEGG, NTTCOM, PANIX, REACH, TC). docs/routecheck.md
already says these "do not check resource holders". Below they are called **unverified**: their objects may well
be right, but nothing checked that they are.

The docs' caveat today:

- Loading every registry instead of RIPE alone took L's observations with a route-object answer from 528,974 to
  1,568,538 of 2,108,128 on the same pairs.
- "How much of that rests on RADB and the mirrors … was not measured".
- They hold 1,843,733 of the 4,866,879 objects loaded (`.data/load-all.log`).

The missing-sets measurement (merged, PR #12) settled the rejected side: no rejection came from a registry
routecheck failed to load. This one looks at what the unverified registries contribute.

### What rests on them

The unverified registries feed three things:

1. **The route-object answer** (`RouteVerdict.RouteObj`): "a route object exists for exactly (prefix, origin)".
   It is answered from every loaded source together (a union), so one unverified route object makes it "yes".
2. **Filters built from route objects**, such as `AS-FOO` expanded to its members' prefixes, or `AS1` to
   AS1's prefixes. This expansion also takes route objects from every source, so an unverified route object can
   put a prefix into a filter and get a route accepted.
3. **Sets** (as-set, route-set, …) that only an unverified registry holds, or holds first in precedence.

Removing route objects can only turn a route-object answer from "yes" to "no", never the other way. So a run
without the unverified route objects measures item 1 exactly, even by counting alone. Items 2 and 3 change
verdicts, which can move either way: a smaller prefix list rejects more routes, while a smaller NOT list rejects
fewer. Those need a route-by-route comparison.

## Goals

1. **Three runs of the real-data test**, at `ROUTECHECK_REALDATA_MAX_PREFIXES=2097152`, on the 2026-10-18
   dumps, with the same 60 pairs:

   | run | loads |
   |---|---|
   | A | every registry, as today |
   | R | every registry, but route and route6 objects only from the five RIRs |
   | V | the five RIRs only (`ROUTECHECK_REALDATA_REGISTRIES=ripe,apnic,arin,afrinic,lacnic`, which exists today) |

   - A against R isolates the unverified route objects (items 1 and 2).
   - A against V isolates everything unverified: route objects, sets and the rest (items 1 to 3).

2. **Route-object answers.** For import and export separately, count the "yes" answers in A that are "no" in
   R. Those rest only on unverified route objects. Also give them as a share of A's "yes" answers.
   - By the monotonicity above, this is exact from per-run totals, and the route-by-route comparison must agree
     with it. A disagreement fails the measurement.
   - Report the RPKI state of those routes (valid, invalid, not found, from the VRPs the run already loads), as a
     quality signal for what the unverified objects say. RPKI-valid means a resource holder signed that origin.

3. **Verdicts.** Compare A and R, and A and V, route by route, for every observation in both directions:
   - each change counted by kind (accepted → rejected, rejected → accepted, either → undecided, undecided →
     either), per direction;
   - the RPKI state of the routes accepted in A that are rejected without the unverified data;
   - each set of counts summing to its total, shown in the docs.

4. **Published.** The figures replace the "was not measured" sentence in docs/routecheck.md's caveat, and the
   CHANGELOG's `[Unreleased]` gets a Measured section. Every figure names its log or data file.

## Constraints

- **Heavy runs as always:** one at a time, under the memory guard, at normal priority
  (`MEMGUARD_NORMAL_PRIORITY=1`), with an 8 GB cap, `GOMAXPROCS=4` and `GOMEMLIMIT=6GiB`. Never beside check.sh,
  and never raise the cap.
  - Run A peaked at 6,991 MB with the missing-sets outputs (`.data/missing-sets-A.log`).
  - The route-by-route output must therefore be streamed per pair, never held for the whole run. The
    missing-sets tracked lines, held to the end, cost about 500 MB.
- **No network.** Everything comes from the pinned dumps and VRPs.
- **Same inputs:** the 2026-10-18 files in `.data/realdata` (MANIFEST unchanged) and the same seed and sample, so
  the 60 pairs are the same in every run. Pairs are chosen from RIPE's aut-nums only, so all three runs check the
  same pairs.
- Outputs stay in `.data/` (git-ignored). Only counts go into docs.
- No local home-directory paths in anything committed or pushed.
- Every figure comes from a command run, and names its log.
- Only `_test.go` files, docs and the CHANGELOG change. The command, `api/*.txt` and go.mod do not.

## Non-goals

- Changing the command: no "verified only" option, no new output. That is a possible follow-up, decided after
  the numbers.
- Judging whether any unverified object is right or wrong. "Unverified" means not checked, not false.
- Per-object attribution inside an expansion ("this prefix came from that RADB route object"). The comparison
  runs answer "does the verdict depend on it", which is what a user acts on.
- Other samples, other limits, a live registry.
- A release.

## Anti-goals

- Calling the unverified registries wrong, or implying that their data is.
- Hiding verdict moves that cancel out. Report both directions of every change, never only the net.
- Treating JPIRR or another mirror as verified, or unverified, by assumption without saying so. Each is grouped
  with RADB, as the docs do today, and the docs say that this grouping is the assumption.

## Decided by me (the maintainer can overrule while reading)

- **The verified group is exactly the five RIRs.** Everything else loaded is unverified. The 2026-10-18 dumps
  hold no `-NONAUTH` source (CHANGELOG, every-registry). If one ever appears, it counts as unverified.
- **The limit is 2,097,152**, the setting of the current every-registry figures.
- **Two comparison runs, R and V**, rather than one, so that route objects and sets can be told apart.
- **RPKI state is the quality signal**, not live queries or hand checks of object owners.
- **No release** unless the maintainer asks.

## Settled after the builder check *(my calls)*

1. **R or V can need more memory than A.** Their sets shrink, and some expansions A gave up on (over 2,097,152)
   may fit and be decided. If the guard stops a run:
   - it is rerun in shards of pairs (`ROUTECHECK_REALDATA_PAIRS`, same seed and 60 pairs), one process at a time,
     each under the guard, as the missing-sets plan allowed;
   - the per-route output and the comparer must combine shards;
   - a shard that still does not fit leaves its pairs "no verdict" in that run, and the docs say which and why;
   - the cap stays at 8 GB.
2. **"No verdict" is a kind of its own, both ways.** A report can fall back to no policy, or a pair can time out,
   in one run only.
   - Changes are counted over A's observations: every observation has a verdict or "no verdict" in each run, and
     each table sums to A's observations per direction.
   - The same RIBs give the same observations in every run.
   - **The route-object rule is per route:** no route may go from "no" in A to "yes" in R. That would contradict
     monotonicity, and it fails the measurement.
   - The "yes → no" count is taken over the routes that have an answer in both runs. The two runs'
     route-object denominators are reported. If they differ, the docs say so and do not use the totals-only
     shortcut.
3. **Both figures are published.**
   - The 60-pair figures are the measurement.
   - The 50 pairs shared with the old caveat are a self-check: A's subset must reproduce 1,568,538, since the
     route-object answer does not depend on MaxPrefixes. They also give the share of the old rise (528,974 to
     1,568,538) that rests on unverified route objects alone.

Also settled:
- An "undecided → either" change gets a sub-count by A's undecided reason. That way a limit effect
  ("unevaluable" at 2,097,152) is not presented as a data effect.
- Dropping a `member-of:` route claimant drops its claim too, which is what the engine does without that object.
- "Unverified" is decided by dump file, checked against the per-source counts: the 16 files and 16 sources match
  one to one in the 2026-10-18 dumps.

## Left to the builder

- How R drops the unverified route objects. The obvious place is `loadRegistry`, behind a new
  `ROUTECHECK_REALDATA_*` variable. It must drop route and route6 objects only, and must keep a `member-of:`
  route claimant's set membership consistent with what the engine does without it.
- The per-route output's format. Each route must be keyed as in the missing-sets work (`routeKey`). It must be
  streamed per pair, and should be compact; a hash of the key is fine if collisions are checked.
- The comparer: an opt-in offline test like `TestMissingSetsClassify`.
