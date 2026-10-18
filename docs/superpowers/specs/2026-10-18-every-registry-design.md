# routecheck: the real-data run loads every registry — design

The user asked for this on 2026-10-18 ("go with loading every registry, design first"), and approved the
proposal in conversation ("ok, go ahead"). Every decision below that the user did not state is marked
*(my call)*.

## Why

routecheck's real-data run (`TestRealData`) loads RIPE's dumps alone. A policy's sets are often held by
another registry: an import from an ARIN or APNIC customer names that customer's as-set, held at ARIN,
APNIC or RADB. With only RIPE loaded, such a set is "missing from the registry", and its clause rejects
the routes only that set could have accepted (D4). The reported rejections are then mostly an artifact
of loading one registry.
On the data of 2026-10-18 (`.data/realdata-v0.2.log`):

- import: 3 of 146 rejected routes named a set RIPE does not hold;
- export: 389,127 of 389,413 rejected routes did.

So the export figures in the CHANGELOG and `docs/routecheck.md` say almost nothing about real policy.
The goal is figures that can be trusted. The second goal is a recipe a user can copy to load every
registry.

## Goals

1. `scripts/fetch-data.sh` also fetches every other registry rpsl's `scripts/fetch-irr-dumps.sh` fetches:
   - APNIC (split files);
   - ARIN, AFRINIC and LACNIC (one file each);
   - RADB and RADB's ten mirrors: altdb, bboi, bell, canarie, jpirr, nestegg, nttcom, panix, reach and tc.

   Each file is pinned in `MANIFEST` with its URL, size and sha256, like the existing files.
2. `TestRealData` loads every registry `MANIFEST` names, in a fixed precedence order (below). It does so
   the way the command loads several `-dump` files: one `resolve.Corpus`, with source precedence by first
   appearance.
3. **The same pairs, so the result is a before-and-after.** The run checks the same 60 (L, X) pairs as v0.2:
   - same seed;
   - same sample sizes;
   - same selection rules (L's and X's aut-nums held by RIPE).

   The only difference between the two runs is which registries are loaded.
4. **The baseline on the same files.** The run can be limited to chosen registries (an environment
   variable; the name is the builder's). The published comparison is two runs on the same pinned files:
   RIPE alone, then every registry. That way the before-and-after does not depend on the 2026-10-18 RIPE
   files and RIBs still being the ones pinned *(my call)*.
5. **What still misses.** For the rejections that still name a missing set, the run logs:
   - their count;
   - the number of distinct missing sets;
   - the sets that reject the most routes (a top list), each with its route count.

   The docs then say what remains unresolvable. A hand check takes the top missing set and greps every
   dump for it, confirming no loaded registry holds it.
6. **Docs.**
   - `docs/routecheck.md` gets a "loading every registry" recipe (the `-dump` order, where to get the
     files).
   - Its "Load every registry" limitation is updated with the new figures.
   - The CHANGELOG gets an `[Unreleased]` entry.
   - CLAUDE.md's real-data commands are updated.

## Precedence order *(my call)*

The registries load in this order:

1. The five regional registries: RIPE, APNIC, ARIN, AFRINIC, LACNIC.
2. RADB.
3. The mirrors, alphabetically: ALTDB, BBOI, BELL, CANARIE, JPIRR, NESTEGG, NTTCOM, PANIX, REACH, TC.

The regional registries check who holds the resources, so when two registries hold an object of the same
name, theirs wins. With RIPE first, every object RIPE holds is the one v0.2 read. L's and X's policies are
therefore unchanged between the two runs, and so is any set RIPE holds. Only sets and routes RIPE lacks
come from elsewhere. The docs recommend the same order for `-dump`.

## Memory comes first

On 2026-10-18, RIPE alone gave a peak RSS of 4.2 GB under the guard, with a Go heap peak of 3,055 MB.
What RADB and the others add is not known; it has not been measured.

Before the full run, measure each registry's load alone under the memory guard: objects kept, Go heap
after loading, and wall time. Then measure all of them loaded together. How (a load-only mode of the test,
or a separate test) is the builder's choice.

The full run goes ahead only if the projected peak RSS stays at or below 6 GB, with the guard's 8 GB cap
unchanged. If it does not fit, stop and report the measurements to the user. Do not raise the cap, and do
not drop a registry to make it fit.

All heavy runs follow the standing rules:
- one at a time;
- `memguard.sh 8 …` at normal priority (`MEMGUARD_NORMAL_PRIORITY=1`);
- `GOMAXPROCS=4`, `GOMEMLIMIT=6GiB`.

## Constraints

- **The command is unchanged.** `-dump` already takes several files with this precedence rule. No new
  flag, no directory or glob option (non-goal).
- **Downloads.**
  - RADB and its mirrors are FTP-only and publish no checksums. They are fetched unauthenticated, with
    retries: five tries over FTP and three over HTTPS, as in rpsl's script.
  - Every registry is required. A registry that still fails stops the script with its name; rerunning
    fetches only what is missing *(my call)*.
  - Fetching registries must not replace the pinned RIBs, RIPE dumps or VRPs. That is goal 4's reason, and
    the script needs a way to add registries alone *(my call; the interface is the builder's)*.
- **Which files.**
  - APNIC: the same split classes routecheck takes from RIPE (aut-num, as-set, route-set, route, route6,
    filter-set, peering-set, inet-rtr, rtr-set).
  - The single-file registries: whole. The Corpus drops the classes it does not keep.
- **No redistribution.** `.data/` stays git-ignored; nothing downloaded is committed. No local
  home-directory path goes into any committed file.
- **Every figure is measured.** Every figure in a doc or the CHANGELOG comes from a run in this work, with
  its log named. A figure not measured is unknown.

## Expected side effects (state them, don't hide them)

- **Hygiene changes.** Route-object existence ("has a route object") is read from every loaded registry,
  so more routes will have one. RADB's dump on RADB's FTP is RPKI-filtered (invalid route objects
  removed), while the mirrors' dumps are not (rpsl's CLAUDE.md). The figures say so.
- **Accept counts change too.** Some rejections become acceptances, and some Undecided counts may move,
  for example a set that is now found but reaches a term peval cannot decide.
- **The bigger load is part of the result.** Load time and peak RSS grow; the CHANGELOG gives both
  figures.

## Non-goals

- No change to the CLI, verdict semantics or pair selection rules.
- No live IRRd run, and no `-irrd` comparison.
- No registries beyond rpsl's list (for example LEVEL3 and IDNIC are not on it).
- No comparison with 0.1.0's figures, which were on other data.

## Anti-goals (a failure even if the run passes)

- Comparing the before and after on different files.
- Raising the memory cap, or dropping a registry quietly to fit.
- A registry that failed to download being skipped without the run saying so.
- Any published figure not traceable to a log.

## Left to the builder

- How the script fetches registries alone, and the environment variable's name and format.
- How the per-registry memory measurement is run.
- The size of the top list of missing sets, and how the log presents the comparison.
- Whether this ships as a release: the user decides at the end. If only the script, the test and the docs
  change, it need not be one.
