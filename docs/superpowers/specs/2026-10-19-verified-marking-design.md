# routecheck: mark route-object answers backed only by unverified registries — design

Status: draft, 2026-10-19. A command and library change, for v0.5.0.

## Why

Today routecheck answers each route's "does a route object exist for exactly (prefix, origin)?" with a plain yes or
no, from every loaded registry together.

The registry-provenance measurement (PR #13, docs/routecheck.md "How much rests on unverified registries") showed
how much of that rests on registries that do not check who holds the address space:
- 36.50% of the "yes" answers on its sample rest on RADB and its mirrors alone;
- 1,660,441 of 4,549,769 answered in both runs.

A user reading "route object yes" cannot tell those from a "yes" an RIR backs.

The maintainer wants users to **treat a "yes" from unverified registries only as weaker evidence**. So the answer must
say which kind of "yes" it is, wherever the answer is shown.

## Goals

1. **Every route-object answer says whether a verified registry backs it.**
   - The new answer is: does a route object exist for exactly (prefix, origin) in the *verified* sources?
   - A "yes" overall with "no" from the verified sources is **yes, unverified only**.
   - It is answered for every route that gets a route-object answer today, in every mode (session, collector,
     `-policy` draft), with `-dump` and with `-irrd`.
2. **The verified sources are, by default, exactly the five RIRs:** RIPE, APNIC, ARIN, AFRINIC and LACNIC, by
   `source:` name, compared without regard to case.
   - `-verified-sources LIST` replaces the list (comma-separated source names).
   - A `-NONAUTH` source (RIPE-NONAUTH, ARIN-NONAUTH, …) is never verified by default.
3. **Shown in the output:**
   - Text: a route's line reads `route object yes`, `route object yes (unverified only)` or `route object no`.
   - JSON: each route gains `RouteObjVerified` (true, false or null) beside `RouteObj`.
   - Each report's existing counts gain the route-object answers: yes, of them unverified only, and no.
4. **Library:**
   - `routecheck.Checker` gains a `VerifiedRoutes resolve.Source`. When nil, the new answer is nil, which means
     not asked.
   - `RouteVerdict` gains `RouteObjVerified *bool`.
   - `hygiene.Checker` answers it the way it answers `RouteObject` today: cached per origin and family, with errors
     returned and not cached.
   - The API change shows in `api/*.txt`.
5. **Documented:**
   - docs/routecheck.md: the output section, the flag table and the caveat that now points at the marking;
   - the CHANGELOG's `[Unreleased]` (Added and Changed);
   - CLAUDE.md.
   - Released as v0.5.0 when the maintainer asks.

## Constraints

- **Verdicts do not change.** The marking is evidence beside a verdict, never an input to one. Filters, exit status
  and the existing `RouteObj` answer stay exactly as in v0.4.0.
- **An unknown answer is never shown as known.** If the verified lookup fails, or cannot be asked, the answer is nil.
  The text then shows the plain `route object yes`, and the run says once on stderr why the marking is missing.
- **Over `-dump`:** the verified answer comes from a view of the loaded registries restricted to the verified sources
  (rpsl's `Corpus.SourceOf`, or an equivalent that holds only route objects).
  - Its memory cost must be measured on the every-registry data, the command on AS9086 from AS6762 at
    `-max-prefixes 2097152`, which peaked at 6,511 MB in v0.4.0.
  - It must stay under the 8 GB guard with room to spare. If it does not, the builder reduces it (for example a
    verified-only route index of route objects alone) before anything ships.
- **Over `-irrd`:** the verified answer comes from the same server, asked with its source list restricted to the
  verified sources (rpsl's `irrd.Source.Sources`, IRRd's `!s`).
  - This doubles the route-object queries. Their count and the time are measured against the in-process IRRd that
    the tests already use.
  - A server that serves none of the verified sources gives nil answers and one stderr note, never "unverified only"
    for everything.
- **Pre-v1 rules:** an API addition is a minor version (v0.5.0), and `api/*.txt` is regenerated and reviewed.
- Heavy runs as always: one at a time under the memory guard (8 GB cap, normal priority, `GOMAXPROCS=4`,
  `GOMEMLIMIT=6GiB`).
- Every figure in docs comes from a command run, with its log.
- No local home-directory paths in anything pushed.

## Non-goals

- Deciding routes from verified route objects only, as an option that changes filters and verdicts. That is the
  measurement's run R as a command option. It is a separate, larger change, which can follow if wanted.
- Judging whether an unverified object is right, or checking RPKI against it. RPKI is already shown beside it.
- Per-registry attribution ("this yes came from NTTCOM"). The marking is the two-way split the maintainer asked for.
- Changing the precedence of sources, or what is loaded.

## Anti-goals

- Wording that calls unverified data wrong. The output says "unverified only", not "invalid" or "untrusted".
- A marking that silently depends on the order of `-dump` files or on the server's source order.
- An exit-status change. "Unverified only" is not a Warning.

## Decided by me (the maintainer can overrule while reading)

- **On by default**, whenever route-object answers are given. That is what "treat it as weaker evidence" needs. There
  is no flag to turn it off: an empty `-verified-sources ""` is refused (exit 2), so the list is never silently empty.
- **The default list is the five RIRs**, and `-verified-sources` exists for users who also trust JPIRR, or trust
  fewer. The measurement's grouping assumption becomes the user's to change.
- **The text format:** `route object yes (unverified only)`. The JSON field name is `RouteObjVerified`, following
  `RouteObj`.
- **Counts per report.** A whole-run summary line in session and collector mode is left to the builder, if one
  already exists to extend.

## Settled after the builder check *(my calls)*

1. **The verified answer is over the verified sources present.** These are the ones loaded under `-dump`, or the
   ones the server serves (and `-sources` allows) under `-irrd`.
   - The run states once on stderr which verified sources it uses and which are absent. That way a "yes
     (unverified only)" is read against what was actually there.
   - When none is present, the marking is off for the run: nil answers, and one stderr note.
   - Under `-irrd`, each verified source is probed once at startup with a one-source query, and a refused one counts
     as absent. IRRd refuses a whole `!s` list if one name is unknown, so asking the full list on a server lacking
     one RIR would fail every query. This needs no rpsl change.
2. **This amends the constraint "if the verified lookup fails … the answer is nil".**
   - Being unavailable is decided once, at startup: no verified source present gives nil plus a note.
   - Once the marking is on, an error from a verified lookup fails the run, exactly as an error from today's
     route-object lookup does. Context errors stay errors.
   - So within a run, every route with a route-object answer has a verified answer too. The per-report counts need
     no fourth "unknown" slot.
3. **Under `-irrd`, the verified sources are limited to the run's own source list.** That is `-sources` when given,
   else the server's default list (`!s-lc`).
   - The verified answer is then always within the main one: a verified "yes" beside an overall "no" cannot happen.
   - Because of that, the verified query is skipped when the main answer is already "no", so the extra queries are
     at most one per (origin, family) with a "yes".
   - A `-sources` that names no verified source turns the marking off, with the note.
4. **"Room to spare" means the extra memory is at most 300 MB:** at most 6,811 MB peak on the command run on AS9086
   from AS6762 at `-max-prefixes 2097152` (6,511 MB in v0.4.0).
   - If a second `MemSource` costs more, the builder uses a lighter index of verified route objects instead, before
     anything ships.
   - That measurement run, and the `-irrd` timing against the in-process IRRd, are approved with this design. They
     run under the usual guard.

## Left to the builder

- How the dump mode builds the verified view (a second `MemSource`, or a lighter index of route objects by source).
  Choose by measured memory.
- The exact wording of the stderr note, and where the per-report counts go in the text layout.
- Whether `hygiene.Checker` gets a second `Src` or a small wrapper type.
- The golden files' update (`internal/cli` goldens) and new tests for:
  - yes, verified;
  - yes, unverified only;
  - no;
  - a failed verified lookup (nil);
  - `-verified-sources` parsing, including an empty or duplicate name;
  - `-irrd` against the in-process IRRd with sources it does and does not serve.
