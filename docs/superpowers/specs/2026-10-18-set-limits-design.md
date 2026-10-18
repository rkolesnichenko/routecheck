# routecheck: a set over an expansion limit makes one report unevaluable, not the run — design

The user asked for this on 2026-10-18 ("go with the MaxPrefixes fix, design first") and approved the proposal
in conversation ("ok, go ahead and write the design"). Every decision below that the user did not state is
marked *(my call)*.

## Why

When peval expands a filter past one of rpsl's limits, it returns a `*resolve.SetTooLargeError`. routecheck
treats that as fatal: `Check` returns the error, and the command exits 3 and prints nothing else.

The every-registry real-data run (merged as PR #7) showed how often that happens:
- With every registry loaded, 10 of 60 sampled pairs hit `MaxPrefixes` (1,048,576). 8 of those filters are in
  X's export toward a large neighbour and 2 in L's import (`.data/over-limit-terms.log`).
- A single such filter fails the whole run. `routecheck -peer AS6762 … -direction export`, or the default
  `both`, exits 3 with only `routecheck: peval: AS174 | AS-SEABONE: resolve: expansion exceeds MaxPrefixes
  (1048576): reached 1048960`. Nothing comes out for AS6762's other neighbours, for the other address family,
  or for L's import (`.data/maxprefixes-cli-export.log`, `.data/maxprefixes-cli-both.log`).
- routecheck's docs now recommend loading every registry, so a user checking a large transit network will
  meet this.

routecheck already has the right shape for an expansion that cannot be done. Since ruling R19, a policy naming
AS-ANY or RS-ANY in filter position (`*resolve.AnySetError`) makes that one report "unevaluable": its routes
are Undecided with the error as the reason, and the rest of the run is decided. This change applies the same
treatment to a set over a limit.

## Goals

1. **Only the report is affected.** In `famRun.report` (check.go), a `*resolve.SetTooLargeError` from
   `Eval.Import` or `Eval.Export`, matched with `errors.As` as `AnySetError` is today, takes the R19 path:
   - `Report.Unevaluable` is set to the error's text, whatever the route count;
   - `Policy` is empty;
   - every route is Undecided with the single reason `verdict.ReasonUnevaluable`, with Why = the error text
     and Clause and Index -1.

   The other reports are decided as usual: other neighbours, the other direction, the other family.
2. **All three limits.** `MaxPrefixes`, `MaxVisited` and `MaxDepth` all return `*resolve.SetTooLargeError`,
   and all three get this treatment *(my call: one error type, one meaning, "this set cannot be expanded
   within the limits")*.
3. **No new output.** The existing "unevaluable" report, its text line (`policy not evaluable, no route
   decided: <error>`), the `Unevaluable` JSON field and the `unevaluable` reason carry it. The error text
   already names the limit.
   - No new reason kind, and no change to `api/*.txt` *(the user accepted this)*.
   - The cost: telling "AS-ANY, never evaluable" from "over a limit" means reading the text.
4. **Exit status as for R19.** An unevaluable report never causes exit 3 on its own. Exit 3 stays for runs
   that cannot complete: an unreadable file, an unreachable server, a missing aut-num, a Source or context
   error, an interrupted run, and the others `docs/routecheck.md` lists. Exit 1 still means something was
   Rejected, and exit 0 means nothing was.
5. **Tests.**
   - `TestCheckPevalError` (check_test.go) now pins the new behaviour. With `Expander{MaxPrefixes: 1}`, the
     import report is unevaluable, with Why containing `MaxPrefixes`, every route Undecided with the single
     reason `unevaluable`, and the export report decided as usual. `Check` returns no error.
   - Its second half stays: a missing aut-num still fails the run.
   - `TestCheckUnevaluable`'s comment ("any other peval error still fails the run") is updated.
   - The CLI gets one test: a limit in one direction gives exit 0 or 1 by the other reports, never 3. The
     text shows the `policy not evaluable` line naming the limit, and the JSON carries `Unevaluable`.
   - One test covers a limit other than `MaxPrefixes` (`MaxDepth` or `MaxVisited`) *(my call: it pins goal 2
     beyond one limit)*.
6. **Real data.**
   - In `TestRealData`, `Check` no longer returns `*resolve.SetTooLargeError`. The pair-level "set too large"
     count stays only as a guard, expected to be 0. The unevaluable reports, already tallied by report and
     error text, now include the over-limit ones.
   - One every-registry run under the memory guard checks all 60 pairs: one at a time, 8 GB cap, normal
     priority, as before.
   - Its figures are published with their logs:
     - the unevaluable reports and routes, by limit;
     - the 10 previously missing pairs' outcomes;
     - wall time and peak RSS.
   - The 50-pair figures of PR #7 must not change, because those pairs had no limit error. Any difference is a
     defect to explain before publishing.
   - The RIPE-only run is repeated only if the test's code path for it changed *(my call: by the logs, RIPE
     alone hits no limit, so its figures cannot change)*.
7. **Docs.**
   - `docs/routecheck.md`:
     - the `unevaluable` reason's row gains "or a set over one of rpsl's expansion limits";
     - the exit-3 row drops "a limit" from "peval failing";
     - the "Known limitations" bullet on `MaxPrefixes` is rewritten: the report is unevaluable and the run
       goes on, so there is no "check the other direction" workaround;
     - the 389,413 → 47,522 paragraph points at the new figures.
   - CLAUDE.md:
     - R19/R21's "Every other peval error (a limit, …)" drops "a limit";
     - a new ruling R27 states this decision;
     - the Known-limitations bullet is updated.
   - SECURITY.md is updated if it says a limit fails the run.
   - CHANGELOG `[Unreleased]`: under Changed, the behaviour change, stated plainly as a change to what
     `Check` returns and to the exit status. Under Measured, the run.
8. **Release** as routecheck v0.3.0, after the user's go-ahead for each outward step *(my call: a behaviour
   change to `Check` and to the exit status, pre-v1)*.

## Constraints

- **Dependencies are unchanged.** rpsl stays at v0.30.0, with no change to rpsl. The limits stay rpsl's
  defaults: no flag raises them (non-goal).
- **Only report-level failures change.** A limit hit outside `Eval.Import`/`Eval.Export` would still fail the
  run. None is known; the builder confirms where `SetTooLargeError` can arise in routecheck's call graph.
- **One reason per route.** An unevaluable report's routes carry exactly the one `unevaluable` reason, as
  under R19.
- **Every published figure is measured,** and its log is named. Heavy runs go one at a time, under the memory
  guard, at normal priority.
- No local home-directory path in any committed file. Commit on the branch, never on `main`.

## Non-goals

- No flag to raise rpsl's limits, such as `-max-prefixes`. That would let a user decide AS6762's export to
  AS174, at an unmeasured memory cost; it is a possible later step.
- No new reason kind or field, and no change to `api/*.txt`.
- No change to how AS-ANY is handled, or to `verdict`, `pathre`, `observe` or `hygiene`.
- No partial evaluation of a policy whose other clauses could be decided. As with R19, the whole report is
  unevaluable.

## Anti-goals (a failure even if the tests pass)

- An over-limit report whose routes look decided: Accepted or Rejected, never Undecided.
- A real failure, such as a missing aut-num, an unreachable server or a Source error, turned into an
  "unevaluable" report: a silent pass.
- Published figures for the 10 pairs that do not trace to a log.

## Left to the builder

- Whether the change is a second `errors.As` beside the `AnySetError` one, or a small helper naming both.
- How the CLI test builds a registry that hits a limit. A tiny `MaxPrefixes` through the CLI's own options is
  not possible, so the test may need a set big enough for a default limit, or a test hook. The test hook must
  not become a user-facing flag.
- How the real-data log presents the over-limit unevaluable reports.
