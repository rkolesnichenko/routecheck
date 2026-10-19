# routecheck: a `-max-prefixes` option — design

The user asked for this on 2026-10-18 ("go with the max-prefixes option, design first"). They decided the
default and the publishing: "keep the default, publish the cost". Every other decision below is marked
*(my call)*.

## Why

Since v0.3.0 (ruling R27), a policy whose expansion passes one of rpsl's limits makes only its report
"unevaluable"; the run goes on. In the every-registry real-data run that left 81 distinct reports, 82 counted
per pair, holding 549,847 routes, unevaluable. That is more than ten times the 47,317 export rejections over
the same 60 pairs (`.data/realdata-set-limits.log`). All 81 were `MaxPrefixes` (1,048,576), most of them X's
export toward a large neighbour, led by AS6762's `announce AS-SEABONE`.

The command offers no way past the limit. A user who wants those routes decided has none. rpsl already makes
the limit a setting (`resolve.Expander.MaxPrefixes`), so the command only has to let the user set it.

How big the full expansions are is not known. The error says only that each passed 1,048,576 (for example
"reached 1048960"). So the memory cost of a higher limit is unknown too, and it is measured here before
anything is documented.

## Goals

1. **The option.** `-max-prefixes N` sets `resolve.Expander.MaxPrefixes` for the policy evaluation, in every
   mode (session, collector, `-dump`, `-irrd`).
   - Without the option, the limit stays rpsl's default of 1,048,576 *(the user's decision: keep the
     default)*.
   - N must be a positive integer. 0, a negative number or a non-number is a command-line error: exit 2 and
     a message naming the option *(my call: 0 would silently mean "the default" in rpsl, which reads as "no
     limit" to a user)*.
   - There is no upper bound in the command; the user owns the memory trade-off, and the docs give its
     measured cost.
2. **Only this limit.** No option for `MaxVisited`, `MaxDepth` or `MaxConjuncts`; none was hit in any
   real-data run *(my call, YAGNI)*.
3. **The library does not change.** A Go user already sets `Checker.Eval.Expander.MaxPrefixes`. The
   `routecheck` package and `api/*.txt` stay as they are.
4. **The test seam goes.** The unexported `expander` variable in `internal/cli` (v0.3.0) is replaced by the
   option's value. `TestUnevaluableLimit` drives the limit through `-max-prefixes 1` instead *(my call: one
   way to set it, and the test then covers the real option)*.
5. **The report already names the limit and the value.** An over-limit report's `Unevaluable` text already
   reads like `… expansion exceeds MaxPrefixes (N): reached M`. A user sees which value to pass; no output
   change is needed.
6. **The real-data test** gets `ROUTECHECK_REALDATA_MAX_PREFIXES` (a positive integer; unset means rpsl's
   default), so the published figures can be reproduced.
7. **Measure, then publish the cost** *(the user's decision)*. Every run is under the memory guard: one at a
   time, 8 GB cap, normal priority.
   1. **The command on the pair with the most over-limit reports.** Run AS9086 from AS6762, collector mode,
      every dump in precedence order, default direction, at `-max-prefixes` 2,097,152, 4,194,304, 8,388,608
      and 16,777,216, stopping at the first value with no unevaluable report. For each value, record the peak
      RSS, the wall time, the number of unevaluable reports, and the routes decided.
      - If the guard stops a run (memory or pressure), that is the result for that value: report it and try
        no higher value.
   2. **The full every-registry run** (`TestRealData`, all 60 pairs) at the lowest value of step 1 that
      leaves AS6762 with no unevaluable report. If step 1 found none, use the highest value that completed.
      Publish:
      - the unevaluable reports left;
      - how the 549,847 routes now split into accepted, rejected and undecided;
      - wall time and peak RSS;
      - that the 50 pairs which hit no limit keep their figures exactly. A raised limit cannot change a
        report that never reached the old one; any difference is a defect to explain before publishing.
   3. **The cost table.** The docs give the per-value figures of step 1: limit, peak RSS, wall time, and
      reports still over. The default stays as it is.
8. **Docs.**
   - `docs/routecheck.md`:
     - the option's row in the flag table;
     - the MaxPrefixes "Known limitations" bullet, which drops "No flag raises the limit" and gains the cost
       table;
     - the unevaluable reason's row, saying `-max-prefixes` can lift a `MaxPrefixes` one.
   - CLAUDE.md:
     - R27 drops the test-seam sentence and names the option;
     - the Known-limitations bullet;
     - the real-data command's environment variables.
   - CHANGELOG `[Unreleased]`: `### Added` for the option, `### Measured` for the runs.
   - The usage text (`-h`).
9. **Release** as routecheck v0.4.0 (a new option), after the user's go-ahead for each outward step
   *(my call)*.

## Constraints

- **No changes to:** rpsl (stays v0.30.0), the library API (`api/*.txt`), or the JSON and text formats.
- **The default** is exactly rpsl's when the option is absent: the zero `Expander`. The code never copies
  1,048,576 in as its own constant.
- **Every published figure is measured,** with its log named. Heavy runs go one at a time, under the guard,
  at normal priority. No local home-directory path in any committed file. Commit on the branch, never on
  `main`.

## Non-goals

- Raising the default *(the user's decision)*.
- Options for the other three limits.
- An automatic retry at a higher limit, or a "no limit" value.
- Telling the user how much memory a given N will need ahead of time (beyond the published table).

## Anti-goals

- **A silent change of the default.** The absent option must behave exactly as v0.3.0.
- **A memory cost published without a measurement,** or a measurement run outside the guard.
- **A `-max-prefixes 0` that means "unlimited"** or "default" without saying so.

## Settled after the builder check *(my calls)*

1. **A guard stop is an acceptable, published result.** Step 1's command runs use the same settings as the
   real-data command: `GOMAXPROCS=4`, `GOMEMLIMIT=6GiB`, `memguard.sh 8`, at normal priority. If the guard stops
   a run, its row in the cost table reads "stopped by the memory guard (8 GB)" with the guard's figures, and
   no higher value is tried. The table may then have only one or two rows; it is still published. Step 2
   then uses the highest value that completed. The option is still worth shipping in that case: it lifts any
   over-limit filter that fits the user's memory, and most are only just over the default ("reached
   1,048,583" … "1,053,142").
2. **Step 1's command** is the one of `.data/set-limits-cli.log`, with both families:

   `routecheck -local AS9086 -peer AS6762 -collector .data/realdata/filtered/AS6762.mrt -max-prefixes N
   -dump <the 32 dumps in .data/realdata/MANIFEST order>`

   It runs in the default direction and with the default `-af both`, without `-vrps`. Step 1 measures the
   option's cost on one pair. Step 2's like-for-like comparison is `TestRealData` against `TestRealData`
   (`.data/realdata-set-limits.log`), on the same pinned files.
3. **Only `MaxPrefixes` reports count.** The loop ends at the first N with no report whose `Unevaluable`
   names `MaxPrefixes`. A report over another limit, or failing for another reason, is counted and published
   separately. It does not count against the value.
4. **The real-data test sets the limit the same way the command does:** `Checker.Eval.Expander =
   resolve.Expander{MaxPrefixes: n}` when `ROUTECHECK_REALDATA_MAX_PREFIXES` is set. Unset means the zero
   `Expander`.
5. **`-irrd` is covered.** The option applies with `-irrd` too: the expansion is local, in the same
   `peval.Evaluator`. The command's tests already exercise the shared code path, and no live-IRRd test is
   added. The docs make no claim about a server's own answer limits.
6. **The release decision stays open.** The docs and CHANGELOG are written from whatever the measurements
   show. Only the tag waits for the user.

## Left to the builder

- Where the option's value travels: a field in the command's config, passed to `peval.Evaluator`.
- The exact wording of the usage line and the error for a bad value, in the style of the other options.
- How the test asserts the bad-value refusal (exit 2 and the message).
