# routecheck: hand reports over as they are built — design

Status: draft, 2026-10-19. Phase 2 of `2026-10-19-memory-profile-design.md`, whose addendum holds the findings
this builds on. The maintainer chose candidates 1 and 2 at the checkpoint. For v0.6.0.

## Why

The phase-1 profile showed that the big runs' memory is mostly reports kept until the whole check ends:
- `Check` returns every `Report` at once.
- Each report holds its expanded prefix sets (in `Report.Policy`) and its route verdicts.
- At the last report, the reports hold 2,302 MiB in pair 2's run A, 4,614 MiB in run R and 4,644 MiB in run V,
  and 2,065 MiB in the command run (addendum, "Candidate reductions").
- In runs R and V, the real-data test then holds one line per rejected route that names missing sets, each
  repeating the whole missing-set list. That grew by 682 MiB (R) and 1,166 MiB (V) before the guard stopped the
  runs.

The maintainer wants the peak lowered so the big runs fit. This change makes:
- `Check`'s callers able to take each report as it is finished, and let it go;
- the command and the real-data test do so;
- the test write its rejected-route lines as it produces them.

## Goals

1. **A streaming check in the library.**
   - A new method on `routecheck.Checker` runs the same check as `Check`, but hands each finished `Report` to a
     function the caller gives, and keeps no reference to it afterwards.
   - The reports come in the same order `Check` puts them in its `Result`s: per family in `Check`'s order, the
     import report first, then the export reports.
   - The caller also gets each family's `Result` without its reports: the family and its `Coverage`, including
     `DirectNotChecked`, before that family's first report.
   - `Check` itself stays, with the same results as today, built on the new method. Library users who want
     everything at once keep it; it holds what it holds today.
2. **The command uses it.**
   - Text and JSON output stay **byte-identical** to v0.5.0, and so does the exit status.
   - The command keeps no `Report` after it has written that report's part of the output.
3. **The real-data test uses it.** It processes each report as it arrives: counting, the `routes.tsv.gz` lines,
   the tracked lines, and the missing-set lines.
4. **The test writes its missing-set lines as it produces them** (candidate 2). `rejected-missing.tsv` stays
   byte-identical: same lines, same order.
5. **Measured against phase 1's targets,** under the guard, each figure with its log:
   - pair 2 alone, with `ROUTECHECK_REALDATA_OUT`, completes in runs R and V under 8 GB;
   - the 60-pair run A, with `ROUTECHECK_REALDATA_OUT`, peaks at or below 6,144 MiB (7,148 MiB today);
   - the command run (AS9086 from AS6762, every registry, `-max-prefixes 2097152`), measured **on the binary**,
     peaks at or below 5,120 MiB (6,421 MiB in v0.5.0).

   A missed target is reported as measured, with the addendum's next candidates (a compact `RangeSet` in rpsl, or
   a GC setting) named for the maintainer. Nothing further is built without their go-ahead.
6. **Documented:** CHANGELOG (Added, Changed, and Measured), CLAUDE.md (a ruling on streamed reports), and
   docs/routecheck.md's memory figures. Released as v0.6.0 when the maintainer asks.

## Constraints

- **Results never change.** Byte-identical output is checked by:
  - the text and JSON goldens;
  - the command run's stdout, compared with v0.5.0's (`.data/verified-counts-2097152.log`);
  - the 60-pair run A, compared route by route with `.data/provenance-A.log`'s run (`TestProvenanceCompare`),
    with no route moving and TOTALS equal;
  - `rejected-missing.tsv` and `routes.tsv.gz`, compared byte for byte with a run before the change (the same
    pairs and settings).
- **Pre-v1:** an API addition is v0.6.0. `api/*.txt` is regenerated and its diff reviewed. `Check`'s signature
  and results do not change.
- **The guard as always:** 8 GB cap, normal priority, `GOMAXPROCS=4`, `GOMEMLIMIT=6GiB`, one heavy run at a time,
  never beside check.sh, no network. The command target is measured on the built binary, like v0.5.0's figure,
  not through `go test`.
- No local home-directory paths in anything pushed. Every figure comes from a command run and names its log.

## Non-goals

- A compact `RangeSet` in rpsl, a smaller `RouteVerdict`, or a GC setting (candidates 3 to 5). They are next only
  if a target is missed, and only on the maintainer's word.
- Sharing one set's expansion between reports (a filter memo). It is noted in the addendum as a question; it is not
  built or measured here.
- Changing what the output says, or its order.
- Redoing the registry-provenance figures with pair 2. That is a follow-up once pair 2 fits.

## Anti-goals

- Output that differs in any byte, including JSON whitespace and key order.
- A streaming method that hands over a report the library still references (and so still holds), so that nothing is
  actually freed.
- Saving memory by dropping information the output or the exit status needs later.

## Decided by me (the maintainer can overrule while reading)

- **Keep `Check`, and add the streaming method beside it.** Library callers keep a simple call, and the change is
  additive. Its shape is a callback, for example
  `CheckEach(ctx, mode, records, o, func(res *Result, dir Direction, rep *Report) error) ([]Result, error)`, where
  the returned `Result`s carry no reports and an error from the callback stops the check. The exact name and
  signature are left to the builder, within the C1–C3 conventions.
- **Text output:** each report is rendered to its text as it arrives, and the text is kept until the end.
  - Text puts the coverage section, which needs a count from the reports, before them. So the command writes the
    pieces in today's order once the check ends.
  - Today's text writer already builds the whole text in memory before writing it, so this holds no more than it
    does now, and no `Report` is held.
- **JSON output is rendered as reports arrive**, each report into the same bytes `encoding/json`'s indented
  encoder writes today, and those bytes are kept until the check ends (see "Settled after the builder check", 1).
- **The exit status** comes from a running flag (any report with a rejected route), not from kept reports.
- **The missing-set lines** go to a per-pair temporary file under the output directory, which `addPair` appends in
  pair order and then removes.
- **One branch:** this continues on `memory-profile`, after phase 1's commits, so one pull request carries the
  profile, the findings and the change.

## Settled after the builder check *(my calls)*

1. **A failed run looks exactly as it does today, in both formats.**
   - stdout stays empty, there is no route-object note, and the exit status is 3. Ruling R28, `TestFailures` and
     `TestNoSession` stand unchanged.
   - So JSON, like text, is rendered report by report into its output bytes, and those bytes are written to stdout
     only once the check has succeeded.
   - This frees every `Report` in both formats. JSON's encoded bytes are held until the end, as today's
     `encoding/json` encoder already holds them. JSON is not one of the targets; the command target runs in text
     mode.
   - Writing JSON to stdout as it goes, or through a temporary file, is a possible later change.
   - A test makes the check fail after some reports, in both formats, and asserts empty stdout, no note and exit 3.
2. **`routes.tsv.gz` keeps its promise that a pair that timed out or failed writes none.** Its lines go through a
   per-pair temporary file, like the missing-set lines, appended in pair order when the pair succeeds. Both files
   stay byte-identical.
   - The per-report work now runs inside the check, so it counts against `ROUTECHECK_CHECK_TIMEOUT` and the logged
     per-pair time. That is accepted: times are left out of every comparison.
3. **JSON's field order:** the goldens have AF, Coverage, Import, Export (from how `jsonResult` embeds `Result`).
   That order is kept byte for byte. This corrects my draft, which said AF, Import, Export, Coverage.
4. **`DirectNotChecked` is counted before the family's first report.** Today `perNeighbour` counts it after the
   import report. Moving the count ahead is a small engine change, so that the family's `Result` is complete
   before its first report.

## Left to the builder

- The streaming method's exact name, signature and doc. It must say when a report may be kept by the caller (it
  may: the library just stops referencing it).
- How the JSON is written incrementally while staying byte-identical, and the tests that prove it on every golden
  plus a multi-family, multi-export case.
- How the real-data test's `pairResult` is reorganised around the callback.
- The measurement scripts, which reuse `.data/memprof-runs.zsh` and `.data/max-prefixes-cli-runs.zsh`.
