# Verified-marking Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Every route-object answer says whether a verified registry (by default the five RIRs) backs it. Text,
JSON and the per-report counts show "yes (unverified only)", and verdicts are left unchanged.

**Architecture:**
- The library gains a second route source, `Checker.VerifiedRoutes`, asked only when the main route-object answer is
  "yes", and a `RouteVerdict.RouteObjVerified` answer.
- The CLI decides once which verified sources are present: under `-dump`, those loaded; under `-irrd`, those the
  server accepts, each probed alone.
  - It builds the verified source over them: `Corpus.SourceOf` under `-dump`, a source-restricted `irrd.Source`
    under `-irrd`.
  - With none present it turns the marking off, with one note on stderr.

**Tech Stack:** Go 1.23 (go.mod floor), rpsl v0.30.0 (`resolve.Corpus.SourceOf`, `irrd.Source.Sources`,
`irrd.ErrQueryRefused`).

**Spec:** `docs/superpowers/specs/2026-10-19-verified-marking-design.md`

## Global Constraints

- Verdicts, filters, exit status and the existing `RouteObj` answer stay exactly as in v0.4.0. "Unverified only" is
  never a Warning.
- The default verified sources are `RIPE,APNIC,ARIN,AFRINIC,LACNIC`, compared to `source:` names without regard to
  case. `-verified-sources LIST` replaces them. An empty list, an empty item or a duplicate name is a usage error
  (exit 2).
- The text wording is exactly `route object yes`, `route object yes (unverified only)` and `route object no`. The
  JSON field is `RouteObjVerified`. The words "invalid" and "untrusted" never appear in this marking.
- `RouteObjVerified` is nil when `RouteObj` is nil or the marking is off, `false` when `RouteObj` is false (no
  query), and otherwise the verified source's answer.
- Being unavailable is decided once, at startup. Once the marking is on, an error from a verified lookup fails the
  run like any route-object lookup error; context errors stay errors.
- Under `-irrd`, the verified sources asked are the defaults or `-verified-sources`, limited to `-sources` when that
  is given, and each is probed alone. A source the server refuses (`irrd.ErrQueryRefused`) is absent.
- **Plan decision:** the design's "else the server's default list (`!s-lc`)" is not needed. The verified query is
  skipped when the main answer is "no", so a verified "yes" beside an overall "no" cannot occur.
- Memory budget: the command on AS9086 from AS6762, every registry, `-max-prefixes 2097152`, must peak at or below
  6,811 MB (6,511 MB in v0.4.0, `.data/max-prefixes-cli-2097152.log`). Measured in Task 4.
- An API addition is v0.5.0. `api/*.txt` is regenerated with `ROUTECHECK_API_UPDATE=1 go run ./internal/apisurface -check`,
  and its diff is reviewed.
- Heavy runs go one at a time under `MEMGUARD_NORMAL_PRIORITY=1 ../rpsl/.superpowers/sdd/tools/memguard.sh 8 …`, with
  `GOMAXPROCS=4` and `GOMEMLIMIT=6GiB`, never beside check.sh.
- No local home-directory path in any committed file or commit message. Every published figure names its log.
- `scripts/check.sh` passes, run under the memory guard.

## Review Focus

1. **A `-dump` run whose dumps hold none of the verified sources** (the test goldens hold only `source: TEST`). The
   marking is off and the note is printed. Routes read plain `route object yes` and never "unverified only".
   Task 2's `TestVerifiedNoneLoaded` pins this.
2. **An `-irrd` server that serves only some RIRs.** The others are absent and named. The run does not fail on IRRd's
   whole-list refusal. Task 2's `TestVerifiedIRRdPartial` pins this.
3. **`-verified-sources` with odd input** (`" ripe , arin "`, `"RIPE,ripe"`, `","`). It is trimmed and upper-cased;
   a duplicate or empty item is refused. Task 2's `TestParseVerifiedSources` pins this.
4. **A route with no origin** (an AS_SET at the end of its path). Both answers are nil, and the counts skip it.
   Task 1's `TestRouteObjVerifiedNoOrigin` pins this.
5. **A verified lookup error mid-run** fails the run, like today's route-object error; it is never a silent nil.
   Task 1's `TestVerifiedLookupError` pins this.

---

### Task 1: The library answers RouteObjVerified

**Files:**
- Modify: `hygiene/hygiene.go`, `check.go`, `api/hygiene.txt`, `api/routecheck.txt`
- Test: `hygiene/hygiene_test.go`, `check_test.go`

**Interfaces:**
- Produces:
  - `hygiene.Checker` gains `Verified resolve.Source`.
    - `(*hygiene.Checker) VerifiedRouteObject(ctx context.Context, r verdict.Route, afi types.AFI) (*bool, error)`
      answers as `RouteObject` does, but from `Verified`, with its own cache.
    - It returns nil, nil when `Verified` is nil or the route has no origin.
  - `routecheck.Checker` gains `VerifiedRoutes resolve.Source`. Its doc says: asked only for routes whose
    `RouteObj` is true; nil turns the marking off.
  - `routecheck.RouteVerdict` gains `RouteObjVerified *bool`, set as the Global Constraints say.
  - `routecheck.Report` gains `RouteObjYes, RouteObjUnverifiedOnly, RouteObjNo int`, counted over `Routes`.
    `RouteObjUnverifiedOnly` counts `RouteObj` true with `RouteObjVerified` false, a subset of `RouteObjYes`.

- [ ] **Step 1: Write the failing tests:**
  - `TestVerifiedRouteObject` (hygiene): `Src` holds (192.0.2.0/24, AS64500) and (198.51.100.0/24, AS64500);
    `Verified` holds only the first.
    - `VerifiedRouteObject` answers true and false.
    - It is nil with `Verified` nil.
    - It reads each (origin, family) once (a counting source).
  - `TestRouteObjVerified` (check_test, collector mode), on three routes:
    - yes and verified gives `RouteObj` true, `RouteObjVerified` true;
    - yes and unverified only gives true, false;
    - no gives false, false, and `VerifiedRoutes` is never asked for that route's origin (a counting source);
    - the report counts are 2 yes, 1 unverified only, 1 no;
    - the verdicts equal those of the same Check with `VerifiedRoutes` nil.
  - `TestRouteObjVerifiedNoOrigin`: a path ending in an AS_SET gives both answers nil and counts it in neither.
  - `TestVerifiedLookupError`: a `VerifiedRoutes` that errors for the origin makes `Check` return that error.

- [ ] **Step 2: Run** `GOWORK=off go test -run 'TestVerifiedRouteObject' ./hygiene` and `GOWORK=off go test -run 'TestRouteObjVerified|TestVerifiedLookupError' .`.
  Expected: FAIL (undefined).

- [ ] **Step 3: Implement.**
  - `run` builds the `hygiene.Checker` with `Verified: c.VerifiedRoutes`.
  - `famRun.hygiene` asks `VerifiedRouteObject` only when `obj != nil && *obj`. `routeHygiene` gains `verified *bool`.
  - Both report builders fill `RouteObjVerified` and the three counts.
  - Regenerate `api/*.txt` and check its diff holds only these additions.

- [ ] **Step 4: Run** the focused tests and then `scripts/check.sh` under the guard. Expected: PASS and `SUCCESS`.

- [ ] **Step 5: Commit**: `routecheck: answer whether a verified registry backs each route object (RouteObjVerified)`.

### Task 2: The CLI picks the verified sources and wires them

**Files:**
- Modify: `internal/cli/cli.go` (flag, config, usage synopsis, wiring), `internal/cli/load.go`
- Test: `internal/cli/cli_test.go`

**Interfaces:**
- Consumes: `Checker.VerifiedRoutes` (Task 1).
- Produces:
  - `parseVerifiedSources(s string) ([]string, error)`: trimmed, upper-cased and in order; an empty list, an empty
    item or a duplicate is an error naming it.
  - A flag, exactly:
    `fs.String("verified-sources", "RIPE,APNIC,ARIN,AFRINIC,LACNIC", "the registries whose route objects count as verified, comma-separated (\`names\`); see docs/routecheck.md")`.
  - `loadPolicy` returns, besides the policy source, a `verified resolve.Source` (nil when the marking is off) and
    `verifiedNote string`, the one stderr line:
    - under `-dump`: `c.SourceOf(present...)`, where present is the verified names in the order the dumps' sources
      first appear;
    - under `-irrd`: an `irrd.Source` with the same address and `Sources: present`, where present is each verified
      name (within `-sources` when given) that a one-source probe does not refuse. The probe is `OriginatedRoutes`
      for AS64496 and IPv4 on `irrd.Source{Sources: {name}}`; an error matching `irrd.ErrQueryRefused` means
      absent, and any other error fails the run.
  - The stderr line, always printed when route-object answers are given:
    - `route objects: verified sources RIPE, ARIN; absent: APNIC, AFRINIC, LACNIC` (`; absent: …` only when some
      are absent);
    - when none is present: `route objects: none of the verified sources (RIPE, APNIC, ARIN, AFRINIC, LACNIC) is present; answers are not marked`.

- [ ] **Step 1: Write the failing tests:**
  - `TestParseVerifiedSources`:
    - `" ripe , arin "` gives [RIPE ARIN];
    - errors: `""`, `","`, `"RIPE,ripe"` (names RIPE), `"RIPE,,ARIN"`.
  - `TestVerifiedNoneLoaded`:
    - a `-dump` of the golden policy (`source: TEST` only) prints the "none … is present" note;
    - every route-object answer in `-format json` has `"RouteObjVerified": null`;
    - the text never holds "unverified only".
  - `TestVerifiedDump`: two dumps, one with `source: RIPE` routes and one with `source: RADB` routes. A route only
    RADB holds reads `RouteObjVerified` false; one RIPE holds reads true; the note names RIPE, with absent APNIC,
    ARIN, AFRINIC, LACNIC.
  - `TestVerifiedIRRdPartial`: an in-process IRRd serving registries RIPE and RADB (generalize `serve` to take several
    named registries).
    - With the default list, the run succeeds;
    - the note lists RIPE as present and the other four as absent;
    - the answers match `TestVerifiedDump`'s.
  - `TestVerifiedSourcesFlag`: `-verified-sources RADB` makes the RADB-only route verified; `-verified-sources ""`
    exits 2.
  - TestHelp pins the flag in `-h`.

- [ ] **Step 2: Run** `GOWORK=off go test -run 'TestParseVerifiedSources|TestVerified|TestHelp' ./internal/cli`. Expected: FAIL.

- [ ] **Step 3: Implement.** `-verified-sources` is accepted with both `-dump` and `-irrd`. The stderr line is
  written once, before the report.

- [ ] **Step 4: Run** the focused tests and then `scripts/check.sh` under the guard. Expected: PASS and `SUCCESS`.

- [ ] **Step 5: Commit**: `cli: choose the verified sources present and mark route objects (-verified-sources)`.

### Task 3: Text output, counts and docs

**Files:**
- Modify: `internal/cli/text.go`, the goldens under `testdata/golden`, `docs/routecheck.md` (flag table, the "Each
  route also gets" list, the caveat sentence about RADB and the mirrors in the "Load every registry" bullet)
- Test: `internal/cli/cli_test.go`, `internal/cli/golden_test.go`

**Interfaces:**
- Consumes: Task 1's fields and counts, and Task 2's wiring.
- Produces:
  - `hygiene()` in text.go prints `route object yes (unverified only)` when `RouteObj` is true and
    `RouteObjVerified` is false, and otherwise the existing words.
  - The report line `  %s: %s: %d accepted, %d rejected, %d undecided` gains, when any route has a route-object answer:
    `; route objects %d yes (%d unverified only), %d no`. The `(… unverified only)` part appears only when the marking is on.

- [ ] **Step 1: Write the failing tests:**
  - `TestTextUnverifiedOnly`: on Task 2's two-dump fixture, `-routes all` prints the RADB-only route with
    `route object yes (unverified only)` and the RIPE one with `route object yes`, and the report line holds
    `route objects 2 yes (1 unverified only), 0 no` (adjust to the fixture's counts).
  - `TestJSONRouteObjVerified`: the JSON's route objects hold `RouteObjVerified` and the report's three counts.
  - The goldens are regenerated, and the diff reviewed: only the report lines' new counts and nothing else move,
    since the golden dumps hold no verified source.

- [ ] **Step 2: Run** `GOWORK=off go test -run 'TestTextUnverifiedOnly|TestJSONRouteObjVerified|TestGolden' ./internal/cli`. Expected: FAIL.

- [ ] **Step 3: Implement.** Then the docs:
  - the flag table row for `-verified-sources`;
  - the output section: the three answers, what "unverified only" means, and that it is weaker evidence, not wrong;
  - the "Load every registry" caveat pointing at the marking.

- [ ] **Step 4: Run** the focused tests and then `scripts/check.sh` under the guard. Expected: PASS and `SUCCESS`.

- [ ] **Step 5: Commit**: `cli: show unverified-only route objects in text and JSON, with per-report counts`.

### Task 4: Measure and publish (controller)

**Files:**
- Modify: `CHANGELOG.md` (`[Unreleased]`: Added, Changed, `### Measured, verified marking`), `CLAUDE.md`, and the
  docs' memory figures if they change.

- [ ] **Step 1: Memory.** Run the command on AS9086 from AS6762 as `.data/max-prefixes-cli-runs.zsh` does: every dump,
  `-max-prefixes 2097152`, under the guard. Log to `.data/verified-cli-2097152.log`. Expected: same exit status and
  counts as `.data/max-prefixes-cli-2097152.log`, and a peak RSS at or below 6,811 MB.
  - If the peak is over, stop and dispatch a fix task: replace `SourceOf` with an index of the verified route objects
    alone. Then measure again.
- [ ] **Step 2: Marking on real data.** From the same log, record the route-object counts per direction, with the
  unverified-only share. Check them against the registry-provenance measurement's direction: the share should sit
  near 36% on the same routes. If it is far off, investigate before publishing.
- [ ] **Step 3: `-irrd` cost.** From Task 1's counting test, the verified queries are at most one per (origin, family)
  with a "yes". Publish that count rule, not a time.
  - **Plan decision:** in-process timings would mean little, and the design's aim, bounding the extra queries, is
    met by the rule.
- [ ] **Step 4: Docs.**
  - CHANGELOG: Added (the marking, `-verified-sources`, the API fields), Changed (the text route line and report
    counts), and Measured (the memory, the real-data counts, the logs).
  - CLAUDE.md: the flag and a new ruling line (R28: the marking is evidence beside the verdict, never an input).
  - Run `scripts/check.sh` under the guard. Expected: `SUCCESS`.
- [ ] **Step 5: Commit**: `docs: the verified marking, measured`.
