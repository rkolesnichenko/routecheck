# Reconciliation: registered policy against real BGP routes — design

Date: 2026-10-16. Status: for approval. This document lives in rpsl's
`docs/superpowers/specs/` only until the new repository exists; it moves with
that repository's first commit, as mrt's design did.

## 1. Summary

A Go library and command that answer one question for a BGP session between
a local AS (L) and a neighbour (X):

> Of the routes X really announces, which would L's registered import policy
> accept, through which clause; which would it reject, and why; and which
> can it not decide, and why?

and its mirror, which needs no new machinery:

> Of the routes X really announces, which does X's own registered export
> policy not permit?

Routes come from two sources (both in the first version — the user's
decision):

1. **Session mode:** an MRT capture of the BGP messages X sent on the real
   session. This is the exact answer for that session.
2. **Collector mode:** public route-collector RIB dumps (RIPE RIS,
   RouteViews). Every observed path through X is cut to the part X itself
   announced. This works before the session exists, and is an
   approximation whose limits §6.3 states.

Each route also gets its RPKI origin-validation state and whether a matching
route object exists.

It builds on three things that already exist: `mrt` v0.1.0 (reads the
routes), rpsl's `resolve/peval` (turns an aut-num's policy into normalized
filters for one session) and rpsl's `resolve/rpki`. What is new is an AS-path
regular-expression matcher that runs against real paths, and the verdict
layer that decides each route against each clause and says why.

## 2. Decisions

The user's:

- Both route sources in the first version.
- The name: module `github.com/rkolesnichenko/routecheck`, command
  `routecheck`.
- The matcher's first oracle is a vector file from rpsl's
  `resolve/internal/routemodel`, written by a test-only, env-gated generator
  added to rpsl in its own PR (§10). That is the one change this project
  makes in rpsl.
- A separate repository, importing the published `rpsl` and `mrt` modules.
  rpsl's own rule stays intact: rpsl never matches an AS-path regexp against
  a live path (its CLAUDE.md, "Scope guardrails"); this repository is the
  "separate consumer" that rule names.

Mine, for the user to check while reading (each one is marked "my call"
where it appears):

- D2. Session mode reads BGP4MP message captures only. A RIB dump
  (TABLE_DUMP_V2) is a router's table *after* its import policy, so
  checking an import policy against it proves nothing (§6.2); it is refused
  unless the caller states that the table is pre-policy.
- D3. Collector-mode community tests are always undecided (§6.3).
- D4. A route the policy rejects only because a referenced set is missing
  from the registry is **Rejected**, and its reason names the missing set:
  a router configured from the registry rejects it too (§6.4).
- D5. A same-AS repetition (`~*`, `~+`, `~{m,n}`) whose operand is not a
  single-AS atom is undecided, as rpsl's test oracle declines it (§6.5).
- D6. The matcher has no repetition-count limit: its cost does not grow
  with the counts (§6.5).
- D8. ASPA path verification is not in the first version (§12).
- D9. Same Go floor (1.23), conventions (C1–C3), API golden, check script,
  CI shape and repository security settings as rpsl and mrt.

## 3. Facts checked

Each was read in the source named, on 2026-10-16.

- RFC 2622 §5.4: AS-path regexps are "POSIX compliant regular expressions
  over the alphabet of AS numbers"; `.` matches any AS; `[...]` is an AS
  set with `-` ranges and as-set names; `[^...]` its complement; `^`/`$`
  anchor the path's start/end; `* + ? {m} {m,n} {m,}` repeat; `~*` `~+`
  `~{…}` repeat with "all occurrences [matching] the same pattern"; `<AS3>`
  "matches any route whose AS-path contains AS3" (unanchored means "any
  contiguous part"); an as-set name "matches the AS-paths that is matched by
  one of the ASes in the AS-set"; `PeerAS` stands for the peer's AS.
- RFC 2622 §7: `community(...)`/`community.contains(...)` and
  `community == {...}` (exact); a value is a 4-byte integer, `hi:lo`
  (two 2-byte integers), or `internet`, `no_export`, `no_advertise`; rpsl's
  dictionary adds `local_as` (policy/dict.go). The RFC gives `internet` no
  numeric value.
- rpsl design §8.10: a `peval.Policy` holds its clauses "in specification
  order"; "a route takes the first clause it matches; one matching none is
  refused (import) or not announced (export)". Terms whose peering cannot be
  decided go to `Policy.Undecided` with a `Why`.
- rpsl `resolve.NormalizeFilter` binds `PeerAS` in a regexp
  (`ASPathRE.Bind(peer)`) and fills `PathMatch.Sets` for every set the
  regexp names, except `AS-ANY`, which it leaves out (resolve/normalize.go,
  `path`). A missing set is recorded in `Missing()`.
- rpsl API (api/*.txt at v0.29.0): `resolve.Conjunct{Prefixes, NotPrefixes
  RangeSet; Paths []PathMatch; Communities []CommunityMatch}`;
  `PathMatch{Negated bool; RE *policy.ASPathRE; Sets
  map[types.SetName]ASNSet}`; `CommunityMatch{Negated bool; Test
  policy.FilterCommunity}`; `ASNSet.Has`; `PrefixRange.Contains`;
  `rpki.VRPs.Validate(prefix, origin) State` (AS0 covers but never matches);
  `Source.OriginatedRoutes(ctx, as, afi)`.
- rpsl `resolve/internal/routemodel` matches a regexp by translating it to a
  Go regexp over tokens `<n>`; it refuses counts Go cannot compile
  (`ErrTooComplex`) and same-AS repetition over a non-single-AS operand
  (`ErrNotSingleAS`).
- mrt v0.1.0: `Routes` yields RIB entries and UPDATE announcements and
  withdrawals, and **skips** `BGP4MP_MESSAGE_LOCAL*` (messages the local
  side sent) and state changes (routes.go `messageRoutes`).
  `BGP4MPMessage` carries `PeerAS, LocalAS, PeerAddr, LocalAddr, Local`;
  `bgp.Path.ASPath` is AS_PATH merged with AS4_PATH, as typed segments
  (`ASSet`, `ASSequence`, `ASConfedSequence`, `ASConfedSet`);
  `bgp.Path.Communities []bgp.Community` (uint32).

## 4. Architecture

One Go module, `github.com/rkolesnichenko/routecheck`, go 1.23,
requiring the published `github.com/rkolesnichenko/rpsl`,
`…/rpsl/types` and `…/rpsl/resolve` at v0.29.0 and
`github.com/rkolesnichenko/mrt` at v0.1.0. No `go.work`; nothing in rpsl or
mrt changes except the routemodel generator (§2).

Packages, imports strictly downward:

```
routecheck/
  pathre/     AS-path regexp matcher over policy.ASPathRE      (rpsl/policy, rpsl/types, rpsl/resolve)
  verdict/    route × peval.Policy → verdict with reasons     (pathre, rpsl/resolve, rpsl/resolve/peval)
  observe/    MRT → routes as X announced them (both modes)    (mrt, mrt/bgp, rpsl/types)
  hygiene/    RPKI state, route-object existence              (rpsl/resolve, rpsl/resolve/rpki)
  check.go    the façade: one session, both directions        (all of the above)
  cmd/routecheck, internal/cli
```

- `pathre`, `verdict`, `observe`, `hygiene` and the façade are pure: no
  `net`, no goroutines they don't own, context-cancellable. Only
  `internal/cli` opens files and, for live IRR, uses rpsl's
  `resolve/irrd` (rpsl's own backend opener is internal; the CLI writes its
  own).
- `verdict` does not import `mrt`: it takes its own `Route` type, so it is
  testable without MRT files. `observe` converts.

## 5. Inputs

- **Policy.** IRR dump files (rpsl `resolve.Corpus` with `KeepPolicy`,
  source precedence in the order given), or a live IRRd (`resolve/irrd`).
  Optionally a local RPSL file (`-policy`) for an aut-num not yet
  published (a draft import policy) — my call. Its objects keep their
  `source:` as written. With dumps they are `Put` into the Corpus after the
  dumps, replacing an object of the same class, key and source. With
  `-irrd` the CLI wraps the server's `PolicySource` so that `AutNum` and
  `InetRtr` answer from the file first; sets always come from the
  registry.
- **Routes.** Session mode: one or more MRT files of BGP4MP messages
  (§6.2). Collector mode: one or more MRT RIB dumps (§6.3). Compressed
  files through `mrt.Decompress`.
- **RPKI.** A VRP JSON file (rpki-client / Routinator format, read by
  `rpki.ReadJSON`); optional.
- **Session parameters.** L, X, the address family (or both), and
  optionally L's and X's router addresses for peerings that name routers
  (`peval.Session.LocalRtr/PeerRtr`). They are never taken from the
  capture's session addresses, which need not be an inet-rtr's `ifaddr:`
  (my call): without them such terms stay undecided, and the report shows
  the capture's addresses as a hint for `-local-rtr`/`-peer-rtr`.

## 6. Semantics

### 6.1 The route

```go
// verdict.Route is one route as X announced it.
type Route struct {
	Prefix      netip.Prefix
	Path        []types.ASN // X first, origin last; AS_SEQUENCE segments only
	PathKnown   bool        // false: the path had an AS_SET, a confederation segment or AS_TRANS (§6.5)
	Communities []uint32    // RFC 1997 standard communities
	CommsKnown  bool        // false in collector mode (§6.3)
}
```

`observe` fills it from `bgp.Path`: segments of type `ASSequence` are
concatenated; any other segment type, or an AS 23456 (AS_TRANS) left after
mrt's AS4 merge, sets `PathKnown` false and leaves `Path` as the sequence
parts (for display only). Prepends stay: `X X X Y` is four ASes.

### 6.2 Session mode

Input: BGP4MP / BGP4MP_ET messages of the L–X session. A capture is selected
by peer AS X and, if given, peer address; the local AS comes from the
records' `LocalAS` unless given.

- **Which captures qualify.** Messages X *sent* (non-LOCAL subtypes) are
  pre-policy by construction: they are what X put on the wire. A capture
  that also has LOCAL messages (what L sent) is accepted; they are not used
  in this version. RIB dumps are refused in this mode (D2) unless the caller
  passes `-pre-policy`, stating that the table is an Adj-RIB-In before
  import policy. Which daemons write qualifying captures (OpenBGPD
  `dump all in` / `dump updates in`; BIRD `mrtdump messages`; GoBGP's MRT
  update dumps) is for the builder to confirm from each daemon's manual and
  record in the docs (§13).
- **Replay.** The state is X's Adj-RIB-Out toward L, keyed by
  (prefix, path ID when add-path is in use). An announcement replaces the
  key's route; a withdrawal deletes it. A `BGP4MP_STATE_CHANGE` *into or
  out of* Established for this peer clears the state; if the capture ends
  with the session down, the result is empty and says "session down at the
  end of the capture". The result is the state at the end of the capture,
  or at `-at TIME`.
- **Malformed attributes.** An UPDATE whose NLRI parse but whose
  attributes mrt reports as malformed is treated as a withdrawal of those
  NLRI (RFC 7606's treat-as-withdraw, what a router does) and counted; its
  prefixes never keep an earlier route (my call).
- **Not X's AS first.** A route whose path does not start with X (a
  transparent route server in front, or a misconfigured peer) is skipped
  and counted; if most routes are like this the report says X looks like a
  transparent route server, which this version does not support (§12).
- **Coverage.** If the capture has no transition to Established for this
  peer before its first UPDATE, routes X announced before the capture began
  are missing. The result says so ("capture starts mid-session; routes
  announced earlier are not seen") — a warning, not a failure.
- **Communities** are exactly what X sent: `CommsKnown` is true.

### 6.3 Collector mode

Input: MRT RIB dumps from any number of collectors. For every RIB entry
whose AS path contains X:

- The **observed route** is the suffix of the path starting at the leftmost
  (collector-nearest) occurrence of X: that is the path X itself put on the
  announcement to the AS on its left. X's own prepends stay.
- The **neighbour** it was announced to is the AS left of that occurrence.
  When X is the first AS, X is the collector's own peer (a direct feed) and
  the neighbour is the collector, whose AS a RIB dump does not carry
  (`PeerIndexTable` has only the collector's BGP ID and view name): the
  observation is marked direct, has no neighbour AS, and is exactly what X
  sent that collector.
- Observations are deduplicated by (prefix, suffix path); each keeps the set
  of neighbours and the count of collector peers it was seen through.
- A path where X appears, then another AS, then X again (path poisoning)
  still cuts at the leftmost X.
- `CommsKnown` is false (D3): communities seen at a collector may have been
  added or stripped by any AS left of X, so community tests are undecided.

What collector mode means, stated in the output: these are routes X
announced to *someone*. X may not announce all of them to L (a peer gets
X's customer cone, a customer gets everything), and may announce routes to
L that no collector sees. A Rejected route in collector mode reads "if X
sends this, L's policy rejects it", not "X sends this to L".

### 6.4 Verdicts

Every test is three-valued: **yes**, **no**, **undecided**.

- Prefix: yes when some range of `Prefixes` contains the prefix and no
  range of `NotPrefixes` does; never undecided. Every conjunct has a prefix
  test: ANY is `0.0.0.0/0^0-32` / `::/0^0-128` (`AnyPrefix()`), and an
  empty `Prefixes` matches nothing.
- Path (`PathMatch`): `pathre.Match`'s answer, flipped when `Negated`;
  undecided when `PathKnown` is false or the matcher declines (D5).
- Community (`CommunityMatch`): undecided when `CommsKnown` is false, when a
  value is `internet` (no defined value, §3) or does not parse; otherwise
  `contains`: every listed value present; `==`: the sets equal. Values
  compare numerically (`hi:lo` = hi<<16|lo; `no_export` 0xFFFFFF01,
  `no_advertise` 0xFFFFFF02, `local_as` 0xFFFFFF03 — the last is my call,
  following RFC 1997's NO_EXPORT_SUBCONFED; the builder confirms the
  mapping against IRRToolSet's), flipped when `Negated`.

A conjunct is the three-valued AND of its tests (any no → no; else any
undecided → undecided; else yes). A clause's filter is the three-valued OR
of its conjuncts. Then, over the policy's clauses in order:

- **Accepted** if some clause's filter is yes. The verdict names the first
  such clause; if an earlier clause was undecided, it says so (the route
  may take that clause, and so its actions, instead).
- **Rejected** if every clause is no and `Policy.Undecided` is empty, and
  the policy has at least one clause or undecided term.
- **No policy**: when `Policy.Clauses` and `Policy.Undecided` are both
  empty (L registers no term for X in this family), the report says
  `NoPolicy` and gives no per-route verdicts, as rpsl's `consist` does
  (`Direction.NoPolicy`). It is printed as a finding and does not set exit
  status 1 (my call).

- **Undecided** otherwise, with every reason: the undecided tests' kinds
  (path not a plain sequence, communities not known, `internet`, same-AS
  repetition over a sequence) and each undecided term's `peval` `Why`.

A clause is identified by its position in `Policy.Clauses` (`Pos`) and
shown with peval's `Clause.Index`, the attribute's position: one `import:`
with REFINE or EXCEPT flattens to several clauses sharing one `Index`
(rpsl resolve/peval/peval.go, `policy`).

A Rejected verdict carries, per clause, the first test that said no
(prefix not in the filter / in a NOT; path regexp text; community test
text), and the sets the clause's filter could not find (`Missing()`), so a
reject caused by a missing set reads as such (D4).

A policy that `peval` cannot evaluate at all (a limit, a context error, a
Source error) is an error for the whole run, never a verdict.

### 6.5 The AS-path matcher (`pathre`)

```go
// Match reports whether re matches some contiguous part of path, under RFC
// 2622 §5.4. sets gives the members of every as-set re names (AS-ANY is
// absent and matches any AS). re's PeerAS must already be bound.
func Match(re *policy.ASPathRE, sets map[types.SetName]resolve.ASNSet, path []types.ASN) (bool, error)

var ErrNotSingleAS = errors.New("pathre: same-AS repetition over more than one AS")
var ErrUnbound = errors.New("pathre: PeerAS not bound")
```

- Semantics as §3 quotes: alphabet = AS numbers; unanchored = any
  contiguous part; `.` any one AS; a class matches one AS in (or, `[^…]`,
  not in) its listed ASes, ranges and sets; an as-set atom matches one AS
  in the set; `AS-ANY` matches any one AS; a set missing from `sets`
  matches no AS (its absence is already in `Missing()`).
- `~` repetitions: the operand must be a single-AS atom (an AS, `.`, a
  class, a set); k repetitions match a run of k copies of one AS the atom
  accepts. Any other operand → `ErrNotSingleAS` (D5), which `verdict`
  turns into undecided.
- Algorithm (my call): position sets — for each sub-expression, the set of
  end positions reachable from a start position, memoized on
  (node, start). Cost is O(nodes × L²) for a path of L ASes, independent
  of repetition counts (D6): a `{m,n}` with n > L+1 behaves as `{m,L+1}`
  once the operand cannot match the empty path, and the builder handles
  operands that can (a fixed point over end-position sets).
- No `regexp` package, no backtracking; must never panic (fuzzed).

### 6.6 Hygiene

Per route, independent of the verdict:

- **RPKI**: `VRPs.Validate(prefix, origin)`; when the path's last segment
  is an AS_SET the origin is "none" (RFC 6811 §2) and is passed as AS0,
  which covers but never matches: Invalid when covered, NotFound otherwise.
  Omitted when no VRP file is given.
- **Route object**: whether the registry has a route/route6 object for
  exactly (prefix, origin), through `OriginatedRoutes(origin, afi)` read
  once per origin. Omitted for an AS_SET origin.

### 6.7 The export direction

The same verdict engine over `peval.Export` with `Session{Local: X, Peer:
N}`:

- Session mode: N = L; the routes are those X sent L.
- Collector mode: N = each observation's neighbour AS, so the export
  report is **per neighbour**: one `peval.Export` per N, verdicts for the
  routes seen announced to N. Direct-feed observations have no N and are
  counted, not checked.

A route X announced that its export policy does not permit is "announced
beyond its registered policy"; the report counts them per neighbour. A
neighbour X's policy has no term for is `NoPolicy` for that neighbour, not
a reject of every route.

## 7. API (exact)

```go
package routecheck

type Mode uint8
const (
	ModeSession Mode = iota + 1
	ModeCollector
)

type Options struct {
	Local, Peer   types.ASN
	AF            []types.AddrFamily // empty: ipv4.unicast and ipv6.unicast
	LocalRtr      netip.Addr         // optional, passed to peval
	PeerRtr       netip.Addr
	PeerAddr      netip.Addr         // session mode: select the capture's peer address
	At            time.Time          // session mode: state at this time; zero = end of capture
	PrePolicyRIB  bool               // session mode: accept a RIB dump as Adj-RIB-In (D2)
	Directions    Direction          // Import, Export or both (default both)
	VRPs          *rpki.VRPs         // optional
}

type Checker struct {
	Eval   peval.Evaluator // Src, Expander, Source as rpsl's peval takes them
	Routes resolve.Source  // for route-object existence; usually Eval.Src
}

// Check reads the routes from records (mrt.Records over the inputs) and
// returns one Result per address family. It never stops at a bad route: bad
// routes are counted in the Result.
func (c *Checker) Check(ctx context.Context, mode Mode, records iter.Seq2[mrt.Record, error], o Options) ([]Result, error)

type Result struct {
	AF       types.AddrFamily
	Import   *Report  // nil when not asked
	Export   []Report // session mode: one, toward L; collector mode: one per neighbour, by AS
	Coverage Coverage // mid-session start, session down at end, skipped records,
	                  // malformed routes, routes not starting with X, direct-feed count
}

type Report struct {
	Toward   types.ASN // the session's Peer: X for import, the neighbour for export
	Policy   peval.Policy
	NoPolicy bool           // no clause and no undecided term: no per-route verdicts
	Routes   []RouteVerdict // in prefix order
	Accepted, Rejected, Undecided int
}

type RouteVerdict struct {
	Route    verdict.Route
	Evidence observe.Evidence // neighbours, direct feed, collector-peer count, time
	Verdict  verdict.Verdict
	RPKI     *rpki.State // nil when no VRPs
	RouteObj *bool       // nil when not checked
}
```

```go
package verdict

type Outcome uint8
const (
	Accepted Outcome = iota + 1
	Rejected
	Undecided
)

type Verdict struct {
	Outcome          Outcome
	Clause           int      // Accepted: Pos of the first clause that said yes
	EarlierUndecided []int    // Accepted: Pos of undecided clauses before it
	Fails            []Fail   // Rejected: one per clause
	Reasons          []Reason // Undecided: every reason, deduplicated
}

type Fail struct {
	Clause  int               // Pos in Policy.Clauses
	Test    string            // the first test that said no, as filter text
	Missing []types.SetRef    // sets the clause's filter could not find
}

type Reason struct {
	Kind   string // ReasonPathNotSequence, ReasonCommsUnknown, ReasonCommInternet,
	              // ReasonCommValue, ReasonSameASRun, or ReasonPeval
	Why    string // ReasonPeval: peval's Why text as given (a Why* constant,
	              // possibly with a suffix: WhyProtocol and WhyInto add the protocol)
	Clause int    // a filter reason: Pos in Policy.Clauses; ReasonPeval: -1
	Index  int    // ReasonPeval: the Undecided term's attribute Index
	Term   string
}

// Decide decides r against p. It holds no state; p's filters may be shared.
func Decide(p peval.Policy, r Route) Verdict
```

The names above are binding; field order and the helpers inside the
packages are the builder's. `observe` exposes `Session(records, sel)
iter.Seq2[Observation, error]` and `Collector(records, x)
iter.Seq2[Observation, error]` with `Observation{Route verdict.Route;
Evidence Evidence; Family bgp.Family}`; their exact shape is the builder's
within that.

## 8. The command

```
routecheck -local AS -peer AS (-session FILE… | -collector FILE…)
           (-dump FILE… | -irrd HOST:PORT [-sources LIST]) [-policy FILE]
           [-vrps FILE] [-af ipv4|ipv6|both] [-direction import|export|both]
           [-peer-addr IP] [-at TIME] [-pre-policy]
           [-local-rtr IP] [-peer-rtr IP] [-format text|json] [-routes all|rejected|undecided|none]
```

- Text output: per family and direction, the counts; Rejected routes grouped
  by their first failing test, with up to N examples each; Undecided grouped
  by reason; coverage warnings; then the routes asked for.
- JSON output: one document with every field of `Result`.
- Exit status (as rpslcheck's): 0 nothing Rejected; 1 some route Rejected
  (either direction); 2 a bad command line; 3 could not complete (a file
  unreadable, the aut-num missing, peval failing, the server unreachable).
  Undecided routes alone exit 0 — they are listed, not failures.

## 9. Limits and performance

- Memory: routes are streamed; held are only X's routes (session: one
  Adj-RIB-Out; collector: deduplicated observations through X) and the
  policy's filters. A RIPE dump with `KeepPolicy` is rpsl's measured
  460 MB + 95 MB (rpsl CLAUDE.md).
- Prefix tests run against an index built once per clause (a trie over the
  clause's ranges), not a scan of `RangeSet.List()` per route; path tests
  are memoized per (regexp, path), since many routes share a path.
- The builder measures and records, from runs in the work: a full IPv4
  table from one direct feed against one real policy (time, peak RSS); a
  RIS+RouteViews collector run for one AS. No figure is promised here.

## 10. Tests

- **Matcher, oracle 1 — routemodel vectors.** A test-only generator in
  rpsl (`resolve/internal/routemodel`, run only when
  `RPSL_ROUTEMODEL_VECTORS=path` is set; no API change) writes
  (regexp text, set members, path, routemodel's answer or its error) for:
  every RFC 2622 §5.4 example, rpsl's routemodel table tests, and seeded
  random regexps × paths. The file is committed here with rpsl's commit SHA
  in its header; `pathre` must agree on every vector (an `ErrTooComplex`
  vector must get a real answer from `pathre`, checked against oracle 2).
- **Matcher, oracle 2 — in-repo token translation.** An independent,
  test-only translation of the regexp into a Go `regexp` over `<n>` tokens
  (the technique, re-implemented, not copied), for random regexp × path
  properties. It clamps every repetition count to L+1 for a path of L ASes,
  which keeps the answer exact (an operand that cannot match the empty path
  cannot repeat more than L times; one that can fills the rest with empty
  matches) and so checks `pathre` on counts over Go's 1000 too.
- **Fuzz:** `FuzzMatch` (regexp text × path bytes): never panics; agrees
  with oracle 2 whenever both answer. `FuzzObserve` (MRT bytes): never
  panics. `FuzzDecide`.
- **Verdict:** table tests per rule in §6.4; a model test: random policies
  over an rpsl `MemSource`, verdicts against a naive in-test evaluator.
  **bgpq4 differential:** for prefix-only policies (`accept AS-X`),
  Accepted ⇔ prefix in `bgpq4 -j`'s expansion of AS-X, on the same fixed
  snapshot rpsl's differential uses; skipped when bgpq4 is absent, required
  in CI.
- **Observe:** synthetic MRT (mrt's `internal/mrtgen` technique, own
  generator) for replay (announce/withdraw/re-establish/add-path/mid-session
  start), suffix cutting (prepends, poisoning, direct feed, AS_SET,
  confederation, AS_TRANS), dedup.
- **Goldens:** the command's text and JSON on committed fixtures
  (RouteViews slices, CC BY 4.0, as in mrt; synthetic captures; a small
  RPSL snapshot); `ROUTECHECK_GOLDEN_UPDATE=1` rewrites them.
- **Real data (opt-in), one at a time under the memory guard:** a RIPE dump
  + a RouteViews and a RIS RIB (RIS downloaded at test time, never
  committed); for a sample of RIPE aut-nums with `import: from X`, run both
  directions in collector mode; no error beyond counted limits; Undecided
  reasons tallied; one Rejected route and one count checked by hand against
  `whois` and the RIB.

## 11. Repository

As mrt: MIT licence, README with a worked example, CLAUDE.md (the operating
contract, including "never push a local home-directory path"), CHANGELOG,
`scripts/check.sh` (gofmt, vet, `-race`, coverage, no-`net` outside
`internal/cli`, API golden), `scripts/fuzz.sh`, CI with a `ci ok` job,
SHA-pinned actions, Dependabot for actions, SECURITY.md, and the GitHub
settings rpsl and mrt now have (ruleset, required `ci ok`, private
vulnerability reporting, secret scanning with push protection, Dependabot
alerts, required SHA pinning). Releases with a `release.sh` like mrt's.

## 12. Out of scope (first version)

- ASPA path verification (D8): its own algorithm and test vectors; next.
- BMP and RIS Live (mrt does not read them).
- Transparent route servers (`import-via:` and a peer whose routes do not
  start with its AS): detected and reported (§6.2), not evaluated.
- Checking what L sent (LOCAL messages) against L's export policy: the same
  machinery, later.
- Applying clause actions (pref, med, community changes, prepends) to
  routes.
- `import-via:`/`export-via:` and `default:`.
- Deciding anything about a regexp in a *peering* (peval leaves it
  undecided already).
- Evaluating a policy against a router's configuration (that is rpsl's
  `rtconfig`).

## 13. Risks and open facts for the builder

- Which daemons' MRT captures are pre-policy and complete (§6.2): confirm
  for OpenBGPD, BIRD 2 and GoBGP from their manuals, write it in the docs,
  and add one real capture from at least one of them to the fixtures if
  it can be made locally.
- `local_as`'s value (§6.4): confirm against IRRToolSet's community code.
- Whether mrt's `Routes` exposes everything session replay needs; it skips
  state changes, so `observe` reads `mrt.Records` itself for them. If an
  mrt change is needed, it is a separate mrt release, not a fork.
- Evidence of demand is thin (the planning session's own note). The first
  version is sized to answer the session question well, not to be a
  platform.

