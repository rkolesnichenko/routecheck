# routecheck

`routecheck` checks the routes a BGP neighbour X really announces against the
policies registered in the Internet Routing Registry. For a session between a
local AS L and X it answers two questions:

- Of the routes X really announces, which would L's registered import policy
  accept, and through which clause? Which would it reject, and why? Which can it
  not decide, and why?
- Of the routes X really announces, which does X's own registered export policy
  not permit?

```sh
go install github.com/rkolesnichenko/routecheck/cmd/routecheck@latest
```

The design, with every rule this page summarizes, is in
`docs/superpowers/specs/2026-10-16-reconcile-design.md`.

## Synopsis

```
routecheck -peer AS (-session FILE [-local AS] | -collector FILE -local AS)
           (-dump FILE | -irrd HOST:PORT [-sources LIST]) [-policy FILE]
           [-vrps FILE] [-af ipv4|ipv6|both] [-direction import|export|both]
           [-peer-addr IP] [-at TIME] [-pre-policy]
           [-local-rtr IP] [-peer-rtr IP] [-format text|json]
           [-routes all|rejected|undecided|none]
```

`-session`, `-collector` and `-dump` can be repeated, one file per flag. Files
are read in the order given. Each one may be raw, gzip or bzip2: the format is
told by the file's first bytes (`mrt.Decompress`), not by its name. Flags come
before any other argument. A stray argument is refused with exit status 2.

| flag | meaning |
|---|---|
| `-peer AS` | X, the neighbour whose routes are checked. Required. `AS65001` and `65001` are both accepted. |
| `-local AS` | L, whose import policy is checked. Session mode: optional, and the default is the capture's local AS. Collector mode: required when the import direction is checked. Must differ from `-peer`. |
| `-session FILE` | Session mode. An MRT capture of the L–X session: BGP4MP / BGP4MP_ET messages that X sent. See "Which captures qualify" below. |
| `-collector FILE` | Collector mode. A route-collector MRT RIB dump (TABLE_DUMP_V2 or TABLE_DUMP), such as a RIPE RIS bview or a RouteViews RIB. |
| `-dump FILE` | An IRR dump file holding the policies, sets and routes. When two registries hold an object, the one whose `source:` comes first in the dumps (in the order given) wins. Give either `-dump` or `-irrd`, not both. |
| `-irrd HOST:PORT` | A live IRRd, used instead of `-dump`. Port 43 when none is given. |
| `-sources LIST` | Only with `-irrd`. The registries, comma-separated, in precedence order. The default is the server's own order. |
| `-policy FILE` | A local RPSL file: a draft that is not yet published. Its aut-nums and inet-rtrs answer before the registry's, under any `source:`. See "A -policy draft" below. |
| `-vrps FILE` | A VRP JSON file in rpki-client or Routinator format. With it, each route gets an RPKI origin-validation state. |
| `-af` | `ipv4`, `ipv6` or `both` (the default): the unicast families checked. Routes of any other family are dropped and counted. |
| `-direction` | `import` (L's policy), `export` (X's policy) or `both` (the default). |
| `-peer-addr IP` | Session mode only. Read only the capture's records that have this peer address. |
| `-at TIME` | Session mode only. Report the state at this RFC 3339 time, such as `2026-10-16T12:00:00Z`. Records at that time are included. The default is the end of the capture. |
| `-pre-policy` | Session mode only. States that the RIB dumps in the input are X's Adj-RIB-In before import policy (see D2 below). |
| `-local-rtr IP`, `-peer-rtr IP` | L's and X's router addresses on the session, for peerings that name routers. They are never taken from the capture (see below). |
| `-format` | `text` (the default) or `json`. |
| `-routes` | Text output only. Which routes to list after the summary: `all`, `rejected`, `undecided` or `none` (the default). |

## The two modes

**Session mode** (`-session`) gives the exact answer for that session. It
replays X's Adj-RIB-Out toward L, keyed by prefix and add-path path ID: an
announcement replaces the key's route and a withdrawal deletes it. A transition
into or out of Established for the peer clears the state. The result is the
state at the end of the capture, or at `-at`.

- **A capture that starts mid-session.** When the capture has no transition to
  Established before X's first UPDATE, the output warns: "capture starts
  mid-session; routes announced earlier are not seen".
- **A session that is down at the end.** The result is empty, and the output
  says "session down at the end of the capture".
- **Malformed UPDATEs** are handled as RFC 7606 says. Most become
  treat-as-withdraw, and those prefixes never keep an earlier route. An UPDATE
  RFC 7606 answers with a session reset clears the state. Both are counted and
  reported.
- **Routes whose path does not start with X** are skipped and counted. Such an
  announcement still withdraws the route it replaced. When most routes seen are
  like this, the output says X looks like a transparent route server, which this
  version does not support.
- **LOCAL messages** (what L sent) are accepted but not used.
- **A RIB dump** in session mode is refused (exit 3, with a hint) unless you pass
  `-pre-policy`.

**Collector mode** (`-collector`) works before the session exists. It is an
approximation. For every RIB entry whose AS path contains X, it keeps:

- the observed route: the suffix of the path from the leftmost (collector-nearest) X
  on, which is what X put on the announcement;
- the neighbour it was announced to: the AS just left of X.

When X is the collector's own peer, the sighting is a "direct feed" and has no
neighbour AS. Observations are deduplicated by (prefix, suffix path).

### What collector mode means

The output says this itself. These are routes X announced to *someone*. X may
not announce all of them to L: a peer gets X's customer cone, while a customer
gets everything. X may also announce routes to L that no collector sees. In
collector mode, a Rejected route reads "if X sends this, L's policy rejects it".
It does not mean "X sends this to L". Community tests are always undecided in
collector mode (D3), because any AS left of X may have added or stripped
communities.

In collector mode the export direction is reported per neighbour. X's export
policy is evaluated toward each AS that X was seen announcing to, over the routes
seen announced to that AS. A direct-feed sighting has no neighbour AS, so it is
counted and not checked.

## Verdicts

Every test is three-valued: yes, no or undecided. A conjunct is the
three-valued AND of its tests, and a clause is the three-valued OR of its
conjuncts. The clauses are then taken in order.

- **accepted**: some clause says yes. The output names the first such clause.
  When an earlier clause or a term peval could not evaluate was undecided, the
  route may take that one instead, and the output says so ("after undecided
  clause N").
- **rejected**: every clause says no, and no term is undecided. For each clause,
  the output gives the first test that said no. When a referenced set is missing
  from the registry, the output names it ("missing from the registry"). Such a
  route is still rejected (D4), because a router configured from the registry
  rejects it too.
- **undecided**: neither of the above. The output gives every reason:

  | reason | meaning |
  |---|---|
  | `path-not-sequence` | The path holds an AS_SET, a confederation segment or AS_TRANS, and a path test needs it. |
  | `communities-unknown` | The communities are not known (collector mode). |
  | `community-internet` | The test names `internet`, which has no defined value. |
  | `community-value` | A community value in the test does not parse. |
  | `same-as-run` | A `~*`, `~+` or `~{m,n}` whose operand is not a single-AS atom (D5). |
  | `path-too-expensive` | The AS-path regexp exceeded the matcher's work budget for this path (D6). |
  | `path-unbound` | The regexp's PeerAS was not bound. This is a caller's bug: peval always binds it. |
  | `peval` | A term peval could not evaluate for this session, with peval's own reason. For example, `peval: peer router not given` (pass `-local-rtr`/`-peer-rtr`). |
  | `unevaluable` | peval could not evaluate the whole policy, because it names AS-ANY where rpsl cannot expand it (see "Known limitations"). |

- **no policy**: L has no import term toward X in this family (or, for export,
  X has no export term toward the neighbour). Its routes are not decided. This is
  printed as a finding and does not set exit status 1.

Each route also gets:

- an RPKI state (`valid`, `invalid` or `not_found`) when `-vrps` is given;
- whether a route object exists for exactly that (prefix, origin).

## A -policy draft

A `-policy` file supplies only aut-nums and inet-rtrs. Sets and routes always
come from the registry. In the draft, the following are skipped with a warning
on stderr, whether broken or not:

- set objects (`as-set`, `route-set`, `filter-set`, `peering-set`, `rtr-set`);
- `route` and `route6` objects;
- objects of classes routecheck does not use (`mntner`, `person`, `role`, …).

The file's parse and decode diagnostics go to stderr. The run fails with exit 3,
naming the file and the object, in any of these cases:

- an aut-num or inet-rtr with an error;
- an aut-num or inet-rtr the registry refuses;
- a file with no aut-num and no inet-rtr.

## Router addresses

A peering that names a router (`from AS1 192.0.2.1 at 192.0.2.2`) needs the
session's router addresses. routecheck never takes them from the capture's
session addresses, which need not be an inet-rtr's `ifaddr:`. Without
`-local-rtr`/`-peer-rtr` such a term is undecided. The text output then ends
with a hint that offers the capture's addresses as candidates.

## Output

**Text.** The output has three parts:

1. A header naming the mode, L, X and the input files, as given.
2. The coverage warnings.
3. For each family and direction:
   - the counts and the policy's clauses;
   - the Rejected routes, grouped by their first failing test, with up to 5
     examples per group;
   - the Undecided routes, grouped by reason;
   - the routes `-routes` asks for.

The README shows a session example and a collector example.
Coverage warnings include:

- capture starts mid-session;
- session down at the end;
- no record at or before `-at`;
- RFC 7606 resets and treat-as-withdraw counts;
- announcements that did not start with X;
- update records ignored in collector mode;
- malformed RIB entries;
- sightings with no neighbour;
- routes in a family not checked.

**JSON** (`-format json`) is one document, `[]routecheck.Result`. It keeps every
field name of `Result`, `Report`, `RouteVerdict`, `Verdict`, `Fail` and `Route`,
in a form that needs no Go source to read:

- an outcome is `"accepted"`, `"rejected"` or `"undecided"`;
- an RPKI state is `"valid"`, `"invalid"` or `"not_found"`;
- communities are `"hi:lo"`;
- a policy is its clauses, each as `{Index, Term, Filter}`, and its undecided
  terms, each as `{Index, Term, Why}`;
- `Unevaluable` holds peval's error text for an unevaluable report, and is `""`
  otherwise.

Two kinds of number appear:

- `Verdict.Clause`, `EarlierUndecided`, `Fails[].Clause` and `Reasons[].Clause`
  are positions in the `Clauses` array, counted from 0;
- a clause's `Index` is the position of its `import:`/`export:` attribute.

One attribute with REFINE or EXCEPT gives several clauses that share one `Index`.

## Exit status

| status | meaning |
|---|---|
| 0 | Nothing was Rejected. Undecided routes and "no policy" alone exit 0: they are listed, not failures. |
| 1 | Some route was Rejected, in either direction. |
| 2 | A bad command line, including options the library refuses (`routecheck.ErrOptions`, such as a session mode run with no `-local` whose capture names no local AS). |
| 3 | The run could not complete. Causes: an unreadable file, a missing aut-num, peval failing (a limit, a Source error; but not AS-ANY, which is "unevaluable"), an unreachable server, a RIB dump in session mode without `-pre-policy`, a broken `-policy` draft, or an interrupted run. |

## Which captures qualify for -session

Session mode needs what X put on the wire, before L's import policy. BGP4MP
messages that X sent are pre-policy by construction. A table dump is a
router's RIB, which is usually after import policy, so it qualifies only with
`-pre-policy`, and only when it really is the Adj-RIB-In (D2). Every row below
comes from the daemon's manual, fetched on 2026-10-17. Each quoted sentence is
copied verbatim (with HTML line breaks joined), and its URL is given.

Sources:

- **OpenBGPD**: `bgpd.conf(5)`, <https://man.openbsd.org/bgpd.conf.5>
  (OpenBSD-current, dated September 24, 2026).
- **BIRD 2**: BIRD 2.0 User's Guide:
  - <https://bird.network.cz/?get_doc&v=20&f=bird-3.html> (chapter 3, Configuration);
  - <https://bird.network.cz/?get_doc&v=20&f=bird-6.html> (chapter 6, Protocols).
- **GoBGP**: `docs/sources/mrt.md` at commit `e2cd8b1f900acea0f6bd558f84b75b624a324e0a`,
  <https://github.com/osrg/gobgp/blob/e2cd8b1f900acea0f6bd558f84b75b624a324e0a/docs/sources/mrt.md>.

| daemon | setting | qualifies for `-session` | the manual's sentence |
|---|---|---|---|
| OpenBGPD | `dump all in FILE` | **yes** | "Dumps of ongoing BGP activity include all BGP state transitions, and all BGP messages in the specified direction." |
| OpenBGPD | `dump updates in FILE` | **yes**, but with no state transitions, so routecheck always warns "capture starts mid-session", and a session reset inside the capture is not seen | "Use updates to dump only BGP UPDATE messages, without state transitions." |
| OpenBGPD | `dump all out` / `dump updates out` | **no**: these are the messages L sent, not X | "Dumps of ongoing BGP activity include all BGP state transitions, and all BGP messages in the specified direction." |
| OpenBGPD | `dump table FILE`, `dump table-v2 FILE`, `dump table-mp FILE` | **no**: the manual does not name the RIB dumped by default; take it as a post-policy table | "Dump the RIB, a.k.a. the routing information base, or dump ongoing BGP activity, in Multi-threaded Routing Toolkit (MRT) format." |
| OpenBGPD | `dump rib Adj-RIB-In table-v2 FILE` | **with `-pre-policy`** | "Dump an alternative RIB by specifying name." and, of `rde rib`: "It is unnecessary to create Adj-RIB-In and Loc-RIB, which are created automatically and used by default." The manual says only indirectly that the Adj-RIB-In is before the filters, in the `as-override` text: "The Adj-RIB-In still holds the unmodified AS path." |
| BIRD 2 | `mrtdump messages` (protocol option; needs the global `mrtdump "FILE"`) | **yes**. Use `mrtdump { states, messages }` so that Established is seen | "For BGP protocol, states logs BGP state changes and messages logs received BGP messages." (chapter 3) |
| BIRD 2 | `protocol mrt { table …; }` | **no**: it dumps a routing table, by default the master table, which holds only routes the import filters accepted. The manual names no way to dump a channel's `import table` (its Adj-RIB-In) | "Specify a routing table (or a set of routing tables described by a wildcard pattern) that are to be dumped by the MRT protocol instance. Default: the master table." and "BIRD BGP by default operates without import tables, in which case received routes are just processed by import filters, accepted ones are stored in the master table, and the rest is forgotten." (chapter 6) |
| GoBGP | `[mrt-dump.config] dump-type = "updates"` | **yes**, but with no state changes, so routecheck always warns "capture starts mid-session", and a session reset inside the capture is not seen | "With the following configuration, gobgpd continuously dumps BGP update messages to `/tmp/updates.dump` file in the BGP4MP format." |
| GoBGP | `dump-type = "table"` | **no**: the global RIB, after policy | "With the following configuration, gobgpd continuously dumps routes in the global rib to `/tmp/table.dump` file in the TABLE_DUMPv2 format every 60 seconds." |
| GoBGP | `dump-type = "table"` with `table-name` (route server) | **no**: a route-server client's RIB, after policy | "With a route server configuration, gobgpd can dump routes in each peer's RIB." |

Some of these facts are not in the manuals:

- **Session establishment.** None of the three manuals says that a message dump
  starts at session establishment. OpenBGPD's rotated files ("Specify an interval
  in seconds to restart periodically with a new file") begin mid-session by
  construction. GoBGP's `rotation-interval` rotates the same way. routecheck
  detects a capture with no transition to Established and says so.
- **GoBGP, received or sent.** GoBGP's manual does not say whether its update
  dump holds received or sent messages, or whether they come before or after
  policy. Its source, read on 2026-10-17 at the same commit, answers both:
  - `pkg/server/mrt.go` subscribes with `WatchUpdate(false, "", "")` and writes
    only `*watchEventUpdate` events, so no state changes are written;
  - `WatchUpdate` in `pkg/server/server.go` (line 5307) sets `o.preUpdate = true`,
    so the events are received updates, before policy.

  See
  <https://github.com/osrg/gobgp/blob/e2cd8b1f900acea0f6bd558f84b75b624a324e0a/pkg/server/mrt.go>
  and
  <https://github.com/osrg/gobgp/blob/e2cd8b1f900acea0f6bd558f84b75b624a324e0a/pkg/server/server.go#L5307>.
- **No local capture.** No real capture from any of these daemons is in the
  fixtures: none could be made here. The session goldens are synthetic.

## Community keywords

Values compare as numbers:

| keyword | value |
|---|---|
| `hi:lo` | `hi<<16 \| lo` |
| `no_export` | 0xFFFFFF01 |
| `no_advertise` | 0xFFFFFF02 |
| `local_as`, `no_export_subconfed` | 0xFFFFFF03 (RFC 1997's NO_EXPORT_SUBCONFED) |
| `internet` | none defined, so a test naming it is undecided |

Both spellings of 0xFFFFFF03 are read, in any case:

- `local_as` is rpsl's dictionary's spelling.
- `no_export_subconfed` is IRRToolSet's. IRRToolSet defines
  `COMMUNITY_NO_EXPORT_SUBCONFED = 0xFFFFFF03u` in `src/normalform/community.hh`
  (<https://github.com/irrtoolset/irrtoolset/blob/c9346dedf112719b03aa1df077f5985b38bf44e9/src/normalform/community.hh#L58-L61>,
  read on 2026-10-17). It has no `local_as` keyword: `src/normalform/community.cc`
  reads `no_advertise`, `no_export` and `no_export_subconfed`, and reads any other
  word as `COMMUNITY_INTERNET` (0).

## Known limitations

- **AS-ANY in an AS-path set.** A policy whose AS-path regexp names a set that
  reaches AS-ANY (an as-set whose `members:` is `AS-ANY`) gives "unevaluable"
  routes: that report's `Unevaluable` holds peval's error, and each of its routes
  is Undecided with the reason `unevaluable`. Other reports of the run are
  decided as usual. This waits for rpsl's peval to handle such a term. routecheck
  gives the set no meaning of its own. Seen in RIPE: `AS1887:AS-Peerings:AS8501`.
- **Load every registry a policy's sets reach.** A set that is missing from the
  registries you load makes its clause reject routes the registry as a whole
  would accept (D4: "missing from the registry"). In the RIPE-only real-data run,
  390,727 of the 391,010 export rejections had a failing clause that named a set
  RIPE does not hold (`.data/realdata-r19.log`). RIPE alone is not enough for most
  transit policies: load the other registries' dumps too, or use `-irrd` with a
  server that mirrors them.
- **Out of scope** (spec §12):
  - ASPA path verification;
  - BMP and RIS Live;
  - transparent route servers and `import-via:`/`export-via:`, `default:`;
  - checking what L sent;
  - applying clause actions;
  - deciding a regexp in a peering.

## Real data

`TestRealData` and the benchmarks are opt-in: see CLAUDE.md, "Commands". Every
figure is in CHANGELOG.md, with the log it comes from.
