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
           [-verified-sources LIST] [-vrps FILE] [-af ipv4|ipv6|both]
           [-direction import|export|both] [-peer-addr IP] [-at TIME]
           [-pre-policy] [-local-rtr IP] [-peer-rtr IP] [-max-prefixes N]
           [-format text|json] [-routes all|rejected|undecided|none]
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
| `-verified-sources LIST` | The registries whose route objects count as verified, comma-separated (the help text calls the placeholder `names`; here it is `LIST`). The default is `RIPE,APNIC,ARIN,AFRINIC,LACNIC`, the five registries that check that whoever registers an object holds the resources. Names are compared without regard to case. Only the ones present in the policy source are used: those loaded with `-dump`, or those the server serves with `-irrd` (within `-sources` when given). See "Each route also gets" below. |
| `-vrps FILE` | A VRP JSON file in rpki-client or Routinator format. With it, each route gets an RPKI origin-validation state. |
| `-af` | `ipv4`, `ipv6` or `both` (the default): the unicast families checked. Routes of any other family are dropped and counted. |
| `-direction` | `import` (L's policy), `export` (X's policy) or `both` (the default). |
| `-max-prefixes N` | The most prefixes one set's expansion may reach (rpsl's `MaxPrefixes`). The default is rpsl's limit (1,048,576 in rpsl v0.30.0). A report over it is unevaluable (R27); raising N lets it be decided at the memory cost given under "Known limitations". N must be a positive integer. |
| `-peer-addr IP` | Session mode only. Read only the capture's records that have this peer address. |
| `-at TIME` | Session mode only. Report the state at this RFC 3339 time, such as `2026-10-16T12:00:00Z`. Records at that time are included. The default is the end of the capture. |
| `-pre-policy` | Session mode only. States that the RIB dumps in the input are X's Adj-RIB-In before import policy (see D2 below). |
| `-local-rtr IP`, `-peer-rtr IP` | L's and X's router addresses on the session, for peerings that name routers. They are never taken from the capture (see below). |
| `-format` | `text` (the default) or `json`. |
| `-routes` | Text output only. Which routes to list after the summary: `all`, `rejected`, `undecided` or `none` (the default). |

### Loading every registry

A policy's sets can live in any registry, so give `-dump` every registry's file,
in the precedence order you want. A set or object that two registries hold is
taken from the one whose dump comes first. The order the real-data run uses is
RIPE, APNIC, ARIN, AFRINIC, LACNIC, RADB, then RADB's mirrors (altdb, bboi,
bell, canarie, jpirr, nestegg, nttcom, panix, reach, tc):

```
routecheck -peer AS… -local AS… -collector RIB.mrt \
  -dump ripe.db.aut-num.gz -dump ripe.db.as-set.gz … \
  -dump apnic.db.aut-num.gz … -dump arin.db.gz -dump afrinic.db.gz \
  -dump lacnic.db.gz -dump radb.db.gz -dump altdb.db.gz …
```

The files come from `scripts/fetch-data.sh`, whose default run fetches RIPE's
split files, the other 15 registries, the RIBs and the VRPs, and pins them in
`.data/realdata/MANIFEST` (every registry is required: one that still fails
after its retries stops the script before MANIFEST is written, and a rerun
fetches only what is missing; `--registries` adds the 15 to an existing
MANIFEST without touching its pinned lines), or from rpsl's `scripts/fetch-irr-dumps.sh`. rpsl's CLAUDE.md records RADB's and NTT's dumps as
RPKI-filtered, and the other mirrors on RADB's FTP as not, so route-object
answers depend on which dump you load. Only the five regional registries (RIPE,
APNIC, ARIN, AFRINIC, LACNIC) check that whoever registers an object holds the
resources; RADB and the mirrors do not, and a mirror may be stale. That is why
they come after the regional registries in the order above, and why an answer
that rests on an object found only there (a route accepted through it, a route
object it supplies) rests on unchecked data. For route objects the output marks
this: a route object only registries outside `-verified-sources` hold (by
default RADB and its mirrors) reads "yes (unverified only)" (see "Each route also gets"). In the real-data test's load-only mode, loading all 16
registries took 35.871 s and a peak RSS of 3,534 MB, against 7.468 s and
1,130 MB for RIPE alone (`.data/load-all.log`, `.data/load-ripe.log`); these are
not the command's own figures. See "Known limitations" for what
loading every registry did and did not change.

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
- **A capture with no record of the session.** When no record in the capture
  is X's (or none is from `-peer-addr`), the run fails with exit 3: "no record
  of a session with AS X in the capture" (exit 2 without `-local`: the capture
  then names no local AS either, and the message says it holds no record of X). An empty result there would read as
  "X announced nothing". A 2-byte BGP4MP capture shows a 4-byte X as AS23456,
  so it holds no record of X.
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
  clause N"). When the AS-path tests of the conjunct that accepted the route
  name a set reaching AS-ANY (an as-set that reaches `AS-ANY`, directly or
  through nested sets; in a regexp it matches any one AS), the output names
  that set: `accepted by clause 2 (AS-X reaches AS-ANY: any AS)`, or
  `(AS-X, AS-Y reach AS-ANY: any AS)` for several, before any "after undecided"
  part. A negated test counts too. The test let any AS through, so the
  acceptance may say less about the path than it seems to. Only the conjunct
  that accepted is read: with `<AS-ALL$> OR <AS-A$>`, where AS-ALL reaches
  AS-ANY, a route is accepted by the first conjunct and AS-ALL is named even
  when the route also passes the stricter `<AS-A$>`; written
  `<AS-A$> OR <AS-ALL$>`, such a route names no set.
- **rejected**: every clause says no, and no term is undecided. For each clause,
  the output gives the first test that said no. When a referenced set is missing
  from the registry, the output names it ("missing from the registry"). Such a
  route is still rejected (D4), because a router configured from the registry
  rejects it too.
  That note names the missing sets of a failing clause. It does not say a
  missing set caused the rejection. With only RIPE loaded, AS29632's export to
  AS33891 (`to AS33891 announce AS-NETASSIST`) rejected 32 routes of origin
  AS48031 with such a note. Only AFRINIC and RADB hold route objects for them,
  so no expansion of AS-NETASSIST from RIPE's data could have contained them
  (`.data/every-registry-checks.log`).
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
  | `unevaluable` | peval could not evaluate the whole policy, because it names a set reaching AS-ANY or RS-ANY in filter position (`accept AS-X`, `NOT AS-X`), where rpsl cannot expand it (see "Known limitations"), or a set over one of rpsl's expansion limits (MaxPrefixes, MaxVisited, MaxDepth, MaxConjuncts); `-max-prefixes` raises the first. |

- **no policy**: L has no import term toward X in this family (or, for export,
  X has no export term toward the neighbour). Its routes are not decided. This is
  printed as a finding and does not set exit status 1.

Each route also gets:

- an RPKI state (`valid`, `invalid` or `not_found`) when `-vrps` is given;
- whether a route object exists for exactly that (prefix, origin). There are
  three answers: "yes", "yes (unverified only)" and "no". "Yes (unverified
  only)" means the object exists, but only in registries that are not verified
  sources (by default RADB and its mirrors, which do not check that the
  registrant holds the resources): weaker evidence, not wrong. A route object is "yes" when a
  verified source holds it. The verified sources are those of `-verified-sources`
  that are present in the policy source. When none is present the marking is off:
  answers are "yes" or "no" only. Each run writes one note to stderr, once the
  check has succeeded and before the report, naming the verified sources it
  found:

  ```
  routecheck: route objects: verified sources RIPE, ARIN; absent: APNIC, AFRINIC, LACNIC
  routecheck: route objects: none of the verified sources (RIPE, APNIC, ARIN, AFRINIC, LACNIC) is present; answers are not marked
  ```

  The sources are named in the order the dumps' sources first appear with
  `-dump`, and in the order of `-verified-sources` with `-irrd`. With `-irrd`
  each verified source is probed alone, within `-sources` when that is given;
  without `-sources` the probe is not limited to the server's default source
  list, so a "yes" can rest on a verified source the main answer did not
  consult.

  The first form is printed when some verified source is present (`; absent: ...`
  only when some are absent), the second when none is. In the text, each report
  line ends with `; route objects 2 yes (1 unverified only), 1 no` (with the
  marking off, `; route objects 2 yes, 1 no`; omitted when no route has an
  answer), and a route listed by `-routes` reads `route object yes (unverified
  only)`.

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
- an aut-num or inet-rtr the registry refuses (its key does not parse);
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
   - the sets missing from the registry ("missing from the registry: ...");
   - when some accepted routes passed a test through a set reaching AS-ANY, one
     line naming those sets and, in parentheses, the number of those routes
     (each route counted once, however many of the sets it names), whatever
     `-routes` asks for:
     `accepted through a set reaching AS-ANY (any AS): AS1887:AS-PEERINGS:AS8501 (2 routes)`;
   - the Rejected routes, grouped by their first failing test, with up to 5
     examples per group;
   - the Undecided routes, grouped by reason;
   - the routes `-routes` asks for.

The README shows a session example and a collector example.
Coverage warnings include:

- `-local` is not the capture's local AS (the AS given is the one checked; the
  warning is also written to stderr, so JSON runs get it, and the exit status
  is unchanged);
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
- a route's `RouteObjVerified` is `null` when `RouteObj` is `null` or the
  marking is off, `false` when `RouteObj` is `false`, and otherwise whether a
  verified source holds the route object (`RouteObj` true with
  `RouteObjVerified` false is "yes (unverified only)"); a report's
  `RouteObjYes`, `RouteObjUnverifiedOnly` and `RouteObjNo` count its routes by
  that answer (`RouteObjUnverifiedOnly` is part of `RouteObjYes`; a route with
  no answer is in none);
- `Unevaluable` holds peval's error text for an unevaluable report, and is `""`
  otherwise;
- `Verdict.AnySets` is, on an accepted route, the names (canonical spelling,
  sorted) of the sets reaching AS-ANY that the accepting conjunct's AS-path
  tests name, such as `["AS1887:AS-PEERINGS:AS8501"]`, and `null` when there are
  none; it is always `null` on a rejected or undecided route.

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
| 2 | A bad command line, including options the library refuses (`routecheck.ErrOptions`, such as a session mode run with no `-local` whose capture names no local AS; when the capture holds no record of the session at all, the message says so). |
| 3 | The run could not complete. Causes: an unreadable file; a capture cut mid-record ("truncated record"), such as a file the daemon is still writing; in session mode, a capture with no record of a session with X (at `-peer-addr`, when given), which is not "X announced nothing" (ruling R23; a 2-byte BGP4MP capture shows a 4-byte X as AS23456, so it holds no record of X); a missing aut-num; peval failing (a Source error; but not AS-ANY or RS-ANY in filter position, nor a set over an expansion limit, which make that report "unevaluable"); an unreachable server (with `-irrd`, also one unreachable while the verified sources are probed, which happens before the library validates the options (`routecheck.ErrOptions`), so it is exit 3 even when the capture would otherwise give a usage error, exit 2); a RIB dump in session mode without `-pre-policy`; a broken `-policy` draft; or an interrupted run. |

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

- **The `-irrd` probe of a verified source.** The probe counts a source as
  absent only when the server refuses it with an error (`F`, IRRd 4's answer).
  A server that answers an unknown source list with `D` makes the probe fail,
  and the run exits 3. Naming only sources the server serves in
  `-verified-sources` avoids it.
- **AS-ANY in filter position.** A policy that accepts or announces a set
  reaching AS-ANY or RS-ANY (`accept AS-X`, `NOT AS-X`, where AS-X reaches
  `AS-ANY` directly or through nested sets) gives "unevaluable" routes: AS-ANY
  denotes the whole IRR, which rpsl does not expand. That report's
  `Unevaluable` holds peval's error, and each of its routes is Undecided with
  the reason `unevaluable`. Other reports of the run are decided as usual.
  routecheck gives the set no meaning of its own. The same set inside an
  AS-path regexp is not a limitation: it matches any one AS, and an accepted
  route names it (see Verdicts). RIPE's
  `AS1887:AS-Peerings:AS8501` is such a set, named in AS8308's
  `import: from AS1887 ... accept <AS1887:AS-Peerings:AS8501$>`. On the data of
  2026-10-18 that clause accepted 2 of the 39 ipv4 routes seen from AS1887; the
  other 37 were accepted by the clause before it (`.data/realdata-v0.2.log`,
  `.data/handcheck-AS8308-v0.2.log`). A set over one of rpsl's expansion
  limits (MaxPrefixes, MaxVisited, MaxDepth, MaxConjuncts) is reported unevaluable,
  the same way as a set reaching AS-ANY in filter position, and the run goes on (see the next bullets).
- **Load every registry a policy's sets reach, and some sets are in none.** A
  set that is missing from the registries you load makes its clause reject
  routes the registry as a whole would accept (D4: "missing from the
  registry"). 0.2.0 loaded RIPE alone: 389,127 of its 389,413 export
  rejections had a failing clause that named a set RIPE does not hold
  (`.data/realdata-v0.2.log`; 390,727 of 391,010 in 0.1.0,
  `.data/realdata-r19.log`). Loading all 16 registries changed less than that
  suggested. On the 50 pairs both runs could check, export rejections went from
  47,522 to 47,317 (`.data/same-pairs.log`). What remains mostly names sets no
  loaded registry holds: AS-ISPSERVICES, AS-STEFFANN-IPV4, AS-STEFFANN-IPV6 and
  AS-TELFORT, at 46,052 routes each (all one pair's: AS200184 from AS1136), are in none of the 32 dumps
  (`.data/every-registry-checks.log`). None of the sources asked holds them:
  RIPE's history says each was deleted (AS-ISPSERVICES on 2019-07-03,
  AS-STEFFANN-IPV4 and AS-STEFFANN-IPV6 on 2024-02-09, AS-TELFORT on
  2025-04-02), and none of whois.radb.net's 19 sources has them (2026-10-19,
  `.data/missing-sets/lookup/sets.tsv`; see "The rejections against missing
  sets" below). What loading more registries changes
  most is the route-object answer: L's observations with a route-object
  answer went from 528,974 to 1,568,538 of 2,108,128 on the same pairs (the
  denominator is yes + no; 366 more are unknown). RADB and the mirrors, which
  do not check resource holders, hold 1,843,733 of the 4,866,879 objects loaded
  (`.data/load-all.log`). On those 50 pairs, 551,873 of the 1,568,538 "yes"
  answers (35.18%), or 53.09% of the rise, rest on their route objects alone
  (see "How much rests on unverified registries" below).
  The 32 routes the hand check followed rest on AFRINIC's route objects, which
  come first among the registries holding them. The export denominator moved a
  little too: with every registry, 731 more export routes were decided on those
  pairs (2,639,651 to 2,640,382, `.data/same-pairs-v2.log`), and in one pair
  (AS31270 from AS25577) export rejections rose from 30 to 37; 5 of X's 12
  no-policy reports there gained a policy, and the mechanism was not measured.
  Do not read 0.2.0's 389,413
  export rejections falling to 47,522 as the registries' effect: 341,891 of the
  389,413 were in the 10 pairs that could not be checked with every registry
  (389,413 - 47,522), see the next bullet. Now that all 60 pairs are checked with
  every registry, the total is 47,317 export rejections (the same as the 50
  pairs alone, `.data/set-limits-same-pairs.log`). The 10 pairs reject nothing
  on export: their export routes are accepted or undecided, and 549,845 of the
  549,846 undecided are unevaluable (the other one is `peer router not given`,
  `.data/realdata-set-limits.log`). How many of RIPE alone's 341,891 rejections
  in those pairs became accepted and how many undecided was not measured route
  by route.
- **A transit-sized filter can exceed rpsl's `MaxPrefixes`, and that report is unevaluable.**
  With every registry loaded, 10 of the 60 sampled pairs have at least one filter
  whose expansion passes rpsl's default limit of 1,048,576 prefixes (the largest
  reached 1,053,142), where RIPE alone gives none. Such a report is unevaluable:
  its routes are Undecided with the reason `unevaluable`, its `Unevaluable` field
  holds peval's error naming the limit and the set, and the text output prints a
  `policy not evaluable` line. The run goes on and the other reports are decided,
  so there is no need to check the other direction. `-max-prefixes N` lifts the
  limit (below); the default stays rpsl's. On
  the data of 2026-10-18 all 60 pairs are checked at rpsl's default limit: 82 report instances, 81
  distinct reports (AS34984's export to AS9121 appears in pairs 10 and 33): 80
  export, in 9 pairs; 2 import, in 2 pairs (one pair, AS44032 from AS15645, has both, so 9 + 2 - 1 = 10); all `MaxPrefixes`, holding 549,847
  routes (`.data/realdata-set-limits.log`,
  `.data/set-limits-pairs-unevaluable.log`). The command on AS9086 from AS6762
  exits 0 (it exited 3 before, `.data/maxprefixes-cli-both.log`) and prints, for
  `export, AS6762 to AS174:`, the `policy not evaluable` line
  (`.data/set-limits-cli.log`).
  - **`-max-prefixes N` raises the limit, and memory pays for it.** Absent, the
    limit is rpsl's 1,048,576 (the user's decision: the default stays). The cost
    is measured on one pair, AS9086 from AS6762, every registry, the command
    with `-af both` and without `-vrps`. Memory is peak RSS on an Apple M3 Max (darwin/arm64) with 36 GiB of memory (`.data/max-prefixes-machine.log`), under
    the memory guard's 8 GB cap, measured 2026-10-18:

    | `-max-prefixes` | result | peak RSS | time | reports over MaxPrefixes | AS6762's export, both families (75 reports) | log |
    |---|---|---|---|---|---|---|
    | absent (1,048,576) | exit 0 | 5,848 MB | 47 s | 34 | 1,181,044 accepted / 0 rejected / 448,345 undecided | `.data/max-prefixes-cli-default.log` |
    | 2,097,152 | exit 1 (routes rejected) | 6,511 MB | 63 s | 21 | 1,194,673 accepted / 33,968 rejected / 400,748 undecided | `.data/max-prefixes-cli-2097152.log` |
    | 4,194,304 | stopped by the guard (over 8 GB) | 8,411 MB when stopped | 82 s | not known | not known | `.data/max-prefixes-cli-4194304.log` |

    The import line is the same in both completed runs (978,368 accepted, 0
    rejected, 0 undecided). Every unevaluable report was a MaxPrefixes one. The
    absent run reproduces the figures above (its ipv4 part equals
    `.data/set-limits-cli.log`: 44 reports, 21 over, 1,160,277 / 0 / 400,748; its
    ipv6 part is 31 reports, 13 over, 20,767 / 0 / 47,597). At 2,097,152 every
    ipv6 report is decided: the 47,597 routes of the 13 reports that were over
    are now 13,629 accepted and 33,968 rejected (13,629 + 33,968 = 47,597), so
    ipv6 as a whole (31 reports, 68,364 routes) is 34,396 accepted (20,767 +
    13,629), 33,968 rejected and 0 undecided (34,396 + 33,968 = 68,364). The
    reports over the limit: 34 = 21 + 13 (ipv4 + ipv6); reports: 75 = 44 + 31. The 21 ipv4
    reports, all naming `AS-SEABONE`, stay over ("reached 2,097,154"). At 4,194,304
    the memory guard stopped the run (over 8 GB), so that export was not decided
    there either; values between 2,097,152 and 4,194,304 were not tried, nor
    8,388,608 and 16,777,216.
  - **The every-registry run at 2,097,152** (`.data/realdata-max-prefixes.log`,
    `ROUTECHECK_REALDATA_MAX_PREFIXES`): PASS, 60 of 60 pairs checked, 0 set too
    large. Wall time 4m38s (3m45s at the default), peak RSS 6,565 MB (6,482 MB).
    Unevaluable reports: 24 (from 81), in 3 pairs (2, 15, 53); routes in
    them 400,751 (from 549,847). 149,096 routes were decided that were
    unevaluable (549,847 - 400,751): 89,701 accepted (4,491,432 - 4,401,731) and
    59,395 rejected (106,712 - 47,317). Every one of the 59,395 newly rejected
    routes is counted "rejected with a missing set in a failing clause" (106,526 -
    47,131): their filters were decided from what the registries hold, and those
    lack sets the filters name (pair 2's 33,968 are against AS-SEABONE-V6, whose
    expansion has 748 missing sets).
    Read them as rejections against incomplete filters, not as proven policy
    violations. Distinct missing sets left on export rose from 116 to 808. The 50
    pairs that never reached the limit are identical line for line but for each pair's timing header
    (`.data/max-prefixes-same-pairs.log`); the 10 that differ are the 10 over the
    limit at the default.
  - **Not measured:** limits between 2,097,152 and 4,194,304; anything above
    4,194,304, the guard's cap; how large `AS-SEABONE`'s full expansion is (it is
    above 2,097,154); memory on a machine without the 8 GB cap. Whether the newly
    rejected routes would be accepted if the missing sets existed is measured in
    the next bullet.
- **The rejections against missing sets: none was measured as a gap.**
  Measured on 2026-10-19 at `-max-prefixes 2097152`, every registry, on the
  2026-10-18 dumps (design: `docs/superpowers/specs/2026-10-19-missing-sets-design.md`).
  - **Method:** run A (`.data/missing-sets-A.log`) listed every route rejected
    with a missing set in a failing clause: 106,526 export and 3 import. Each
    missing set was looked up live. Then run B was the same test with the sets
    found elsewhere added as one extra dump, last in precedence. This went round
    by round until B named no set not yet looked up: 4 rounds, 809 sets, then
    22, 10, 1 and 0 new names after rounds 1 to 4
    (`.data/missing-sets-rounds.log`).
  - **The 842 sets** (`.data/missing-sets/lookup/sets.tsv`): 407 deleted, 380
    not found, 54 found elsewhere, 1 inconclusive and 0 held but refused.
    - **Deleted:** RIPE's history gives the date; 110 of the 407 were deleted
      in 2026, none after 2026-10-18.
    - **Not found:** "no entries" from all 19 of whois.radb.net's sources and
      from RIPE's history. "Deleted" and "never existed" can be told apart only
      where a registry publishes its history (RIPE); elsewhere a set deleted
      from a registry with no published history reads "not found".
    - **Found elsewhere:** 51 are in a source routecheck does not load (copies:
      LEVEL3 33, IDNIC 17, RIPE-NONAUTH 1), and 3 in a loaded registry but not
      in its dump (copies: RIPE 2, ARIN 1). The copies are dated 2014-03-20 to
      2026-10-18, so none is dated after 2026-10-18 (the design's rule is by
      day), and none is undated.
      - The two RIPE copies, AS204464:AS-JUSTINFRANKE and
        AS204464:AS-DOWNSTREAMS, were created on 2026-10-18 at 03:23:29Z and
        03:24:49Z (`.data/missing-sets/lookup/extra.db.gz`), after RIPE's
        snapshot: its newest `last-modified:` is 2026-10-17T21:04:19Z
        (`.data/realdata/ripe.db.as-set.gz`). 59,397 listed routes name
        AS204464:AS-JUSTINFRANKE (`.data/missing-sets/A/rejected-missing.tsv`),
        and run B still rejected them with both sets loaded.
      - The ARIN copy, AS-RACKIFI (whois.radb.net's ARIN source, dated
        2025-11-19), is likely a stale mirror copy, though not proven: ARIN's
        own dump has no AS-RACKIFI, and has AS-RACK with the same `mnt-by:` and
        `last-modified:` (`.data/realdata/arin.db.gz`).
    - **Queries:** 1,641 of the 5,000 cap, to whois.radb.net and
      whois.ripe.net, one at a time (`.data/missing-sets/lookup/queries.log`).
      None failed in transport (the error column is empty on all 1,641
      lines), and no service was stopped. AS-CONCERTAP's RIPE history answer
      stayed inconclusive each of the 12 times it was asked, over 6 lookup
      runs: the round-1 lookup ran three times, because the memory guard
      refused run B twice for lack of free memory
      (`.data/missing-sets-rounds-try1.log`,
      `.data/missing-sets-rounds-try2.log`).
  - **Run B changed no verdict** (`.data/missing-sets-round4-B.log`, peak RSS
    7,480 MB; run A 6,991 MB).
    - It loaded the 54 objects. 59,403 of the listed routes had a found set in
      a failing clause, and each of their lists of missing sets got shorter
      (`.data/missing-sets/A/rejected-missing.tsv` against
      `.data/missing-sets/B4/tracked.tsv`).
    - Every route count in B's TOTALS equals A's: 106,712 export rejections,
      and the same 24 unevaluable reports holding the same routes. Distinct
      missing sets left on export fell from 808 to 787: 406 deleted, 380 not
      found and AS-CONCERTAP (`.data/missing-sets/B4/missing-sets.tsv`, with
      the classes from `sets.tsv`). Only the "reached"
      figures of those 24 moved: AS-SEABONE's 2,097,154 became 2,097,153,
      AS-UAIX's 2,100,534 became 2,100,684, and AS-DECIX's 2,097,192 became
      2,097,225.
  - **The listed routes** (`.data/missing-sets-classify.log`):

    | class | all 106,529 | the 59,395 0.4.0 newly decided |
    |---|---|---|
    | gap (accepted with the found sets) | 0 | 0 |
    | real (rejected, no missing set left) | 0 | 0 |
    | real for any IRR filter | 72,561 | 25,427 |
    | unknown | 33,968 | 33,968 |

    - The sums are 72,561 + 33,968 = 106,529 and 25,427 + 33,968 = 59,395.
    - Every unknown route is in pair 2's ipv6 export (AS6762 toward its
      neighbours, against AS-SEABONE-V6), for one reason: AS-CONCERTAP is
      inconclusive.
    - RIPE's history for AS-CONCERTAP is an empty table with no deletion line
      (`.data/missing-sets/lookup/cache/ripe/as-concertap.bad.txt`), so it is
      not "deleted". RIPE holds no object of that name: one query by
      hand to whois.ripe.net, `-r -B -T as-set AS-CONCERTAP`, outside
      `queries.log`, answered in `.data/missing-sets/concertap-ripe-obj.txt`
      (the time, 2026-10-19T10:22:37Z, is that file's mtime). Neither does any
      of whois.radb.net's 19 sources.
  - **What this means:** on these 60 pairs, no rejection against a missing set
    was measured as a gap: none was accepted with the found sets loaded, and
    33,968 stay unknown on one inconclusive set. Of the 842 sets the filters
    named, 54 were found and loaded; the sets still missing in run B are ones
    none of the sources asked holds. Over both directions, 787 of the 842 are
    deleted or not found (407 + 380, the import set FLTR-BOGONS-V6 among the
    deleted; a different 787 from run B's export count above, which holds
    AS-CONCERTAP instead), and 407 of those 787 (51.7%) were deleted. A filter
    built from the IRR
    (bgpq4, rpslq) rejects the same routes. Whether the policy's author meant
    to accept them cannot be read from the data.
  - **Not measured:**
    - route objects that live only in IDNIC, RIPE-NONAUTH or LEVEL3 (one could
      cover a route counted "real for any IRR filter");
    - any sample other than these 60 pairs.
- **How much rests on unverified registries.** Measured on 2026-10-19 at
  `-max-prefixes 2097152`, on the 2026-10-18 dumps (design:
  `docs/superpowers/specs/2026-10-19-registry-provenance-design.md`).
  - **Unverified means:** RADB and its ten mirrors (ALTDB, BBOI, BELL, CANARIE,
    JPIRR, NESTEGG, NTTCOM, PANIX, REACH, TC), as against the five RIRs. This
    grouping is an assumption: JPIRR, for one, is grouped with RADB without
    checking how it verifies. Unverified means not checked, not wrong.
  - **Method:** three runs of the real-data test on the same 60 pairs, compared
    route by route:
    - run A, every registry (`.data/provenance-A.log`);
    - run R, every registry but route objects only from the RIRs; it dropped
      1,785,072 route objects, 23,655 of them `member-of:` claimants
      (`.data/provenance-R1.log`);
    - run V, the RIRs alone (`.data/provenance-V1.log`).
  - **Pair 2 (AS9086 from AS6762, 2,607,757 routes in A).** It went over the
    8 GB cap in R and in V when first measured (stopped at 8,255 and 8,249 MB,
    `.data/provenance-R2.log`, `-V2.log`), so the figures were first published
    without it ("without pair 2" below).
    - Since the streaming change (CHANGELOG 0.6.0), pair 2 alone completes in R
      and V: 5,337 and 4,526 MB (`.data/stream-R2.log`, `-V2.log`). The cause,
      measured by the memory profile, was 21 AS-SEABONE reports that are over
      the limit in A and fit under it in R and V, each kept until the check
      ended; the test also held its rejected lines (the memory-profile
      addendum).
    - **The comparisons with pair 2** read R as two shards, R1 (every pair
      but 2, made at 2d5e24a) and pair 2 alone (made at ae7d034, v0.6.0's code
      commit), and V likewise (`.data/provenance-AR2.log`, `-AV2.log`).
      - Mixing the two versions is sound because v0.6.0's results are
        identical to before: its 60-pair run A's TOTALS and output files are
        byte-identical to `.data/provenance/A`'s. That run never takes the
        RIR-only route-object path that R uses, so it does not cover it.
      - Pair 2's route-object "yes → no" in R (253,107 import, 394,877 export)
        equals the v0.5.0 marking's "yes (unverified only)" for the same pair.
        This is the independent cross-check of the RIR-only path: a different
        code path gives the same numbers.
      - Run first without pair 2, the extended comparer reproduces the
        published logs exactly, apart from timing, peak memory and source line
        numbers (`.data/provenance-AR-control.log`, `-AV-control.log`).
  - **Route-object answers**, with pair 2 (`.data/provenance-AR2.log`):
    - Over the routes answered in both runs, 2,308,425 of the 6,400,790 "yes"
      answers (36.06%) rest on the unverified route objects alone. That is
      1,017,229 of 2,820,473 on import (36.07%) and 1,291,196 of 3,580,317 on
      export (36.06%).
    - Pair 2's own part is 647,984 of its 1,851,021 "yes" answers (35.01%).
    - No answer goes from "no" to "yes", as dropping objects cannot add one.
    - The RPKI state of the 2,308,425: 1,448,598 valid (62.75%), 859,770 not
      found, 57 invalid.
    - Without pair 2 (as first published, `.data/provenance-AR.log`):
      1,660,441 of 4,549,769 (36.50%); 764,122 of 2,102,844 on import (36.34%)
      and 896,319 of 2,446,925 on export (36.63%); 1,055,319 valid (63.56%),
      605,079 not found, 43 invalid.
    - On the 50 pairs of the earlier caveat, which leave pair 2 out: 551,873 of
      1,568,538 "yes" answers (35.18%), which is 53.09% of the rise from
      528,974. Run A reproduces the 1,568,538 exactly, in every comparison.
  - **Verdicts**, with pair 2:
    - Without the unverified route objects (A against R): 8,883 export routes go
      from accepted to rejected (5,552 valid, 3,317 not found, 14 invalid; 0.18%
      of the 4,999,119 export routes). Nothing goes from rejected to accepted.
    - Without anything unverified (A against V, `.data/provenance-AV2.log`):
      10,604 (7,260 valid, 3,330 not found, 14 invalid; 0.21% of 4,998,680).
      Another 439 (432 accepted, 7 rejected) have no verdict, because their
      report loses its policy.
    - Pair 2 adds 3,693 of the 8,883 (R) and 5,205 of the 10,604 (V).
    - **Pair 2's 400,748 export routes that are undecided in A.** In A they are
      unevaluable: AS-SEABONE reaches 2,097,154 prefixes, over the limit.
      Without the unverified route objects, AS-SEABONE fits, and they are
      decided: 186,276 accepted and 214,472 rejected in R; 176,449 and 224,299
      in V. (The "unevaluable → accepted" cells of the pair-2 comparison are
      186,277 and 176,450; each holds 1 limit-effect route from another pair,
      which `.data/provenance-AR.log` and `-AV.log` show as
      "unevaluable → accepted 1" without pair 2: 186,277 − 1 = 186,276 and
      176,450 − 1 = 176,449.)
      - So the limit is reached because of the unverified route objects. This
        is a data effect that shows up through the limit, not only a limit
        effect.
      - Every pair-2 rejection in R and V fails against missing sets (252,133
        in R and 263,472 in V, naming 1,276 and 1,039 distinct sets;
        `.data/stream-R2.log`, `-V2.log`). The missing-sets lookup
        overlaps these (`.data/stream/R2/missing-sets.tsv` and `V2/` against
        the 842 looked up in `.data/missing-sets/lookup/sets.tsv`): 807 of R's
        1,276 sets and 568 of V's 1,039 were among the 842 looked up; 469 and
        471 were not. (Run A named 809 of the 842; the other 33 came from
        later lookup rounds.) The lookup for R's rejections (below) has since
        covered R's 469, and with them 109 of V's 471; V's other 362 were never
        looked up, and every one of them is a set in the non-RIR dumps V does
        not load (`.data/pair2-wording-counts.txt`).
        - In R, each of 739 sets is named by all 252,133 pair-2 rejections.
          All 739 were looked up: 367 deleted, 347 not found, 24 found
          elsewhere and 1 inconclusive, AS-CONCERTAP, the set that left A's
          33,968 rejections unknown.
        - In V, each of 712 sets is named by all 263,472 rejections; 476 of
          them were looked up: 315 deleted, 153 not found, 7 found elsewhere
          and 1 inconclusive (AS-CONCERTAP).
          - **Against R** (2026-10-20, design
            `docs/superpowers/specs/2026-10-20-pair2-v-rejections-design.md`).
            V's 263,472 rejections, joined route by route with R and A
            (`TestPair2VAgainstR`, `.data/pair2-v-join.log`; the table is
            `.data/pair2-v-cross.txt`, the keys `.data/pair2-v-rescued.tsv`):
            R accepts 11,339 of them and rejects 252,133.
          - **What R adds to V.** The RIRs come first in the registry order,
            and both runs load the same route objects, the RIRs'. So R is V
            plus the objects only the non-RIR registries hold, other than
            route objects:
            - their sets, which is most of it;
            - their aut-nums, with their `member-of:` claims;
            - their maintainers;
            - registry-scoped references such as `RADB::AS-X`, which resolve
              in R and are missing in V.
            - AS6762's aut-num, whose export clauses decide these routes, is
              RIPE's in both runs: no other dump holds one
              (`.data/pair2-v-autnum.log`).
          - **Rescued:** a route rejected in V and accepted in R is rescued by
            the non-RIR registries' objects, as a whole. Which set rescues
            which route is not measured. These are not gaps: V leaves those
            registries out by design, and for a filter built from the RIRs
            alone these rejections are what it decides.
          - **By family, A's outcome and route-object answer**
            (`.data/pair2-v-cross.txt`). The route-object answer is the same
            in V and R (a control), so it has no "yes → no" here:

            | family | A's outcome | route-object answer | rescued | rejected in R |
            |---|---|---|---|---|
            | ipv4 | undecided | yes | 9,642 | 6,413 |
            | ipv4 | undecided | no | 184 | 208,022 |
            | ipv4 | undecided | unknown | 1 | 37 |
            | ipv6 | accepted | yes | 1,506 | 10 |
            | ipv6 | accepted | no | 6 | 3,683 |
            | ipv6 | rejected | yes | 0 | 1,657 |
            | ipv6 | rejected | no | 0 | 32,311 |
            | sum | | | 11,339 | 252,133 |

            - Rescued: 9,827 ipv4 routes, all undecided in A
              (224,299 − 214,472), and 1,512 ipv6 routes, all accepted in A.
              The 1,512 are the difference between pair 2's 5,205 (V) and
              3,693 (R) moves from accepted to rejected, above. None of the
              33,968 rejected in A is rescued.
            - Of the rescued, 11,148 are "yes" (9,642 + 1,506), 190 "no"
              (184 + 6) and 1 "unknown". The 190 have no route object for
              exactly their prefix and origin in either run: what rescues
              them is in the export filter's sets, not in their own answer.
            - The rejected cells are those of R's A → R table (below) with
              its "yes → no" and "no → no" added, since neither V nor R holds
              the dropped route objects: 208,022 = 82,415 + 125,607,
              3,683 = 3,471 + 212 and 32,311 = 2,589 + 29,722; 6,413, 10,
              1,657 and 37 are the same.
          - **The 252,133 still rejected** are exactly R's rejections, since
            no route is accepted in V and rejected in R. Run B still rejects
            all of them, so they carry R's classes (Classified, below): no
            gap; all unknown on AS-CONCERTAP; taken as not found, all real
            for an RIR-objects filter. The missing-sets method was not run
            over V: every V rejection names AS-CONCERTAP
            (`.data/stream/V2/missing-sets.tsv`, row
            `export AS-CONCERTAP 263472`), so it would give all "unknown".
          - **Controls**, all held (`.data/pair2-v-join.log`; peak RSS
            1,053 MB): both runs list the same keys; each key has the same
            route-object answer in V and R; import is 978,368 accepted in
            both; no route is accepted in V and rejected in R; and the
            margins: 9,827 and 1,512 rescued, the 33,968 rejected in A
            rejected in both runs, 263,472 rejections in V and 252,133 in R.
          - **Hand-checked** (`.data/pair2-v-handcheck.txt`):
            2001:1398:2::/48 from AS27678, exported toward AS1299
            (`mp-export: afi ipv6.unicast to AS1299 announce AS-SEABONE-V6`).
            AS-SEABONE-V6 (RIPE) names AS-HIGHWINDS, which only ALTDB holds,
            and two more ALTDB sets reach AS27678, whose route6 object is
            LACNIC's. V lists AS-HIGHWINDS among the route's 720 missing
            sets; it is one of V's 362 sets never looked up.
      - **Classified** (2026-10-19, design
        `docs/superpowers/specs/2026-10-19-pair2-rejections-design.md`), with
        the missing-sets method, over R's 252,133 rejections.
        - The control first. Pair 2 in R with nothing extra loaded reproduces
          R2: its four output files are byte-identical and all 252,133 tracked
          routes are rejected (`.data/pair2-rejections-control.log`).
        - **The lookup** looked up the 469 sets never looked up
          (`.data/pair2-rejections-round1-lookup.log`): 75 deleted, 392 not
          found and 2 found elsewhere (AS-AKMLINK-ISP and AS45723:AS-OMADATA,
          both in IDNIC, which routecheck does not load).
          - It sent 938 queries, 469 to whois.radb.net and 469 to
            whois.ripe.net, one at a time, with no transport error. That makes
            2,579 of the cap of 5,000 over both measurements
            (`.data/pair2-rejections/lookup/queries.log`).
          - AS-CONCERTAP was asked again (twice, RIPE's history) and stayed
            inconclusive.
          - The 1,311 sets now classed are 482 deleted, 772 not found, 56 found
            elsewhere and 1 inconclusive.
        - **Run B** (pair 2 in R, with the 56 found copies loaded) still
          rejects all 252,133. It needed one round: it named no set not yet
          looked up (`.data/pair2-rejections-rounds.log`,
          `.data/pair2-rejections-round1-B.log`; peak RSS 5,625 MB). Missing
          sets left fell from 1,276 to 1,253: 26 found sets are no longer
          missing, and 3 sets nested in loaded copies are newly missing
          (AS-GOLIGHTSPEED, AS150470:AS-ID and AS151544:AS-PANDAWANETWORK, all
          not found).
        - **Classes** (`.data/pair2-rejections-classify.log`; in R they mean
          "for a filter built from RIR route objects only"):
          - no gap: no rejection is accepted with the found sets loaded;
          - all 252,133 are unknown, for one reason: every one names
            AS-CONCERTAP, which is inconclusive;
          - taking AS-CONCERTAP as not found (a labelled sensitivity, from the
            hand check above in "The rejections against missing sets"), all
            252,133 are "real for an RIR-objects filter": every set they still
            miss is deleted or not found.
          - The second control holds: the 33,968 rejected in A too are all
            "unknown, inconclusive set", as in the missing-sets measurement.
        - **By A's outcome, family and route-object answer**, A → R
          (`.data/pair2-rejections-cross.txt`, from `.data/provenance/A/routes.tsv.gz`
          and `.data/stream/R2/routes.tsv.gz`):

          | A's outcome (family) | yes → no | no → no | yes → yes | unknown | sum |
          |---|---|---|---|---|---|
          | undecided (ipv4) | 82,415 | 125,607 | 6,413 | 37 | 214,472 |
          | accepted (ipv6) | 3,471 | 212 | 10 | 0 | 3,693 |
          | rejected (ipv6) | 2,589 | 29,722 | 1,657 | 0 | 33,968 |
          | sum | 88,475 | 155,541 | 8,080 | 37 | 252,133 |

          - "yes → no": the route has a route object for exactly this prefix
            and origin only in the registries R drops. Only its route-object
            answer rests on them.
          - "no → no": the route has no route object for exactly this prefix
            and origin in either run. Its own answer did not change, but the
            route can still have been inside AS-SEABONE's filter in A through
            another origin's route object, which A could not show (unevaluable).
          - "yes → yes": a route object in the RIRs too; rejected anyway.
    - The only other moves are limit effects: 3 routes unevaluable at 2,097,152
      in A (2 import, 1 export) are accepted once their sets shrink. Apart from
      those 2, no import verdict moves.
    - Without pair 2 (as first published): 5,190 (A against R; 2,888 valid,
      2,288 not found, 14 invalid; 0.15% of 3,369,730) and 5,399 (A against V).
  - **Hand-checked:** 44.31.178.0/24 from AS211776 and 81.208.192.0/19 from
    AS14544 are route objects only in `radb.db.gz`. Their route-object answer
    is "yes" in A and "no" in R, and AS44306's export of each to AS3491 is
    accepted in A and rejected in R.
  - **What this means:**
    - On this sample, about a third of routecheck's "yes" route-object answers
      rest on registries that do not check resource holders (36.06% with pair
      2, 36.50% without). Most of those routes are RPKI-valid.
    - Few decided verdicts flip: 0.18% of the export routes go from accepted to
      rejected without the unverified route objects.
    - But a large pair can depend on them in a less visible way. Pair 2's
      400,748 export routes are undecided in A only because the unverified
      route objects push AS-SEABONE over the limit. Without them, 214,472 of
      those would be rejected (R), all against sets missing from every registry
      routecheck loads (R loads sets from all 16 registries; only its route
      objects are RIR-only). V, which loads the RIRs alone, rejects 224,299.
      The non-RIR registries' objects other than route objects, mainly sets,
      rescue 9,827 of those: R loads them and accepts the routes
      (`.data/pair2-v-cross.txt`). The other 214,472 are R's.
      - None of R's rejections is a gap: loading the sets found elsewhere
        rescues none.
      - Whether they stand turns on one set, AS-CONCERTAP: inconclusive under
        the method, so all are unknown; taken as not found, all are real for a
        filter built from RIR route objects.
      - The route-object answer cannot tell how much of the 214,472 is a RADB
        effect. It asks whether a route object exists for exactly the route's
        prefix and origin; AS-SEABONE's filter is made of the route objects of
        all its members, by prefix. A and R differ only in the dropped route
        objects and their member-of: claims, so any route accepted in A and
        rejected in R moves because of them, whatever its own answer. Of the
        214,472, 82,415 have a route object for exactly their prefix and origin
        only in the dropped registries ("yes → no") and 125,607 have none in
        either run ("no → no"); those are the routes' own answers only.
        - Pair 2's ipv6 routes, which A decides, show it
          (`.data/pair2-rejections-cross.txt`): 212 "accepted (ipv6)" routes
          with "no → no" and 10 with "yes → yes" went from accepted in A to
          rejected in R, and 2,589 "yes → no" are rejected in A too. Of all of
          pair 2's ipv6 routes accepted in A, those are 212 of the 12,790 with
          "no → no" and 10 of the 15,560 with "yes → yes"
          (`.data/pair2-wording-ipv6-accepted.txt`).
    - These shares are weighted by routes, and the sample is concentrated
      (`.data/provenance-AR2.log`, "concentration"):
      - pair 2 alone holds 1,851,021 of the 6,400,790 "yes" answers (28.92%);
      - three pairs (AS213642 from AS3257, pair 2, AS48354 from AS20485) hold
        5,139,745 of the 6,400,790 "yes" answers (80.30%); without them,
        406,371 of 1,261,045 become "no" (32.22%);
      - over the 59 pairs with a "yes" answered in both runs, the median pair's
        share is 0.00%;
      - 4,910 of the 8,883 moves from accepted to rejected are in one report,
        AS31133's export to AS31500 (pair AS41446 from AS31133); 20 pairs have
        at least one.
    - So the shares describe these 60 pairs, mostly three of them, not a
      typical pair.
  - **Not measured:**
    - whether any unverified object is right;
    - how JPIRR or any other mirror verifies;
    - whether AS-CONCERTAP exists anywhere: RIPE's history answer stays
      inconclusive, so pair 2's R rejections stay unknown under the method;
    - which of the non-RIR objects rescues which of V's rejections: the 11,339
      are rescued by them as a whole, and one route is hand-checked;
    - what A's filter would decide for pair 2's ipv4 routes: AS-SEABONE is over
      the limit in A.
- **The marking on the command run.** The command on AS9086 from AS6762, every
  registry, `-max-prefixes 2097152`, with the marking (2026-10-19,
  `.data/verified-counts-2097152.log`; the stderr note named all five RIRs as
  present):
  - Verdicts equal v0.4.0's: AS9086's import 978,368 accepted, AS6762's export
    1,194,673 accepted / 33,968 rejected / 400,748 undecided over 75 reports.
  - AS9086's import: 717,629 "yes", of them 253,107 "yes (unverified only)"
    (35.27%), and 260,560 "no" (179 routes have no origin to ask about).
  - AS6762's export, over its 55 reports with routes: 1,133,392 "yes", of them
    394,877 unverified only (34.84%), and 495,720 "no".
  - This is pair 2, which the provenance measurement above first left out (it
    now includes it), so these shares and the first-published ones are not of
    the same routes.
  - Peak RSS 6,421 MB; the same command without the counts in the text
    (`.data/verified-cli-2097152.log`) peaked at 6,322 MB, and v0.4.0 at
    6,511 MB (`.data/max-prefixes-cli-2097152.log`). The marking's second view
    of the registries stays within the variation between runs.
  - With `-irrd`, the marking asks at most one extra query per (origin,
    family) whose answer is "yes" (the verified sources are asked only then),
    plus one probe per verified source at startup.
- **Memory since the streaming change** (CHANGELOG, [Unreleased]). `Checker.CheckEach` hands each report over as it is
  built, and the command and the real-data test let it go (design
  `docs/superpowers/specs/2026-10-19-stream-reports-design.md`). Measured
  2026-10-19 under the guard (MB = MiB), with output unchanged:
  - The command on AS9086 from AS6762, every registry, `-max-prefixes 2097152`:
    5,959 MB (`.data/stream-cli-2097152.log`), against 6,421 MB in v0.5.0. Its
    output equals the v0.5.0 run's (`.data/verified-counts-2097152.log`, built at 6309e36 on the branch v0.5.0 was released from; the later code change, 13d47d3, validates `-verified-sources` names and moves the route-object note after the session check, and does not touch this collector run).
  - The real-data test's 60 pairs with `ROUTECHECK_REALDATA_OUT`: 6,635 MB
    (`.data/stream-A.log`), against 7,148 MB. Its TOTALS and every output file
    equal the earlier run's.
  - Pair 2 alone in runs R and V: completes, 5,337 and 4,526 MB.
  - What remains is mostly the Go heap's room between collections. This is inferred: the 60-pair run was not
    profiled, and the explanation rests on pair 2 alone and the command's profile. Pair 2's live heap is measured
    only at report boundaries (marks, after a forced GC): at most 2,212 MB there (4,232 MB before,
    `.data/memprof/A2`). Its in-use heap peaked at 4,359 MB during the first (import) report, 179 s in
    (`.data/memprof2/A2/series.tsv`); the two figures are not one moment.
  - The command's live heap: 2,696 MiB in the highest profile (`peak-009`) and 2,498 MiB in the last
    (`peak-010`), both in `.data/memprof2/cmd`; a peak profile shows the heap at the last completed GC. In
    `peak-010` the registry's load path (`loadPolicy`) holds 1,465 MiB, the route-object lookups (`hygiene`,
    `resolve.Cache`) 554 and the per-neighbour and collector structures 447, of 2,498 (the other 31 are the
    family index and the runtime; `go tool pprof -sample_index=inuse_space -top -nodefraction=0` with
    `-focus`/`-ignore` on those names).
    Its in-use heap, sampled each second, ran between 2,750 and 5,218 MiB from 39 s to 66 s of the 66.6 s run
    (`.data/memprof2/cmd/series.tsv`).
  - The design's targets for the command (5,120 MB) and the 60 pairs
    (6,144 MB) are not met. The command's live heap is now mostly the registry, so a lower GC target or a smaller
    registry in rpsl are the next candidates; neither is measured or built.
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

`ROUTECHECK_REALDATA_MEMPROF=DIR` makes `TestRealData` profile its heap into
DIR: `series.tsv`, a profile at each new high, and a profile of the live heap
(after a forced GC, logged as `MEMPROF: <label> live <MiB> MiB`) at the end of
the load, around each pair and at each fetch of the pair's two aut-nums
(`pair-<i>-autnum-<n>-AS<asn>`: per address family, IPv4 then IPv6, L's import
report first, then X's export report toward each neighbour in ascending ASN
order; each report starts with exactly one marked fetch). The marks run inside
the per-pair timeout and count against `ROUTECHECK_CHECK_TIMEOUT`: raise it
when profiling a large pair. A `MEMPROF: pair-<i> marks <n> in <duration>` line
says what they took.

`ROUTECHECK_MEMPROF_OUT=DIR` and `ROUTECHECK_MEMPROF_ARGS` (the command line, separated by spaces)
make `TestMemProfileCommand` run the command in process under the same sampler: profiles, `stdout.txt`
and `stderr.txt` go to DIR, and the test logs `exit <code>` and `MEMPROF: after-run live <MiB> MiB`.
Exit 0 and 1 pass; 2 and 3 fail the test.
