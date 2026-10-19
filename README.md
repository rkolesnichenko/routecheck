# routecheck

Checks a BGP session's real routes against the policies registered in the
Internet Routing Registry. For a session between a local AS (L) and a
neighbour (X), it answers:

- Of the routes X really announces, which would L's registered import policy
  accept, through which clause; which would it reject, and why; and which can
  it not decide, and why?
- Of the routes X really announces, which does X's own registered export
  policy not permit?

Routes come from an MRT capture of the session, or from public route-collector
RIB dumps (RIPE RIS, RouteViews). Each route also gets its RPKI
origin-validation state and whether a matching route object exists. The
policies come from IRR dump files or a live IRRd. It builds on
[rpsl](https://github.com/rkolesnichenko/rpsl) (the policy evaluation, set
expansion and RPKI) and [mrt](https://github.com/rkolesnichenko/mrt) (the MRT
reader); what is new here is an AS-path regular-expression matcher that runs
against real paths (`pathre`) and the verdict layer that decides each route
against each clause and says why (`verdict`).

It never guesses: a test it cannot decide (a path with an AS_SET, communities a
collector cannot vouch for, a regexp over its work budget, a term that names a
router the command line did not give) makes the route Undecided, with the
reason.

Status: pre-v1 (0.x). The API may still change between minor versions. The
latest release is v0.6.0; see [CHANGELOG.md](CHANGELOG.md).

## Install

```sh
go get github.com/rkolesnichenko/routecheck                              # the library (Go 1.23+)
go install github.com/rkolesnichenko/routecheck/cmd/routecheck@latest    # the command
```

## A session

From the repository's root, the committed synthetic capture of AS64500's side
of a session with AS64496, against a small registry and three VRPs:

```sh
routecheck -local AS64496 -peer AS64500 -session testdata/session/golden.mrt \
  -dump testdata/irr/golden-policy.txt -vrps testdata/rpki/vrps.json -routes all
```

prints (and exits 1, because routes are Rejected):

```
routecheck: session mode: local AS64496, peer AS64500
routes: testdata/session/golden.mrt
policy: -dump testdata/irr/golden-policy.txt
rpki: -vrps testdata/rpki/vrps.json (3 VRPs)
warning: capture starts mid-session; routes announced earlier are not seen
warning: 1 announcement did not start with AS64500: skipped, each withdrawing the route it replaced

ipv4.unicast
  import, AS64496 from AS64500: 5 routes: 2 accepted, 2 rejected, 1 undecided; route objects 2 yes, 2 no
    clause 1 (import attribute 4): from AS64500 accept AS64500
    clause 2 (import attribute 5): from AS64500 accept <^AS64500 AS64501$>
    rejected, by the first failing test of clause 1:
      prefix not in filter: 2 routes
        203.0.113.0/24  AS64500 AS64502
        203.0.113.128/25  AS64500 AS64502
    undecided, by reason (a route may have several):
      path-not-sequence: 1 route
        10.0.0.0/8  AS64500 (not a plain AS_SEQUENCE)
    routes (all):
      10.0.0.0/8  AS64500 (not a plain AS_SEQUENCE)  undecided: clause 2: path-not-sequence (<^ AS64500 AS64501 $>)  rpki not_found
      192.0.2.0/24  AS64500  accepted by clause 1  rpki valid  route object yes
      198.51.100.0/24  AS64500 AS64501  accepted by clause 2  rpki not_found  route object yes
      203.0.113.0/24  AS64500 AS64502  rejected: clause 1: prefix not in filter; clause 2: <^ AS64500 AS64501 $>  rpki invalid  route object no
      203.0.113.128/25  AS64500 AS64502  rejected: clause 1: prefix not in filter; clause 2: <^ AS64500 AS64501 $>  rpki invalid  route object no
  export, AS64500 to AS64496: 5 routes: 1 accepted, 4 rejected, 0 undecided; route objects 2 yes, 2 no
    clause 1 (export attribute 1): to AS64496 announce AS64500
    rejected, by the first failing test of clause 1:
      prefix not in filter: 4 routes
        10.0.0.0/8  AS64500 (not a plain AS_SEQUENCE)
        198.51.100.0/24  AS64500 AS64501
        203.0.113.0/24  AS64500 AS64502
        203.0.113.128/25  AS64500 AS64502
    routes (all):
      10.0.0.0/8  AS64500 (not a plain AS_SEQUENCE)  rejected: clause 1: prefix not in filter  rpki not_found
      192.0.2.0/24  AS64500  accepted by clause 1  rpki valid  route object yes
      198.51.100.0/24  AS64500 AS64501  rejected: clause 1: prefix not in filter  rpki not_found  route object yes
      203.0.113.0/24  AS64500 AS64502  rejected: clause 1: prefix not in filter  rpki invalid  route object no
      203.0.113.128/25  AS64500 AS64502  rejected: clause 1: prefix not in filter  rpki invalid  route object no

ipv6.unicast
  import, AS64496 from AS64500: 2 routes: 1 accepted, 1 rejected, 0 undecided; route objects 1 yes, 1 no
    clause 1 (import attribute 6): from AS64500 accept AS64500
    rejected, by the first failing test of clause 1:
      prefix not in filter: 1 route
        2001:db8:dead::/48  AS64500 AS64502
    routes (all):
      2001:db8:1::/48  AS64500  accepted by clause 1  rpki valid  route object yes
      2001:db8:dead::/48  AS64500 AS64502  rejected: clause 1: prefix not in filter  rpki invalid  route object no
  export, AS64500 to AS64496: 2 routes: 1 accepted, 1 rejected, 0 undecided; route objects 1 yes, 1 no
    clause 1 (export attribute 2): to AS64496 announce AS64500
    rejected, by the first failing test of clause 1:
      prefix not in filter: 1 route
        2001:db8:dead::/48  AS64500 AS64502
    routes (all):
      2001:db8:1::/48  AS64500  accepted by clause 1  rpki valid  route object yes
      2001:db8:dead::/48  AS64500 AS64502  rejected: clause 1: prefix not in filter  rpki invalid  route object no
```

This is `testdata/golden/session.txt`, which `TestGoldens`
(`internal/cli/golden_test.go`) holds the command to, byte for byte.

## A collector

The same registry, and the committed slice of a route-views2 RIB: every path
through AS4766, cut to the part AS4766 announced. `AS-GOLDEN-BEHIND` and the
import terms from AS4766 are made up for the test (see
[testdata/README.md](testdata/README.md)), not that network's registrations.

```sh
routecheck -local AS64496 -peer AS4766 -collector testdata/mrt/rv2-rib.20261015.1200.gz \
  -dump testdata/irr/golden-policy.txt -direction import -routes all
```

```
routecheck: collector mode: local AS64496, peer AS4766
routes: testdata/mrt/rv2-rib.20261015.1200.gz
policy: -dump testdata/irr/golden-policy.txt
note: collector mode: these are routes AS4766 announced to someone. AS4766 may not
  announce all of them to AS64496 (a peer gets AS4766's customer cone, a customer
  gets everything), and may announce routes to AS64496 that no collector sees.
  A rejected route reads "if AS4766 sends this, AS64496's policy rejects it",
  not "AS4766 sends this to AS64496".
collector: 31782 RIB entries read, 179 through AS4766 (0 on AS4766's own feed to a collector)

ipv4.unicast
  import, AS64496 from AS4766: 19 routes: 19 accepted, 0 rejected, 0 undecided; route objects 5 yes, 14 no
    clause 1 (import attribute 1): from AS4766 accept AS-GOLDEN-BEHIND
    clause 2 (import attribute 2): from AS4766 accept community(4766:100)
    clause 3 (import attribute 3): from AS4766 accept <^AS4766+ .*>
    routes (all):
      1.10.145.0/24  AS4766 AS4651 AS23969  [to AS6939; 5 collector peers]  accepted by clause 3, after undecided clause 2  route object no
      1.18.116.0/24  AS4766 AS131098  [to AS174 AS1299 AS2497 AS2914 AS3356 AS6830 AS6939 AS37100; 17 collector peers]  accepted by clause 3, after undecided clause 2  route object no
      1.18.123.0/24  AS4766 AS9957 AS9286 AS23599  [to AS174 AS1299 AS2497 AS2914 AS3356 AS6830 AS6939 AS37100; 17 collector peers]  accepted by clause 3, after undecided clause 2  route object no
      1.18.126.0/24  AS4766 AS23599  [to AS174 AS1299 AS2497 AS2914 AS3356 AS6830 AS6939 AS37100; 17 collector peers]  accepted by clause 1  route object yes
      1.18.127.0/24  AS4766 AS1237 AS1237 AS23596  [to AS2497 AS6939; 5 collector peers]  accepted by clause 3, after undecided clause 2  route object no
      1.18.130.0/24  AS4766 AS23596  [to AS174 AS1299 AS2497 AS2914 AS3356 AS6830 AS6939 AS37100; 17 collector peers]  accepted by clause 1  route object yes
      1.18.132.0/24  AS4766 AS9858 AS23600  [to AS1299 AS2914 AS3356 AS6939; 10 collector peers]  accepted by clause 1  route object yes
      1.18.134.0/24  AS4766 AS23600  [to AS1299 AS2914 AS3356 AS6830 AS6939 AS37100; 13 collector peers]  accepted by clause 1  route object yes
      1.32.198.0/24  AS4766 AS64050  [to AS6939 AS37100; 6 collector peers]  accepted by clause 3, after undecided clause 2  route object yes
      1.32.201.0/24  AS4766 AS64050 AS64050  [to AS6939; 4 collector peers]  accepted by clause 3, after undecided clause 2  route object no
      1.32.202.0/24  AS4766 AS64050 AS64050  [to AS6939; 4 collector peers]  accepted by clause 3, after undecided clause 2  route object no
      1.32.203.0/24  AS4766 AS64050 AS64050  [to AS6939; 4 collector peers]  accepted by clause 3, after undecided clause 2  route object no
      1.32.204.0/24  AS4766 AS64050 AS64050  [to AS6939; 4 collector peers]  accepted by clause 3, after undecided clause 2  route object no
      1.32.217.0/24  AS4766 AS64050  [to AS1299 AS2497 AS6830 AS6939 AS37100; 12 collector peers]  accepted by clause 3, after undecided clause 2  route object no
      1.32.223.0/24  AS4766 AS64050  [to AS1299 AS2497 AS2914 AS3356 AS6830 AS6939 AS37100; 17 collector peers]  accepted by clause 3, after undecided clause 2  route object no
      1.32.227.0/24  AS4766 AS64050 AS64050  [to AS6939; 4 collector peers]  accepted by clause 3, after undecided clause 2  route object no
      1.32.240.0/24  AS4766 AS64050 AS64050  [to AS6939; 5 collector peers]  accepted by clause 3, after undecided clause 2  route object no
      1.32.241.0/24  AS4766 AS64050  [to AS1299 AS2497 AS6830 AS6939 AS37100; 12 collector peers]  accepted by clause 3, after undecided clause 2  route object no
      1.32.245.0/24  AS4766 AS64050  [to AS6939 AS37100; 6 collector peers]  accepted by clause 3, after undecided clause 2  route object no

ipv6.unicast
  import, AS64496 from AS4766: no policy: AS64496 has no import term toward AS4766 in this family; its routes are not decided
```

This is `testdata/golden/collector.txt`. Clause 2 tests a community, which a
collector cannot vouch for, so it is undecided for every route, and the routes
clause 3 accepts say so ("after undecided clause 2").

## What collector mode means

These are routes X announced to *someone*. X may not announce all of them to
L (a peer gets X's customer cone, a customer gets everything), and may
announce routes to L that no collector sees. A Rejected route in collector
mode reads "if X sends this, L's policy rejects it", not "X sends this to L".
Community tests are always undecided there. Session mode, from a capture of
the real session, is the exact answer; [docs/routecheck.md](docs/routecheck.md)
lists which daemons' MRT dumps qualify.

## More

- [docs/routecheck.md](docs/routecheck.md): every flag, the output, the exit
  status, which captures qualify for `-session`, and the known limitations
  (load every registry a policy's sets reach).
- The library: `routecheck.Checker.Check` over `mrt.Records`; `verdict.Decide`
  and `verdict.Compile` for one policy and one route; `pathre.Match`;
  `observe.Session` and `observe.Collector`; `hygiene`. The exported API is
  listed in [api/](api/).
- The design: `docs/superpowers/specs/2026-10-16-reconcile-design.md`.

## Data and licence

The code is MIT (see [LICENSE](LICENSE)). `testdata/mrt` holds a slice of a
RouteViews archive file, which is CC BY 4.0 (University of Oregon Route Views
Project, https://www.routeviews.org), attributed in
[testdata/README.md](testdata/README.md). RIPE RIS files are not
redistributed; the opt-in real-data run downloads them at test time.
