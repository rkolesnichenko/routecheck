# Test data

- `irr/snapshot/`, `irr/policies.txt`: the bgpq4 differential's registry
  (see `irr/snapshot/README.md`).
- `irr/golden-policy.txt`: the registry the command's goldens read
  (`internal/cli/golden_test.go`). Hand-written and synthetic: AS64496 (the
  local AS of every golden) and AS64500-AS64511 are documentation ASes
  (RFC 5398); AS4766 and the ASes behind it are real ASes seen in
  `mrt/rv2-rib.20261015.1200.gz`, but the objects naming them (the import
  terms from AS4766, `AS-GOLDEN-BEHIND`, the route objects of 1.18.0.0/16
  and 1.32.0.0/16) were made up for the test and are not those networks'
  registrations.
- `rpki/vrps.json`: three synthetic VRPs over documentation prefixes, in
  rpki-client's JSON format.
- `session/*.mrt`: synthetic BGP4MP captures written by `internal/mrtgen`;
  `TestSessionFixtures` (`internal/cli/golden_test.go`) rebuilds them and
  checks the committed bytes, and `ROUTECHECK_GOLDEN_UPDATE=1` rewrites them.
  `golden.mrt` is AS64500's side of a session with AS64496 that starts
  mid-session (no transition to Established); `nopolicy.mrt` is AS64511's,
  from Established on.
- `golden/`: the command's text and JSON output for each golden
  (`TestGoldens`; `ROUTECHECK_GOLDEN_UPDATE=1` rewrites them).
- `mrt/`: a slice of a real RouteViews RIB, below.

## RouteViews

`mrt/rv2-rib.20261015.1200.gz` is copied unchanged from mrt v0.1.0's
`testdata/mrt/` (github.com/rkolesnichenko/mrt), whose README records:

- route-views2,
  https://archive.routeviews.org/bgpdata/2026.10/RIBS/rib.20261015.1200.bz2,
  first 2000 records, downloaded on 2026-10-16. Source sha256
  c63b33af7646435471e9f646e3514a6b2cdfb71a7a143e14252086a2630f4d07; slice
  sha256 (of the decompressed MRT bytes)
  ba1423bf55b5f05a1fcb4d99312e021b178df9621e1d3b24b9550c2de3e6ec0f, which
  the copy here was checked against.
  TABLE_DUMP_V2: PEER_INDEX_TABLE and 1999 RIB_IPV4_UNICAST records (31782
  entries).

Attribution: this file utilizes data provided by RouteViews
(www.routeviews.org), University of Oregon; use of this data is subject to
the CC BY 4.0 license (https://creativecommons.org/licenses/by/4.0/).
RouteViews' DOI is 10.7264/1y7v-2d90. Changes made: the file is a contiguous
run of whole records from the RouteViews file named above, decompressed from
bzip2 and recompressed with gzip; no record is altered. The goldens derived
from it (`golden/collector.*`) carry the same attribution.
