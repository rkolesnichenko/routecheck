# Engine differential — input snapshot

copied from rpsl v0.29.0 resolve/testdata/snapshot; synthetic

In routecheck, `bgpq4_test.go` (TestPrefixPolicyMatchesBgpq4) serves these
four files to bgpq4 with rpsl's `resolve/irrdq` and `resolve/irrdserver`, and
`../policies.txt` names each set in an import term. The text below is rpsl's,
unchanged: the paths and commands it names are rpsl's.

This directory holds the in-memory IRR snapshot that feeds the bgpq4
differential test in `resolve/`. It is synthetic, not anonymized real data:
every ASN is in the documentation ranges (`AS64500`–`AS64511`,
`AS65000`+) and every prefix is from `192.0.2.0/24` (TEST-NET-1),
`198.51.100.0/24` (TEST-NET-2), `203.0.113.0/24` (TEST-NET-3), or
`2001:db8::/32`. There are no live registry handles.

The snapshot is small on purpose. The point is to be readable: a regression
should be diagnosable by reading the input and the golden output side-by-side,
not by re-running an opaque fixture. It is expanded with the source priority
`TEST,RADB`, by the engine and by bgpq4.

## Files

| File | Contents |
| --- | --- |
| `as-sets.txt` | `as-set` objects: direct and nested membership, a deliberate cycle, `mbrs-by-ref`, a set defined in two sources, a missing nested set. |
| `route-sets.txt` | `route-set` objects: prefix ranges with operators, IPv6 `mp-members`, nested route-sets and as-sets, `mbrs-by-ref`. |
| `routes.txt` | `route` / `route6` objects providing the origin → prefix mapping the engine joins on. |
| `claims.txt` | `aut-num`, `route` and `route6` objects claiming membership: honored, and rejected for a wrong maintainer or another source. |

## Regenerating the golden output

The goldens under `../golden/` are bgpq4's output for this snapshot. After
editing it, regenerate them and review the diff (see `../golden/README.md`):

    go test -run TestGoldensAreBgpq4Output -update ./resolve
