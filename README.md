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
RIB dumps (RIPE RIS, RouteViews). It builds on
[rpsl](https://github.com/rkolesnichenko/rpsl) and
[mrt](https://github.com/rkolesnichenko/mrt).

Status: pre-release. The design is in `docs/superpowers/specs/`.
