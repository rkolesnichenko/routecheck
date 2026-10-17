// Package routecheck checks the routes a BGP neighbour really announces
// against registered RPSL policy. For one session between a local AS and a
// neighbour it answers which routes the local AS's import policy would
// accept, through which clause, which it would reject and why, and which it
// cannot decide and why; its mirror reports which routes the neighbour's own
// export policy does not permit. Routes come from an MRT capture of the
// session or from public route-collector dumps, and each also gets its RPKI
// origin-validation state and whether a matching route object exists.
package routecheck
