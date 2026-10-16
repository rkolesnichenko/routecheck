// Package verdict decides a route against an evaluated policy. It takes its
// own Route type, so it needs no MRT files, and walks the clauses of a peval
// policy, returning Accepted with the clause that matched, Rejected with the
// reason, or Undecided with the reason it cannot tell.
package verdict
