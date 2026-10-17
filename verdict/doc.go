// Package verdict decides a route against an evaluated policy. It takes its
// own Route type, so it needs no MRT files, and walks the clauses of a peval
// policy, returning Accepted with the clause that matched, Rejected with the
// reason, or Undecided with the reason it cannot tell.
//
// Every test is three-valued (spec §6.4). A prefix test is yes when some
// range of the conjunct's Prefixes holds the route's prefix and no range of
// its NotPrefixes does, and is never undecided. An AS-path test is package
// pathre's answer, flipped when negated; it is undecided when the path is
// not a plain AS_SEQUENCE (ReasonPathNotSequence), when the regexp repeats
// one AS over a wider operand (ReasonSameASRun), or when matching needs more
// than pathre's default work budget (ReasonPathTooExpensive). A community
// test is undecided when a value is internet (ReasonCommInternet) or cannot
// be read (ReasonCommValue), or when the route's communities are not known
// (ReasonCommsUnknown); otherwise community(…) holds when every value is
// present and community == {…} when the two sets are equal, compared as
// numbers (hi:lo is hi<<16|lo; no_export is 0xFFFFFF01, no_advertise
// 0xFFFFFF02, local_as and no_export_subconfed 0xFFFFFF03), and is flipped
// when negated.
//
// ReasonPathUnbound marks a regexp pathre cannot match because it still
// names PeerAS or a set template (or is missing). peval always binds PeerAS,
// so it indicates a bug in the caller; it is reported rather than taken as
// a no.
//
// ReasonUnevaluable is never given by Decide: routecheck.Check gives it to
// every route of a report whose policy peval could not evaluate because it
// names AS-ANY or RS-ANY where rpsl cannot expand it (ruling R19).
//
// Compile prepares a policy once for many routes: an index of each
// conjunct's prefix ranges (a path-compressed binary trie per family), the
// community values read, and a memo of path answers by (regexp, path).
package verdict
