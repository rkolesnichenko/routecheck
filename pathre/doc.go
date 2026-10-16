// Package pathre matches RFC 2622 AS-path regular expressions, as rpsl parses
// them, against real AS paths.
//
// The reading is RFC 2622 §5.4's: the alphabet is AS numbers; a regexp with
// no anchor matches when it matches some contiguous part of the path; "^"
// and "$" are the path's start and end; "." is any one AS; an AS number that
// AS; an as-set any one AS in the set; "[...]" any one AS one of its items
// matches and "[^...]" any one AS none of them matches; "*", "+", "?",
// "{m}", "{m,n}" and "{m,}" repeat as in POSIX; and "~*", "~+" and "~{m,n}"
// repeat with every repetition the same AS.
//
// The matcher never uses package regexp and never backtracks: for each node
// of the regexp and each start position it computes the set of positions a
// match can end at, once. A repetition count above the path's length costs
// nothing more than one at it, so no count is too large (spec D6).
package pathre
