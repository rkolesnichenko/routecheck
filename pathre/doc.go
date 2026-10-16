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
// The matcher never uses package regexp and never backtracks. It evaluates
// each node of the regexp on a set of start positions at once, giving the
// set of positions a match can end at; the unanchored search is one
// evaluation from every position. A repetition count above the path's
// length, plus one, costs no more than that count, and no count is refused
// for its size (spec D6). Work is bounded instead: MatchWith stops with
// ErrTooExpensive past MatchOptions.MaxWork steps.
package pathre
