// Package pathre matches RFC 2622 AS-path regular expressions against real
// AS paths. It runs over the policy AST that rpsl parses, with set references
// resolved through rpsl's resolver, and answers match, no match or undecided
// with a reason; it never guesses.
package pathre
