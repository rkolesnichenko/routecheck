package main

import (
	"slices"
	"testing"
)

// TestConventions: each check reports the declarations that break it, with
// file and line, in declaration order, and nothing for a package that keeps
// the conventions.
func TestConventions(t *testing.T) {
	for _, c := range []struct {
		dir  string
		want []string
	}{
		{"testdata/conventions/good", nil},
		{"testdata/conventions/bad", []string{
			"bad.go:10: C3: ErrAlias is not declared with errors.New",
			"bad.go:12: C3: ErrFormatted is not declared with errors.New",
			"bad.go:16: C2: ParseThing returns bool as its last result; malformed input is an error",
			"bad.go:18: C2: ParseField returns bool as its last result; malformed input is an error",
			"bad.go:26: C1: LoadWith has no Load",
			"bad.go:30: C1: MergeWith's parameters are not Merge's plus one options parameter",
		}},
	} {
		pkgs, err := discover(c.dir)
		if err != nil {
			t.Fatal(err)
		}
		if got := conventions(c.dir, pkgs); !slices.Equal(got, c.want) {
			t.Errorf("%s:\n got %q\nwant %q", c.dir, got, c.want)
		}
	}
}
