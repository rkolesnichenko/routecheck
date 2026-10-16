package good

import "errors"

var ErrNotFound = errors.New("good: not found")

// Errors starts with "Err" but is not a sentinel: no capital follows.
var Errors = []string{"not a sentinel"}

func ParseThing(s string) (int, error) { return 0, nil }

// Lookup's bool is comma-ok for a miss, which rule 2 allows outside Parse*.
func Lookup(k string) (int, bool) { return 0, false }

func Read(s string) int { return 0 }

func ReadWith(s string, o Options) int { return 0 }

// With alone is not an XWith: it has no X to pair with.
func (o Options) With(n int) Options { return o }

type Options struct{}
