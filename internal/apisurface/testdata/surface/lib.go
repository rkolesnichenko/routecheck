// Package lib is a fixture: every kind of declaration the surface lists.
package lib

import "errors"

// Doc comments never reach the golden.
const (
	KindA Kind = iota
	KindB
	kindHidden
)

const Max = 10

var ErrBad = errors.New("lib: bad")

var Default = Options{Strict: true}

var Hook func(string) error

type Kind uint8

type Options struct {
	Strict bool `json:"strict"`
	hidden int
	Embedded
}

type Embedded struct{ A, b int }

type Shape interface {
	Area() float64
	isShape()
}

type Alias = Options

type Set[T comparable] struct{ m map[T]bool }

func NewSet[T comparable](xs ...T) *Set[T] { return nil }

func (s *Set[T]) Has(x T) bool { return s.m[x] }

func (k Kind) String() string { return "" }

func (k Kind) hidden() {}

func Parse(s string,
	strict bool,
) (Options, error) {
	return Options{}, nil
}

func helper() {}
