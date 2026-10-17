package main

import (
	"strings"
	"testing"
)

// TestRender: the surface lists every exported declaration of a public
// package, one per line, without comments, unexported members or var values,
// with a signature split over lines joined into one.
func TestRender(t *testing.T) {
	pkgs, err := discover("testdata/surface")
	if err != nil {
		t.Fatal(err)
	}
	var dirs []string
	for _, p := range pkgs {
		dirs = append(dirs, p.dir)
	}
	// internal/, cmd/, hidden directories, package main and test files are not public.
	if got := strings.Join(dirs, " "); got != ". sub" {
		t.Fatalf("public packages %q, want %q", got, ". sub")
	}
	const want = `package lib
const KindA Kind = iota
const KindB Kind
const Max = 10
var Default Options
var ErrBad = errors.New(…)
var Hook func(string) error
func NewSet[T comparable](xs ...T) *Set[T]
func Parse(s string, strict bool) (Options, error)
type Alias = Options
type Embedded struct
	A int
type Kind uint8
func (Kind) String() string
type Options struct
	Strict bool ` + "`json:\"strict\"`" + `
	Embedded
type Set[T comparable] struct
func (*Set[T]) Has(x T) bool
type Shape interface
	Area() float64
	isShape()
`
	if got := render(pkgs[0]); got != want {
		t.Errorf("render:\n%s\nwant:\n%s", got, want)
	}
	if got := render(pkgs[1]); got != "package sub\nfunc F() int\n" {
		t.Errorf("render(sub) = %q", got)
	}
	for dir, want := range map[string]string{".": "routecheck.txt", "bgp": "bgp.txt", "bgp/attr": "bgp_attr.txt"} {
		if got := goldenName(dir); got != want {
			t.Errorf("goldenName(%q) = %q, want %q", dir, got, want)
		}
	}
}
