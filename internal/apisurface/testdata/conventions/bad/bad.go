package bad

import (
	"errors"
	"fmt"
)

var errInner = errors.New("bad: inner")

var ErrAlias = errInner

var ErrFormatted = fmt.Errorf("bad: formatted")

var ErrOK = errors.New("bad: ok")

func ParseThing(s string) (int, bool) { return 0, false }

func (t Thing) ParseField(s string) (string, bool) { return s, true }

type Thing struct{}

func Expand(s string) []string { return nil }

func ExpandWith(s string, o Options) []string { return nil }

func LoadWith(s string, o Options) error { return nil }

func Merge(a string) int { return 0 }

func MergeWith(a string, b int, o Options) int { return 0 }

type Options struct{}
