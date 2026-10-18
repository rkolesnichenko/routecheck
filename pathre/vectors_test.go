package pathre_test

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"testing"

	"github.com/rkolesnichenko/routecheck/pathre"
	"github.com/rkolesnichenko/rpsl/resolve"
	"github.com/rkolesnichenko/rpsl/types"
)

// vector is one line of testdata/routemodel-vectors.jsonl (see its README).
type vector struct {
	RE      string                 `json:"re"`
	Sets    map[string][]types.ASN `json:"sets"`
	AnySets []string               `json:"any_sets"` // sets that reach AS-ANY
	Path    []types.ASN            `json:"path"`
	Match   *bool                  `json:"match"`
	Err     string                 `json:"err"`
}

// vectorsVersion is the format this reader knows: 2 added "any_sets".
const vectorsVersion = 2

// readHeader reads the vectors file's first line and returns the rpsl commit
// it names. It refuses any format but vectorsVersion: an older file has no
// "any_sets", and a set it leaves out would be read as matching nothing.
func readHeader(line []byte) (commit string, err error) {
	var header struct {
		Version int    `json:"version"`
		Commit  string `json:"rpsl_commit"`
	}
	if err := json.Unmarshal(line, &header); err != nil {
		return "", err
	}
	if header.Version != vectorsVersion {
		return "", fmt.Errorf("format version %d, want %d", header.Version, vectorsVersion)
	}
	if len(header.Commit) != 40 {
		return "", fmt.Errorf("rpsl_commit %q is not a 40-digit commit", header.Commit)
	}
	return header.Commit, nil
}

// TestVectorsHeaderVersion holds readHeader to the format version: a file
// without one, or of version 1, predates "any_sets", and reading it would
// take a set that reaches AS-ANY for a set that matches nothing.
func TestVectorsHeaderVersion(t *testing.T) {
	const commit = "0123456789abcdef0123456789abcdef01234567"
	for _, c := range []struct {
		line string
		ok   bool
	}{
		{`{"rpsl_commit":"` + commit + `"}`, false},
		{`{"rpsl_commit":"` + commit + `","version":1}`, false},
		{`{"rpsl_commit":"` + commit + `","version":3}`, false},
		{`{"rpsl_commit":"0123","version":2}`, false},
		{`{"version":2,"generator":"g","rpsl_commit":"` + commit + `","seed":1}`, true},
	} {
		got, err := readHeader([]byte(c.line))
		switch {
		case c.ok && (err != nil || got != commit):
			t.Errorf("readHeader(%s) = %q, %v; want %q", c.line, got, err, commit)
		case !c.ok && err == nil:
			t.Errorf("readHeader(%s) = %q, nil; want an error", c.line, got)
		}
	}
}

// TestMatchesRoutemodel holds Match to oracle 1, rpsl's routemodel, on every
// vector it wrote: the same answer where routemodel answers, ErrNotSingleAS
// where it refuses a same-AS repetition, and, where its count was too large
// for Go's regexp, an answer that oracle 2 agrees with.
func TestMatchesRoutemodel(t *testing.T) {
	f, err := os.Open("testdata/routemodel-vectors.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	if !sc.Scan() {
		t.Fatal("no header line")
	}
	commit, err := readHeader(sc.Bytes())
	if err != nil {
		t.Fatalf("header %q: %v", sc.Text(), err)
	}
	counts := map[string]int{}
	n, withAny := 0, 0
	for line := 2; sc.Scan(); line++ {
		n++
		var v vector
		if err := json.Unmarshal(sc.Bytes(), &v); err != nil {
			t.Fatalf("line %d: %v", line, err)
		}
		re := parse(t, v.RE)
		sets := map[types.SetName]resolve.ASNSet{}
		for name, members := range v.Sets {
			sets[setName(t, name)] = resolve.NewASNSet(members...)
		}
		for _, name := range v.AnySets {
			sets[setName(t, name)] = resolve.NewAnyASNSet()
		}
		if len(v.AnySets) > 0 {
			withAny++
		}
		got, err := pathre.Match(re, sets, v.Path)
		switch {
		case v.Err == "not-single-as":
			// routemodel refuses only on a non-empty path: on the empty one it
			// never asks whether an operand is one AS. So does Match.
			if len(v.Path) == 0 {
				t.Errorf("line %d: a not-single-as vector on the empty path", line)
			}
			if !errors.Is(err, pathre.ErrNotSingleAS) {
				t.Errorf("line %d: <%s> on %v = %v, %v; routemodel refuses: not a single AS", line, v.RE, v.Path, got, err)
			}
			counts["not-single-as"]++
		case v.Err == "too-complex":
			if err != nil {
				t.Errorf("line %d: <%s> on %v: %v; want an answer", line, v.RE, v.Path, err)
			}
			counts["too-complex, oracle 2 "+agree(t, re, sets, v.Path, pathre.MatchOptions{})]++
		case v.Err != "" || v.Match == nil:
			t.Fatalf("line %d: neither an answer nor a known refusal: %s", line, sc.Text())
		default:
			if err != nil || got != *v.Match {
				t.Errorf("line %d: <%s> on %v = %v, %v; routemodel says %v", line, v.RE, v.Path, got, err, *v.Match)
			}
			counts["match"]++
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	if n < 20000 {
		t.Fatalf("%d vectors, want at least 20,000", n)
	}
	t.Logf("%d vectors (rpsl %s), %d with any_sets: %v", n, commit[:12], withAny, counts)
}
