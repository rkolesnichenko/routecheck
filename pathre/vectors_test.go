package pathre_test

import (
	"bufio"
	"encoding/json"
	"errors"
	"os"
	"testing"

	"github.com/rkolesnichenko/routecheck/pathre"
	"github.com/rkolesnichenko/rpsl/resolve"
	"github.com/rkolesnichenko/rpsl/types"
)

// vector is one line of testdata/routemodel-vectors.jsonl (see its README).
type vector struct {
	RE    string                 `json:"re"`
	Sets  map[string][]types.ASN `json:"sets"`
	Path  []types.ASN            `json:"path"`
	Match *bool                  `json:"match"`
	Err   string                 `json:"err"`
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
	var header struct {
		Commit string `json:"rpsl_commit"`
	}
	if err := json.Unmarshal(sc.Bytes(), &header); err != nil || len(header.Commit) != 40 {
		t.Fatalf("header %q: %v", sc.Text(), err)
	}
	counts := map[string]int{}
	n := 0
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
			counts["too-complex, oracle 2 "+agree(t, re, sets, v.Path)]++
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
	t.Logf("%d vectors (rpsl %s): %v", n, header.Commit[:12], counts)
}
