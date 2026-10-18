package pathre

import (
	"bufio"
	"encoding/json"
	"os"
	"testing"

	"github.com/rkolesnichenko/routecheck/internal/reoracle"
	"github.com/rkolesnichenko/rpsl/policy"
	"github.com/rkolesnichenko/rpsl/resolve"
	"github.com/rkolesnichenko/rpsl/types"
)

// TestDefaultMaxWorkCovers holds DefaultMaxWork to what it was chosen for:
// no regexp of rpsl's routemodel vectors, of RFC 2622's examples, or of
// 20,000 pairs from internal/reoracle's generator over paths of up to 255
// ASes comes near it. Each must finish in a tenth of the budget.
func TestDefaultMaxWorkCovers(t *testing.T) {
	most := map[string]int{}
	try := func(kind string, re *policy.ASPathRE, sets map[types.SetName]resolve.ASNSet, path []types.ASN) {
		t.Helper()
		_, work, err := match(re, sets, path, MatchOptions{})
		if err == ErrTooExpensive || work > DefaultMaxWork/10 {
			t.Fatalf("%s: <%s> on %d ASes took %d steps (%v); want under %d", kind, re, len(path), work, err, DefaultMaxWork/10)
		}
		most[kind] = max(most[kind], work)
	}

	// RFC 2622 §5.4's examples, over the paths of TestMatch.
	for _, body := range []string{"AS3", "^AS1", "AS2$", "^AS1 AS2 AS3$", "^AS1 .* AS2$", "^[AS1 AS2]{2}$", "^[AS1 AS2]~{2}$"} {
		re, err := policy.ParseASPathRegexp(body)
		if err != nil {
			t.Fatal(err)
		}
		for _, path := range [][]types.ASN{nil, {1, 2}, {1, 2, 3}, {1, 7, 7, 2}, {1, 3, 2}} {
			try("rfc", re, nil, path)
		}
	}

	// Every routemodel vector.
	f, err := os.Open("testdata/routemodel-vectors.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	sc.Scan() // the header
	for sc.Scan() {
		var v struct {
			RE      string                 `json:"re"`
			Sets    map[string][]types.ASN `json:"sets"`
			AnySets []string               `json:"any_sets"`
			Path    []types.ASN            `json:"path"`
		}
		if err := json.Unmarshal(sc.Bytes(), &v); err != nil {
			t.Fatal(err)
		}
		re, err := policy.ParseASPathRegexp(v.RE)
		if err != nil {
			t.Fatal(err)
		}
		sets := map[types.SetName]resolve.ASNSet{}
		for name, members := range v.Sets {
			n, err := types.ParseSetName(name)
			if err != nil {
				t.Fatal(err)
			}
			sets[n] = resolve.NewASNSet(members...)
		}
		for _, name := range v.AnySets {
			n, err := types.ParseSetName(name)
			if err != nil {
				t.Fatal(err)
			}
			sets[n] = resolve.NewAnyASNSet()
		}
		try("routemodel", re, sets, v.Path)
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}

	// The generator, over paths of up to 255 ASes, with counts over 1000
	// and without.
	for _, big := range []bool{false, true} {
		g := reoracle.NewGen(255)
		g.MaxPath, g.BigCounts = 255, big
		kind := "generator"
		if big {
			kind = "generator, big counts"
		}
		for i := 0; i < 20000; i++ {
			body := g.Regexp()
			re, err := policy.ParseASPathRegexp(body)
			if err != nil {
				t.Fatal(err)
			}
			try(kind, re, reoracle.Sets(), g.Path())
		}
	}
	t.Logf("most steps taken, DefaultMaxWork %d: %v", DefaultMaxWork, most)
}
