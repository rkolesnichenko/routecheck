package routecheck_test

import (
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// Route classes of the missing-sets measurement.
const (
	classGap     = "gap"
	classReal    = "real"
	classRealAny = "real for any IRR filter"
	classUnknown = "unknown"
)

// unknownReasons is every reason an unknown route can have, in the order the
// first applicable one is chosen.
var unknownReasons = []string{
	"inconclusive set",
	"held-but-refused set",
	"newer set",
	"set not looked up",
	"found set still missing in B",
	"unevaluable in B",
	"undecided in B",
	"no verdict in B",
}

// trackedLine is one line of a tracked.tsv: the route's key, its outcome in
// run B ("accepted", "rejected", "undecided" or "none"), the Undecided reason
// kinds (comma-joined) and the missing sets of run B's failing clauses (empty
// unless B rejected the route against one).
type trackedLine struct {
	Key, Outcome, Detail string
	Sets                 []string
}

// readTracked reads a tracked.tsv; a malformed line is an error naming the
// file and the line number.
func readTracked(path string) ([]trackedLine, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []trackedLine
	for i, line := range strings.Split(strings.TrimSuffix(string(b), "\n"), "\n") {
		if line == "" && len(b) == 0 {
			break
		}
		f := strings.Split(line, "\t")
		if len(f) != 4 || f[0] == "" || !slices.Contains([]string{"accepted", "rejected", "undecided", "none"}, f[1]) {
			return nil, fmt.Errorf("%s:%d: %q is not key, outcome, detail, sets", path, i+1, line)
		}
		var sets []string
		if f[3] != "" {
			sets = strings.Split(f[3], ",")
		}
		out = append(out, trackedLine{f[0], f[1], f[2], sets})
	}
	return out, nil
}

// mergeTracked merges the tracked files of shards or runs, which list the same
// keys in the same order: per key a verdict beats "none", and two different
// verdicts are an error naming the key. A file of another length or another
// key order is an error too.
func mergeTracked(files ...[]trackedLine) ([]trackedLine, error) {
	if len(files) == 0 {
		return nil, nil
	}
	out := slices.Clone(files[0])
	for n, f := range files[1:] {
		if len(f) != len(out) {
			return nil, fmt.Errorf("file %d holds %d keys, file 0 holds %d", n+1, len(f), len(out))
		}
		for i, l := range f {
			o := out[i]
			if l.Key != o.Key {
				return nil, fmt.Errorf("file %d line %d is key %q, file 0 has %q", n+1, i+1, l.Key, o.Key)
			}
			switch {
			case l.Outcome == "none":
			case o.Outcome == "none":
				out[i] = l
			case l.Outcome != o.Outcome || l.Detail != o.Detail || !slices.Equal(l.Sets, o.Sets):
				return nil, fmt.Errorf("key %q has two verdicts: %s %q and %s %q", l.Key, o.Outcome, o.Detail, l.Outcome, l.Detail)
			}
		}
	}
	return out, nil
}

// classifyRoute classes one tracked route by its run B verdict and the lookup
// of the sets run A named. A route is a gap when run B accepts it, real when
// B rejects it and no set (or no set that any IRR filter would find) is to
// blame, and unknown, with the first reason that applies, otherwise.
func classifyRoute(b trackedLine, sets map[string]setLookup) (class, reason string) {
	if b.Outcome == "accepted" {
		return classGap, ""
	}
	if b.Outcome == "rejected" {
		if len(b.Sets) == 0 {
			return classReal, ""
		}
		all := true
		for _, s := range b.Sets {
			if c := sets[setKey(s)].Class; c != "deleted" && c != "not found" {
				all = false
			}
		}
		if all {
			return classRealAny, ""
		}
	}
	var inconclusive, refused, newer, unlooked, stillMissing bool
	for _, s := range b.Sets {
		l, ok := sets[setKey(s)]
		switch {
		case !ok || l.Class == "not looked up":
			unlooked = true
		case l.Class == "inconclusive":
			inconclusive = true
		case l.Class == "held but refused":
			refused = true
		case l.Class == "elsewhere" && !l.InB:
			newer = true
		}
		if ok && l.InB {
			stillMissing = true
		}
	}
	switch {
	case inconclusive:
		reason = unknownReasons[0]
	case refused:
		reason = unknownReasons[1]
	case newer:
		reason = unknownReasons[2]
	case unlooked:
		reason = unknownReasons[3]
	case stillMissing:
		reason = unknownReasons[4]
	case b.Outcome == "undecided" && slices.Contains(strings.Split(b.Detail, ","), "unevaluable"):
		reason = unknownReasons[5]
	case b.Outcome == "undecided":
		reason = unknownReasons[6]
	case b.Outcome == "none":
		reason = unknownReasons[7]
	default:
		reason = "unclassified" // a rejected route with sets always meets one above; TestMissingSetsClassify fails on this
	}
	return classUnknown, reason
}

func TestClassifyRoute(t *testing.T) {
	sets := map[string]setLookup{
		"AS-DEL":  {Set: "AS-DEL", Class: "deleted"},
		"AS-NF":   {Set: "AS-NF", Class: "not found"},
		"AS-INC":  {Set: "AS-INC", Class: "inconclusive"},
		"AS-REF":  {Set: "AS-REF", Class: "held but refused"},
		"AS-NEW":  {Set: "AS-NEW", Class: "elsewhere"},
		"AS-OLD":  {Set: "AS-OLD", Class: "elsewhere", InB: true},
		"AS-SKIP": {Set: "AS-SKIP", Class: "not looked up"},
	}
	line := func(outcome, detail string, names ...string) trackedLine {
		return trackedLine{Key: "k", Outcome: outcome, Detail: detail, Sets: names}
	}
	for _, c := range []struct {
		name          string
		in            trackedLine
		class, reason string
	}{
		{"accepted", line("accepted", "", "AS-NEW"), "gap", ""},
		{"rejected, no sets", line("rejected", ""), "real", ""},
		{"deleted and not found", line("rejected", "", "AS-DEL", "AS-NF"), "real for any IRR filter", ""},
		{"inconclusive", line("rejected", "", "AS-INC"), "unknown", "inconclusive set"},
		{"held but refused", line("rejected", "", "AS-REF"), "unknown", "held-but-refused set"},
		{"newer", line("rejected", "", "AS-NEW"), "unknown", "newer set"},
		{"not looked up (class)", line("rejected", "", "AS-SKIP"), "unknown", "set not looked up"},
		{"not looked up (absent)", line("rejected", "", "as-nowhere"), "unknown", "set not looked up"},
		{"still missing in B", line("rejected", "", "AS-OLD"), "unknown", "found set still missing in B"},
		{"unevaluable", line("undecided", "peval,unevaluable"), "unknown", "unevaluable in B"},
		{"undecided", line("undecided", "peval"), "unknown", "undecided in B"},
		{"none", line("none", ""), "unknown", "no verdict in B"},
		{"case-folded name", line("rejected", "", "as-inc"), "unknown", "inconclusive set"},
		{"two reasons, earlier wins", line("rejected", "", "AS-NEW", "AS-INC", "AS-SKIP"), "unknown", "inconclusive set"},
		{"refused beats newer", line("rejected", "", "AS-NEW", "AS-REF"), "unknown", "held-but-refused set"},
		{"newer beats not looked up", line("rejected", "", "AS-SKIP", "AS-NEW"), "unknown", "newer set"},
		{"not looked up beats still missing", line("rejected", "", "AS-OLD", "AS-SKIP"), "unknown", "set not looked up"},
		{"set beats unevaluable", line("undecided", "unevaluable", "AS-OLD"), "unknown", "found set still missing in B"},
		{"deleted with a newer set", line("rejected", "", "AS-DEL", "AS-NEW"), "unknown", "newer set"},
		{"undecided with deleted set", line("undecided", "unevaluable", "AS-DEL"), "unknown", "unevaluable in B"},
	} {
		class, reason := classifyRoute(c.in, sets)
		if class != c.class || reason != c.reason {
			t.Errorf("%s: got %q, %q; want %q, %q", c.name, class, reason, c.class, c.reason)
		}
	}
}

func TestMergeTracked(t *testing.T) {
	a := []trackedLine{{"k1", "none", "", nil}, {"k2", "rejected", "", []string{"AS-X"}}}
	b := []trackedLine{{"k1", "accepted", "", []string{"AS-Y"}}, {"k2", "none", "", []string{"AS-X"}}}
	got, err := mergeTracked(a, b)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Outcome != "accepted" || got[1].Outcome != "rejected" {
		t.Errorf("merged %+v", got)
	}
	c := []trackedLine{{"k1", "rejected", "", nil}, {"k2", "none", "", nil}}
	if _, err := mergeTracked(b, c); err == nil || !strings.Contains(err.Error(), `"k1"`) {
		t.Errorf("accepted + rejected: err = %v, want one naming k1", err)
	}
	if _, err := mergeTracked(a, b[:1]); err == nil {
		t.Error("files of different lengths merged")
	}
}

func TestReadTracked(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "good.tsv")
	if err := os.WriteFile(good, []byte("k1\trejected\t\tAS-A,AS-B\nk2\tundecided\tpeval,unevaluable\t\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := readTracked(good)
	if err != nil || len(got) != 2 || len(got[0].Sets) != 2 || got[1].Sets != nil || got[1].Detail != "peval,unevaluable" {
		t.Errorf("readTracked = %+v, %v", got, err)
	}
	bad := filepath.Join(dir, "bad.tsv")
	if err := os.WriteFile(bad, []byte("k1\trejected\t\t\nk2\tmaybe\t\t\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readTracked(bad); err == nil || !strings.Contains(err.Error(), "bad.tsv:2") {
		t.Errorf("malformed line: err = %v, want one naming bad.tsv:2", err)
	}
	if _, err := readTracked(filepath.Join(dir, "missing.tsv")); err == nil {
		t.Error("missing file read")
	}
}

// pairID is a pair's id as a route key starts with it: AS<L>-AS<X>.
var pairID = regexp.MustCompile(`^AS[0-9]+-AS[0-9]+$`)

// parseSubset reads ROUTECHECK_MISSINGSETS_SUBSET: pair ids, comma-separated
// (empty items skipped). An id that is not AS<L>-AS<X> is an error naming it:
// it could match no route key. A well-formed id may match no tracked route (a
// checked pair with no rejection against a missing set), so that is logged, not
// an error.
func parseSubset(s string) (map[string]bool, error) {
	out := map[string]bool{}
	for _, p := range strings.Split(s, ",") {
		if p == "" {
			continue
		}
		if !pairID.MatchString(p) {
			return nil, fmt.Errorf("subset pair %q is not AS<L>-AS<X>", p)
		}
		out[p] = true
	}
	return out, nil
}

func TestParseSubset(t *testing.T) {
	got, err := parseSubset("AS197229-AS20771,,AS9086-AS6762")
	if err != nil || len(got) != 2 || !got["AS197229-AS20771"] || !got["AS9086-AS6762"] {
		t.Errorf("parseSubset = %v, %v; want the two pairs", got, err)
	}
	if got, err := parseSubset(""); err != nil || len(got) != 0 {
		t.Errorf("parseSubset(\"\") = %v, %v; want no pairs", got, err)
	}
	for _, bad := range []string{"AS9086-AS6762,AS9086_AS6762", "9086-6762", "AS9086-AS6762|export", " AS1-AS2", "AS1-AS2-AS3"} {
		if _, err := parseSubset(bad); err == nil {
			t.Errorf("parseSubset(%q) took a malformed pair id", bad)
		}
	}
}

// classTable tallies classified routes of one direction.
type classTable struct {
	classes, reasons map[string]int
	total            int
}

// tallyClasses logs the table of one direction (or "both") and fails when a
// sum differs from its total.
func tallyClasses(t *testing.T, title string, tb classTable) {
	t.Helper()
	classSum, reasonSum := 0, 0
	t.Logf("%s: %d routes", title, tb.total)
	for _, c := range []string{classGap, classReal, classRealAny, classUnknown} {
		t.Logf("  %-28s %d", c, tb.classes[c])
		classSum += tb.classes[c]
	}
	t.Logf("  classes sum %d of %d", classSum, tb.total)
	if classSum != tb.total {
		t.Errorf("%s: classes sum to %d, total is %d", title, classSum, tb.total)
	}
	for _, r := range slices.Sorted(maps.Keys(tb.reasons)) {
		t.Logf("    unknown: %-30s %d", r, tb.reasons[r])
		reasonSum += tb.reasons[r]
		if !slices.Contains(unknownReasons, r) {
			t.Errorf("%s: %q is not an unknown reason", title, r)
		}
	}
	t.Logf("  unknown reasons sum %d of %d", reasonSum, tb.classes[classUnknown])
	if reasonSum != tb.classes[classUnknown] {
		t.Errorf("%s: reasons sum to %d, unknown is %d", title, reasonSum, tb.classes[classUnknown])
	}
}

func TestMissingSetsClassify(t *testing.T) {
	dir := os.Getenv("ROUTECHECK_MISSINGSETS_DIR")
	if dir == "" {
		t.Skip("ROUTECHECK_MISSINGSETS_DIR is not set")
	}
	trackedEnv, subsetEnv := os.Getenv("ROUTECHECK_MISSINGSETS_TRACKED"), os.Getenv("ROUTECHECK_MISSINGSETS_SUBSET")
	if trackedEnv == "" {
		t.Fatal("ROUTECHECK_MISSINGSETS_TRACKED is needed")
	}
	sets, err := readSets(filepath.Join(dir, "sets.tsv"))
	if err != nil {
		t.Fatal(err)
	}
	var files [][]trackedLine
	for _, p := range strings.Split(trackedEnv, ",") {
		f, err := readTracked(p)
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, f)
	}
	routes, err := mergeTracked(files...)
	if err != nil {
		t.Fatal(err)
	}
	subset, err := parseSubset(subsetEnv)
	if err != nil {
		t.Fatal(err)
	}
	subsetRoutes := map[string]int{}
	type scope struct {
		title string
		dirs  map[string]*classTable
	}
	scopes := [2]scope{{"all tracked routes", map[string]*classTable{}}, {"subset pairs", map[string]*classTable{}}}
	var out strings.Builder
	for _, r := range routes {
		class, reason := classifyRoute(r, sets)
		if reason == "unclassified" {
			t.Errorf("%q: rejected with sets %v matches no unknown reason", r.Key, r.Sets)
		}
		fmt.Fprintf(&out, "%s\t%s\t%s\n", r.Key, class, reason)
		f := strings.Split(r.Key, "|")
		if len(f) < 2 {
			t.Fatalf("key %q has no direction", r.Key)
		}
		if subset[f[0]] {
			subsetRoutes[f[0]]++
		}
		for i, in := range []bool{true, subset[f[0]]} {
			if !in {
				continue
			}
			for _, d := range []string{f[1], "both"} {
				tb := scopes[i].dirs[d]
				if tb == nil {
					tb = &classTable{classes: map[string]int{}, reasons: map[string]int{}}
					scopes[i].dirs[d] = tb
				}
				tb.total++
				tb.classes[class]++
				if class == classUnknown {
					tb.reasons[reason]++
				}
			}
		}
	}
	for _, p := range slices.Sorted(maps.Keys(subset)) {
		t.Logf("subset pair %s: %d tracked routes", p, subsetRoutes[p])
	}
	for _, s := range scopes {
		for _, d := range slices.Sorted(maps.Keys(s.dirs)) {
			tallyClasses(t, s.title+", "+d, *s.dirs[d])
		}
	}
	if err := writeAtomic(filepath.Join(dir, "routes.tsv"), out.String()); err != nil {
		t.Fatal(err)
	}
}
