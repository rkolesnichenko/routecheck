package routecheck_test

import (
	"bufio"
	"compress/gzip"
	"fmt"
	"io"
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

// readTracked reads a tracked.tsv, streaming: a file is ~5 GB for pair 2's
// rejections, so no line outlives its own parse. Lines whose sets field is the
// same share one []string (there are only a few distinct lists), and the other
// fields are copied, so a line's buffer is not retained. A line can exceed
// 21 KB, hence ReadString and not a Scanner. A malformed line is an error
// naming the file and the line number.
func readTracked(path string) ([]trackedLine, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	outcomes := []string{"accepted", "rejected", "undecided", "none"}
	r := bufio.NewReaderSize(f, 1<<20)
	shared := map[string][]string{}
	var out []trackedLine
	for n := 1; ; n++ {
		line, err := r.ReadString('\n')
		if err != nil && err != io.EOF {
			return nil, fmt.Errorf("%s:%d: %w", path, n, err)
		}
		if line == "" && err == io.EOF {
			break
		}
		line = strings.TrimSuffix(line, "\n")
		f := strings.Split(line, "\t")
		i := -1
		if len(f) == 4 {
			i = slices.Index(outcomes, f[1])
		}
		if i < 0 || f[0] == "" {
			return nil, fmt.Errorf("%s:%d: %q is not key, outcome, detail, sets", path, n, line)
		}
		var sets []string
		if f[3] != "" {
			sets = shared[f[3]]
			if sets == nil {
				sets = strings.Split(f[3], ",")
				for j := range sets {
					sets[j] = strings.Clone(sets[j])
				}
				shared[strings.Clone(f[3])] = sets
			}
		}
		out = append(out, trackedLine{strings.Clone(f[0]), outcomes[i], strings.Clone(f[2]), sets})
		if err == io.EOF {
			break
		}
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

func newClassTable() *classTable {
	return &classTable{classes: map[string]int{}, reasons: map[string]int{}}
}

func (tb *classTable) add(c classified) {
	tb.total++
	tb.classes[c.Class]++
	if c.Class == classUnknown {
		tb.reasons[c.Reason]++
	}
}

// The two "real" classes under ROUTECHECK_MISSINGSETS_RIR_ONLY, where run R
// holds the route objects of the five RIRs only: a route with no missing set
// is real only without the unverified route objects, and one whose sets are
// all deleted or not found is real for a filter built from RIR objects.
const (
	classRealRIR    = "real without the unverified route objects"
	classRealAnyRIR = "real for an RIR-objects filter"
)

// displayClass is the name a class is logged and written under.
func displayClass(class string, rirOnly bool) string {
	if rirOnly {
		switch class {
		case classReal:
			return classRealRIR
		case classRealAny:
			return classRealAnyRIR
		}
	}
	return class
}

// classified is a route's class (as displayClass names it) and unknown reason.
type classified struct{ Class, Reason string }

// classifyAll classes every route against sets.
func classifyAll(routes []trackedLine, sets map[string]setLookup, rirOnly bool) []classified {
	out := make([]classified, len(routes))
	for i, r := range routes {
		c, reason := classifyRoute(r, sets)
		out[i] = classified{displayClass(c, rirOnly), reason}
	}
	return out
}

// takeNotFound returns a copy of sets in which the named sets (comma-separated,
// matched as setKey) read "not found", for the sensitivity table. A name that
// is not in sets is added as not found.
func takeNotFound(sets map[string]setLookup, names string) (map[string]setLookup, []string) {
	out := maps.Clone(sets)
	var list []string
	for _, n := range strings.Split(names, ",") {
		if n == "" {
			continue
		}
		list = append(list, n)
		l := out[setKey(n)]
		l.Set, l.Class = n, "not found"
		out[setKey(n)] = l
	}
	return out, list
}

// routeAnswer is what a routes.tsv.gz says of one route: its outcome and its
// route-object answer.
type routeAnswer struct{ Outcome, Obj string }

// readRouteAnswers streams a routes.tsv.gz (key, outcome, route-object, RPKI,
// undecided kinds) and keeps the tracked keys only. A tracked key the file
// lacks is an error naming the key and the file.
func readRouteAnswers(path string, routes []trackedLine) (map[string]routeAnswer, error) {
	want := make(map[string]bool, len(routes))
	for _, r := range routes {
		want[r.Key] = true
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	z, err := gzip.NewReader(f)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	r := bufio.NewReaderSize(z, 1<<20)
	out := make(map[string]routeAnswer, len(routes))
	for n := 1; ; n++ {
		line, err := r.ReadString('\n')
		if err != nil && err != io.EOF {
			return nil, fmt.Errorf("%s:%d: %w", path, n, err)
		}
		if line == "" && err == io.EOF {
			break
		}
		key, _, _ := strings.Cut(line, "\t")
		if want[key] {
			f := strings.Split(strings.TrimSuffix(line, "\n"), "\t")
			if len(f) < 3 {
				return nil, fmt.Errorf("%s:%d: %q is not key, outcome, route object, …", path, n, line)
			}
			out[strings.Clone(key)] = routeAnswer{strings.Clone(f[1]), strings.Clone(f[2])}
		}
		if err == io.EOF {
			break
		}
	}
	for _, r := range routes {
		if _, ok := out[r.Key]; !ok {
			return nil, fmt.Errorf("tracked key %q is not in %s", r.Key, path)
		}
	}
	return out, nil
}

// splitRows tallies the classes by a row label, for all tracked routes.
func splitRows(routes []trackedLine, cls []classified, label func(key string) string) map[string]*classTable {
	rows := map[string]*classTable{}
	for i, r := range routes {
		l := label(r.Key)
		if rows[l] == nil {
			rows[l] = newClassTable()
		}
		rows[l].add(cls[i])
	}
	return rows
}

// classNames are the class names a table lists, in order.
func classNames(rirOnly bool) []string {
	return []string{classGap, displayClass(classReal, rirOnly), displayClass(classRealAny, rirOnly), classUnknown}
}

// tallyClasses logs the table of one direction (or "both") and fails when a
// sum differs from its total.
func tallyClasses(t *testing.T, title string, tb classTable, rirOnly bool) {
	t.Helper()
	classSum, reasonSum := 0, 0
	width := 28 // the R names are longer
	if rirOnly {
		width = 42
	}
	t.Logf("%s: %d routes", title, tb.total)
	for _, c := range classNames(rirOnly) {
		t.Logf("  %-*s %d", width, c, tb.classes[c])
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

// tallySplit logs one split table (a table per row) and checks that its rows
// sum to the number of tracked routes.
func tallySplit(t *testing.T, title string, rows map[string]*classTable, total int, rirOnly bool) {
	t.Helper()
	sum := 0
	t.Logf("%s: %d routes", title, total)
	for _, l := range slices.Sorted(maps.Keys(rows)) {
		tallyClasses(t, title+", "+l, *rows[l], rirOnly)
		sum += rows[l].total
	}
	t.Logf("  rows sum %d of %d", sum, total)
	if sum != total {
		t.Errorf("%s: rows sum to %d, total is %d", title, sum, total)
	}
}

// classifyConfig is what TestMissingSetsClassify reads from the environment.
type classifyConfig struct {
	Dir          string
	Tracked      []string
	Subset       string
	RIROnly      bool
	ARoutes      string // routes.tsv.gz of run A and of run R: both or neither
	RRoutes      string
	TakeNotFound string
}

// runClassify is the classifier: it logs the tables and writes Dir/routes.tsv.
func runClassify(t *testing.T, cfg classifyConfig) {
	t.Helper()
	sets, err := readSets(filepath.Join(cfg.Dir, "sets.tsv"))
	if err != nil {
		t.Fatal(err)
	}
	var files [][]trackedLine
	for _, p := range cfg.Tracked {
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
	files = nil
	subset, err := parseSubset(cfg.Subset)
	if err != nil {
		t.Fatal(err)
	}
	if (cfg.ARoutes == "") != (cfg.RRoutes == "") {
		t.Fatal("ROUTECHECK_MISSINGSETS_A_ROUTES and ROUTECHECK_MISSINGSETS_R_ROUTES are used together")
	}
	cls := classifyAll(routes, sets, cfg.RIROnly)
	subsetRoutes := map[string]int{}
	var out strings.Builder
	for i, r := range routes {
		if cls[i].Reason == "unclassified" {
			t.Errorf("%q: rejected with sets %v matches no unknown reason", r.Key, r.Sets)
		}
		fmt.Fprintf(&out, "%s\t%s\t%s\n", r.Key, cls[i].Class, cls[i].Reason)
		f := strings.Split(r.Key, "|")
		if len(f) < 2 {
			t.Fatalf("key %q has no direction", r.Key)
		}
		if subset[f[0]] {
			subsetRoutes[f[0]]++
		}
	}
	for _, p := range slices.Sorted(maps.Keys(subset)) {
		t.Logf("subset pair %s: %d tracked routes", p, subsetRoutes[p])
	}
	directionTables(t, "", routes, cls, subset, cfg.RIROnly)
	var answers, rAnswers map[string]routeAnswer
	if cfg.ARoutes != "" {
		if answers, err = readRouteAnswers(cfg.ARoutes, routes); err != nil {
			t.Fatal(err)
		}
		if rAnswers, err = readRouteAnswers(cfg.RRoutes, routes); err != nil {
			t.Fatal(err)
		}
		splitTables(t, "", routes, cls, answers, rAnswers, cfg.RIROnly)
	}
	if cfg.TakeNotFound != "" {
		alt, names := takeNotFound(sets, cfg.TakeNotFound)
		title := "sensitivity: " + strings.Join(names, ", ") + " taken as not found"
		altCls := classifyAll(routes, alt, cfg.RIROnly)
		directionTables(t, title+", ", routes, altCls, nil, cfg.RIROnly)
		if answers != nil {
			splitTables(t, title+", ", routes, altCls, answers, rAnswers, cfg.RIROnly)
		}
	}
	if err := writeAtomic(filepath.Join(cfg.Dir, "routes.tsv"), out.String()); err != nil {
		t.Fatal(err)
	}
}

// directionTables logs a table per direction (and "both") for all tracked
// routes and, when subset is not empty, for the routes of its pairs.
func directionTables(t *testing.T, prefix string, routes []trackedLine, cls []classified, subset map[string]bool, rirOnly bool) {
	t.Helper()
	type scope struct {
		title string
		dirs  map[string]*classTable
	}
	scopes := [2]scope{{"all tracked routes", map[string]*classTable{}}, {"subset pairs", map[string]*classTable{}}}
	for n, r := range routes {
		f := strings.Split(r.Key, "|")
		for i, in := range []bool{true, subset[f[0]]} {
			if !in {
				continue
			}
			for _, d := range []string{f[1], "both"} {
				if scopes[i].dirs[d] == nil {
					scopes[i].dirs[d] = newClassTable()
				}
				scopes[i].dirs[d].add(cls[n])
			}
		}
	}
	for _, s := range scopes {
		for _, d := range slices.Sorted(maps.Keys(s.dirs)) {
			tallyClasses(t, prefix+s.title+", "+d, *s.dirs[d], rirOnly)
		}
	}
}

// splitTables logs the two split tables: by A's outcome, and by the
// route-object answer (A's → R's).
func splitTables(t *testing.T, prefix string, routes []trackedLine, cls []classified, a, r map[string]routeAnswer, rirOnly bool) {
	t.Helper()
	byOutcome := splitRows(routes, cls, func(k string) string { return "A " + a[k].Outcome })
	tallySplit(t, prefix+"split by A's outcome", byOutcome, len(routes), rirOnly)
	byObj := splitRows(routes, cls, func(k string) string { return a[k].Obj + " → " + r[k].Obj })
	tallySplit(t, prefix+"split by route object, A → R", byObj, len(routes), rirOnly)
}

// TestMissingSetsClassify classes the tracked routes of a run and logs the
// tables; it writes DIR/routes.tsv (key, class, reason). Environment:
//
//	ROUTECHECK_MISSINGSETS_DIR            the lookup directory (sets.tsv); the test skips without it
//	ROUTECHECK_MISSINGSETS_TRACKED        tracked.tsv files, comma-separated (streamed, merged by key)
//	ROUTECHECK_MISSINGSETS_SUBSET         pair ids AS<L>-AS<X>, comma-separated: one more table for their routes
//	ROUTECHECK_MISSINGSETS_RIR_ONLY=1     run R (route objects of the five RIRs only): the two "real"
//	                                      classes read "real without the unverified route objects" and
//	                                      "real for an RIR-objects filter", in the log and in routes.tsv
//	ROUTECHECK_MISSINGSETS_A_ROUTES,
//	ROUTECHECK_MISSINGSETS_R_ROUTES       the routes.tsv.gz of runs A and R (both or neither): two split
//	                                      tables over all tracked routes, by A's outcome and by the
//	                                      route-object answer A -> R; every tracked key must be in both
//	ROUTECHECK_MISSINGSETS_TAKE_NOT_FOUND set names, comma-separated: one more table ("sensitivity: ...
//	                                      taken as not found") classed as if those sets were not found;
//	                                      routes.tsv and the main tables keep the method's classes
func TestMissingSetsClassify(t *testing.T) {
	dir := os.Getenv("ROUTECHECK_MISSINGSETS_DIR")
	if dir == "" {
		t.Skip("ROUTECHECK_MISSINGSETS_DIR is not set")
	}
	trackedEnv := os.Getenv("ROUTECHECK_MISSINGSETS_TRACKED")
	if trackedEnv == "" {
		t.Fatal("ROUTECHECK_MISSINGSETS_TRACKED is needed")
	}
	runClassify(t, classifyConfig{
		Dir:          dir,
		Tracked:      strings.Split(trackedEnv, ","),
		Subset:       os.Getenv("ROUTECHECK_MISSINGSETS_SUBSET"),
		RIROnly:      os.Getenv("ROUTECHECK_MISSINGSETS_RIR_ONLY") == "1",
		ARoutes:      os.Getenv("ROUTECHECK_MISSINGSETS_A_ROUTES"),
		RRoutes:      os.Getenv("ROUTECHECK_MISSINGSETS_R_ROUTES"),
		TakeNotFound: os.Getenv("ROUTECHECK_MISSINGSETS_TAKE_NOT_FOUND"),
	})
}

func TestReadTrackedInternsSets(t *testing.T) {
	p := filepath.Join(t.TempDir(), "t.tsv")
	long := strings.Repeat("AS-LONGNAME-X,", 3000) + "AS-END"
	text := "k1\trejected\t\t" + long + "\nk2\trejected\t\t" + long + "\nk3\trejected\t\tAS-A\nk4\taccepted\t\t"
	if err := os.WriteFile(p, []byte(text), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := readTracked(p)
	if err != nil || len(got) != 4 {
		t.Fatalf("readTracked = %d lines, %v", len(got), err)
	}
	if len(got[0].Sets) != 3001 || &got[0].Sets[0] != &got[1].Sets[0] {
		t.Errorf("equal sets fields do not share a slice (len %d)", len(got[0].Sets))
	}
	if &got[0].Sets[0] == &got[2].Sets[0] || got[3].Sets != nil || got[3].Outcome != "accepted" {
		t.Errorf("lines mixed up: %+v", got[2:])
	}
}

func TestClassifyRIROnlyNames(t *testing.T) {
	sets := map[string]setLookup{"AS-DEL": {Set: "AS-DEL", Class: "deleted"}, "AS-NF": {Set: "AS-NF", Class: "not found"}}
	routes := []trackedLine{
		{Key: "a|import", Outcome: "rejected"},
		{Key: "b|import", Outcome: "rejected", Sets: []string{"AS-DEL", "as-nf"}},
	}
	for _, c := range []struct {
		rir  bool
		want [2]string
	}{
		{true, [2]string{"real without the unverified route objects", "real for an RIR-objects filter"}},
		{false, [2]string{"real", "real for any IRR filter"}},
	} {
		got := classifyAll(routes, sets, c.rir)
		if got[0].Class != c.want[0] || got[1].Class != c.want[1] {
			t.Errorf("rir=%v: classes %q, %q; want %q, %q", c.rir, got[0].Class, got[1].Class, c.want[0], c.want[1])
		}
	}
}

func writeGz(t *testing.T, path string, lines ...string) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	z := gzip.NewWriter(f)
	for _, l := range lines {
		fmt.Fprintln(z, l)
	}
	if err := z.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestClassifySplits(t *testing.T) {
	dir := t.TempDir()
	routes := []trackedLine{
		{Key: "AS1-AS2|import|r1", Outcome: "rejected"},
		{Key: "AS1-AS2|export|r2", Outcome: "accepted"},
		{Key: "AS1-AS2|import|r3", Outcome: "undecided", Detail: "peval"},
	}
	cls := classifyAll(routes, nil, true)
	aPath, rPath := filepath.Join(dir, "a.gz"), filepath.Join(dir, "r.gz")
	writeGz(t, aPath,
		"AS1-AS2|import|r1\tundecided\tyes\tvalid\tpeval",
		"AS1-AS2|export|r2\taccepted\tno\tunknown\t",
		"AS1-AS2|import|r3\trejected\tyes\tvalid\t",
		"AS9-AS9|import|other\taccepted\tyes\tvalid\t")
	writeGz(t, rPath,
		"AS1-AS2|import|r1\trejected\tno\tvalid\t",
		"AS1-AS2|export|r2\trejected\tno\tunknown\t",
		"AS1-AS2|import|r3\trejected\tno\tvalid\t")
	a, err := readRouteAnswers(aPath, routes)
	if err != nil {
		t.Fatal(err)
	}
	r, err := readRouteAnswers(rPath, routes)
	if err != nil {
		t.Fatal(err)
	}
	if len(a) != 3 {
		t.Errorf("kept %d answers, want only the 3 tracked keys", len(a))
	}
	byOutcome := splitRows(routes, cls, func(k string) string { return "A " + a[k].Outcome })
	byObj := splitRows(routes, cls, func(k string) string { return a[k].Obj + " → " + r[k].Obj })
	check := func(name string, rows map[string]*classTable, want map[string]map[string]int) {
		sum := 0
		for l, w := range want {
			tb := rows[l]
			if tb == nil {
				t.Errorf("%s: no row %q", name, l)
				continue
			}
			for c, n := range w {
				if tb.classes[c] != n {
					t.Errorf("%s: row %q class %q = %d, want %d", name, l, c, tb.classes[c], n)
				}
			}
		}
		for _, tb := range rows {
			sum += tb.total
		}
		if sum != 3 || len(rows) != len(want) {
			t.Errorf("%s: %d rows summing to %d, want %d rows summing to 3", name, len(rows), sum, len(want))
		}
	}
	check("by outcome", byOutcome, map[string]map[string]int{
		"A undecided": {classRealRIR: 1}, "A accepted": {classGap: 1}, "A rejected": {classUnknown: 1},
	})
	check("by object", byObj, map[string]map[string]int{
		"yes → no": {classRealRIR: 1, classUnknown: 1}, "no → no": {classGap: 1},
	})
	tallySplit(t, "split", byObj, 3, true)

	writeGz(t, aPath, "AS1-AS2|import|r1\tundecided\tyes\tvalid\t", "AS1-AS2|import|r3\trejected\tyes\tvalid\t")
	if _, err := readRouteAnswers(aPath, routes); err == nil || !strings.Contains(err.Error(), "AS1-AS2|export|r2") || !strings.Contains(err.Error(), "a.gz") {
		t.Errorf("absent key: err = %v, want one naming the key and the file", err)
	}
}

func TestClassifyTakeNotFound(t *testing.T) {
	sets := map[string]setLookup{
		"AS-DEL": {Set: "AS-DEL", Class: "deleted"},
		"AS-X":   {Set: "AS-X", Class: "inconclusive"},
	}
	routes := []trackedLine{{Key: "a|import", Outcome: "rejected", Sets: []string{"AS-DEL", "AS-X"}}}
	if got := classifyAll(routes, sets, true)[0]; got.Class != classUnknown || got.Reason != "inconclusive set" {
		t.Errorf("main table: %+v, want unknown (inconclusive set)", got)
	}
	alt, names := takeNotFound(sets, "as-x")
	if got := classifyAll(routes, alt, true)[0]; got.Class != "real for an RIR-objects filter" {
		t.Errorf("sensitivity table: %+v, want real for an RIR-objects filter", got)
	}
	if sets["AS-X"].Class != "inconclusive" || len(names) != 1 {
		t.Errorf("takeNotFound changed its input or lost names: %v %v", sets["AS-X"], names)
	}
}
