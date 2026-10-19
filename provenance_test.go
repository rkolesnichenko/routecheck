package routecheck_test

import (
	"bufio"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// The self-check figures, from CHANGELOG.md's every-registry section, over the
// 50 pairs both of its runs checked: L's import observations with a
// route-object answer ("yes") rose from 528,974 (RIPE only) to 1,568,538
// (every registry; "route objects: import yes 1,568,538").
const (
	provEveryRegistryImportYes = 1568538
	provRIPEOnlyImportYes      = 528974
	provOldRise                = provEveryRegistryImportYes - provRIPEOnlyImportYes // 1,039,564
)

// The comparison kinds. provNoVerdict is a route with no line in a run: its
// report had no policy there, or its pair was not checked.
const (
	provAccepted  = "accepted"
	provRejected  = "rejected"
	provUndecided = "undecided"
	provNoVerdict = "no verdict"
)

// provOutcomes and provRouteObjs are the rows and columns of the outcome and
// route-object matrices, in the order they are logged.
var (
	provOutcomes  = []string{provAccepted, provRejected, provUndecided, provNoVerdict}
	provRouteObjs = []string{"yes", "no", "unknown", provNoVerdict}
)

// provRoute is one route of a run's routes.tsv.gz: its outcome, route-object
// answer ("yes", "no" or "unknown"), RPKI state ("none" without VRPs) and,
// when Undecided, its reason kinds (sorted, comma-joined).
type provRoute struct{ Outcome, RouteObj, RPKI, Detail string }

// provDirOf is the direction of a route key ("import" or "export"): its second
// "|" field. Anything else is an error naming the key.
func provDirOf(key string) (string, error) {
	_, rest, _ := strings.Cut(key, "|")
	dir, _, _ := strings.Cut(rest, "|")
	if dir != "import" && dir != "export" {
		return "", fmt.Errorf("key %q: direction %q is not import or export", key, dir)
	}
	return dir, nil
}

// parseProvLine parses one routes.tsv.gz line: key, outcome, route object,
// RPKI state and detail. It returns the pair (the key's first "|" field).
func parseProvLine(line string) (pair, key string, r provRoute, err error) {
	f := strings.Split(line, "\t")
	if len(f) != 5 {
		return "", "", r, fmt.Errorf("%q is not key, outcome, route object, RPKI, detail", line)
	}
	key, r = f[0], provRoute{Outcome: f[1], RouteObj: f[2], RPKI: f[3], Detail: f[4]}
	pair, _, _ = strings.Cut(key, "|")
	if !pairID.MatchString(pair) {
		return "", "", r, fmt.Errorf("key %q: pair %q is not AS<L>-AS<X>", key, pair)
	}
	if _, err := provDirOf(key); err != nil {
		return "", "", r, err
	}
	if !slices.Contains(provOutcomes[:3], r.Outcome) {
		return "", "", r, fmt.Errorf("key %q: outcome %q is not accepted, rejected or undecided", key, r.Outcome)
	}
	if !slices.Contains(provRouteObjs[:3], r.RouteObj) {
		return "", "", r, fmt.Errorf("key %q: route object %q is not yes, no or unknown", key, r.RouteObj)
	}
	if r.RPKI == "" {
		return "", "", r, fmt.Errorf("key %q: no RPKI state", key)
	}
	return pair, key, r, nil
}

// pairReader reads the routes.tsv.gz files of one run (its shards, in order)
// one pair at a time, so that only one pair's routes are held. A pair ends at
// the next pair's line or at the end of its file.
type pairReader struct {
	files []string
	next  int // index of the next file to open
	name  string
	f     *os.File
	zr    *gzip.Reader
	sc    *bufio.Scanner
	line  int // of the current file
	// pending is the line read past the end of the last pair returned: the
	// first of the next pair, in the same file.
	pending     bool
	pPair, pKey string
	pRoute      provRoute
	seen        map[string]bool // pairs returned or begun
	err         error           // sticky: every later Next returns it
}

// newPairReader opens the first of files, a run's routes.tsv.gz shards in
// order; the others are opened as they are reached.
func newPairReader(files []string) (*pairReader, error) {
	if len(files) == 0 {
		return nil, errors.New("no routes.tsv.gz file")
	}
	r := &pairReader{files: files, seen: map[string]bool{}}
	if err := r.open(); err != nil {
		return nil, err
	}
	return r, nil
}

// open opens the next file.
func (r *pairReader) open() error {
	r.name = r.files[r.next]
	r.next++
	f, err := os.Open(r.name)
	if err != nil {
		return err
	}
	zr, err := gzip.NewReader(f)
	if err != nil {
		f.Close()
		return fmt.Errorf("%s: %w", r.name, err)
	}
	r.f, r.zr, r.line = f, zr, 0
	r.sc = bufio.NewScanner(zr)
	r.sc.Buffer(nil, 1<<20)
	return nil
}

// Close closes the file being read, if any.
func (r *pairReader) Close() {
	if r.f != nil {
		r.f.Close()
		r.f, r.zr, r.sc = nil, nil, nil
	}
}

// Next returns the next pair and its routes by key. It returns io.EOF after
// the last pair of the last file. A pair that appears again after another
// pair (or in another file), a key repeated within a pair, a malformed line,
// and a gzip or read error are errors; once one is returned, every later call
// returns it too.
func (r *pairReader) Next() (pair string, routes map[string]provRoute, err error) {
	if r.err != nil {
		return "", nil, r.err
	}
	pair, routes, err = r.next1()
	if err != nil {
		r.err = err
		r.Close()
	}
	return pair, routes, err
}

// next1 is Next without the sticky error.
func (r *pairReader) next1() (string, map[string]provRoute, error) {
	var pair string
	var routes map[string]provRoute
	add := func(p, key string, route provRoute) error {
		if pair == "" {
			if r.seen[p] {
				return fmt.Errorf("%s:%d: pair %s appears again after another pair", r.name, r.line, p)
			}
			r.seen[p] = true
			pair, routes = p, map[string]provRoute{}
		}
		if _, dup := routes[key]; dup {
			return fmt.Errorf("%s:%d: key %q is repeated in pair %s", r.name, r.line, key, p)
		}
		routes[key] = route
		return nil
	}
	for {
		if r.sc == nil {
			if r.next == len(r.files) {
				return "", nil, io.EOF
			}
			if err := r.open(); err != nil {
				return "", nil, err
			}
		}
		if r.pending {
			r.pending = false
			if err := add(r.pPair, r.pKey, r.pRoute); err != nil {
				return "", nil, err
			}
		}
		for r.sc.Scan() {
			r.line++
			p, key, route, err := parseProvLine(r.sc.Text())
			if err != nil {
				return "", nil, fmt.Errorf("%s:%d: %w", r.name, r.line, err)
			}
			if pair != "" && p != pair {
				r.pending, r.pPair, r.pKey, r.pRoute = true, p, key, route
				return pair, routes, nil
			}
			if err := add(p, key, route); err != nil {
				return "", nil, err
			}
		}
		// A truncated file gives its partial last line as a token before
		// Err reports it: check Err before returning the pair.
		if err := r.sc.Err(); err != nil {
			return "", nil, fmt.Errorf("%s: %w", r.name, err)
		}
		if err := r.zr.Close(); err != nil {
			return "", nil, fmt.Errorf("%s: %w", r.name, err)
		}
		r.Close()
		if pair != "" {
			return pair, routes, nil
		}
	}
}

// provStatuses is the set of pairs.tsv statuses.
var provStatuses = []string{"checked", "timeout", "error", "not selected"}

// readPairStatus reads the pairs.tsv files of one run's shards. Each lists
// every pair of the run in the same order; that order is returned with each
// pair's status. A pair "not selected" in one shard takes its status from the
// shard that selected it. A pair selected in two shards (checked twice, or
// with two statuses) is an error naming it, as are a malformed line and a
// shard listing other pairs or another order.
func readPairStatus(files []string) (map[string]string, []string, error) {
	if len(files) == 0 {
		return nil, nil, errors.New("no pairs.tsv file")
	}
	status := map[string]string{}
	var order []string
	for i, file := range files {
		b, err := os.ReadFile(file)
		if err != nil {
			return nil, nil, err
		}
		var fileOrder []string
		inFile := map[string]bool{}
		for n, line := range strings.Split(strings.TrimSuffix(string(b), "\n"), "\n") {
			if line == "" && len(b) == 0 {
				break
			}
			p, s, ok := strings.Cut(line, "\t")
			if !ok || !pairID.MatchString(p) || strings.Contains(s, "\t") {
				return nil, nil, fmt.Errorf("%s:%d: %q is not pair, status", file, n+1, line)
			}
			if !slices.Contains(provStatuses, s) {
				return nil, nil, fmt.Errorf("%s:%d: status %q is not one of %q", file, n+1, s, provStatuses)
			}
			if inFile[p] {
				return nil, nil, fmt.Errorf("%s:%d: pair %s is listed twice", file, n+1, p)
			}
			inFile[p] = true
			fileOrder = append(fileOrder, p)
			prev, seen := status[p]
			switch {
			case !seen || prev == "not selected":
				status[p] = s
			case s == "not selected":
			case prev == "checked" && s == "checked":
				return nil, nil, fmt.Errorf("%s: pair %s is checked in two shards", file, p)
			default:
				return nil, nil, fmt.Errorf("%s: pair %s is %s in one shard and %s in another", file, p, prev, s)
			}
		}
		if i == 0 {
			order = fileOrder
		} else if !slices.Equal(fileOrder, order) {
			return nil, nil, fmt.Errorf("%s lists other pairs, or another order, than %s", file, files[0])
		}
	}
	return status, order, nil
}

// zipPairs calls fn for each pair of order, in order, with its routes in run A
// and in the other run (nil when that run wrote none for it). Each run's
// reader is advanced only after fn returns, so at most one pair of each run is
// held. A pair with routes that order does not hold, or holds earlier than the
// pair before it, or whose status in that run is not "checked", is an error
// naming it.
func zipPairs(order []string, a, b *pairReader, aStatus, bStatus map[string]string, fn func(pair string, am, bm map[string]provRoute) error) error {
	pos := make(map[string]int, len(order))
	for i, p := range order {
		pos[p] = i
	}
	type cursor struct {
		run    string
		r      *pairReader
		status map[string]string
		pair   string
		routes map[string]provRoute
		eof    bool
	}
	// advance reads c's next pair; i is the index in order of the last pair
	// handed to fn (-1 before the first).
	advance := func(c *cursor, i int) error {
		c.pair, c.routes = "", nil
		p, routes, err := c.r.Next()
		if errors.Is(err, io.EOF) {
			c.eof = true
			return nil
		}
		if err != nil {
			return fmt.Errorf("run %s: %w", c.run, err)
		}
		j, ok := pos[p]
		switch {
		case !ok:
			return fmt.Errorf("run %s: pair %s has routes but is not in pairs.tsv", c.run, p)
		case j <= i:
			return fmt.Errorf("run %s: pair %s comes after %s, against the pairs.tsv order", c.run, p, order[i])
		case c.status[p] != "checked":
			return fmt.Errorf("run %s: pair %s has routes but its status is %q", c.run, p, c.status[p])
		}
		c.pair, c.routes = p, routes
		return nil
	}
	cs := [2]*cursor{{run: "A", r: a, status: aStatus}, {run: "other", r: b, status: bStatus}}
	for _, c := range cs {
		if err := advance(c, -1); err != nil {
			return err
		}
	}
	for i, p := range order {
		var m [2]map[string]provRoute
		for k, c := range cs {
			if !c.eof && c.pair == p {
				m[k] = c.routes
			}
		}
		if err := fn(p, m[0], m[1]); err != nil {
			return err
		}
		for k, c := range cs {
			if m[k] != nil {
				m[k] = nil
				if err := advance(c, i); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// provKey is a cell of a table: the kind in run A and in the other run.
type provKey struct{ A, B string }

// provDir is one direction's comparison of run A with the other run, over its
// universe: every route key either run has.
type provDir struct {
	// Outcome is the outcome matrix over provOutcomes.
	Outcome map[provKey]int
	// NoVerdict splits the Outcome cells with a "no verdict" side by its
	// reason: that side's kind reads "no verdict (no policy)" when its pair
	// was checked, else "no verdict (pair <status>)".
	NoVerdict map[provKey]int
	// Undecided splits the "undecided → *" row by A's Detail: {Detail, the
	// other run's kind}. An empty Detail is "(none)".
	Undecided map[provKey]int
	// RouteObj is the route-object matrix over provRouteObjs.
	RouteObj map[provKey]int
	// RPKIYesNo and RPKIAccRej are A's RPKI state of the routes whose route
	// object goes yes → no, and of those accepted → rejected. Both runs load
	// the same VRPs.
	RPKIYesNo, RPKIAccRej map[string]int
	// The universe, split: keys in both runs, in A only, in the other only.
	Both, AOnly, OtherOnly int
}

func newProvDir() *provDir {
	return &provDir{Outcome: map[provKey]int{}, NoVerdict: map[provKey]int{}, Undecided: map[provKey]int{},
		RouteObj: map[provKey]int{}, RPKIYesNo: map[string]int{}, RPKIAccRej: map[string]int{}}
}

// Universe is the number of route keys compared.
func (d *provDir) Universe() int { return d.Both + d.AOnly + d.OtherOnly }

// add adds e's counts to d.
func (d *provDir) add(e *provDir) {
	for _, mm := range [][2]map[provKey]int{{d.Outcome, e.Outcome}, {d.NoVerdict, e.NoVerdict}, {d.Undecided, e.Undecided}, {d.RouteObj, e.RouteObj}} {
		for k, n := range mm[1] {
			mm[0][k] += n
		}
	}
	for _, mm := range [][2]map[string]int{{d.RPKIYesNo, e.RPKIYesNo}, {d.RPKIAccRej, e.RPKIAccRej}} {
		for k, n := range mm[1] {
			mm[0][k] += n
		}
	}
	d.Both, d.AOnly, d.OtherOnly = d.Both+e.Both, d.AOnly+e.AOnly, d.OtherOnly+e.OtherOnly
}

// sumCells is the sum of a table's cells.
func sumCells[K comparable](m map[K]int) int {
	n := 0
	for _, v := range m {
		n += v
	}
	return n
}

// rowSum and colSum are the sums of a matrix's row a (A's kind) and column b
// (the other run's kind).
func rowSum(m map[provKey]int, a string) int {
	n := 0
	for k, v := range m {
		if k.A == a {
			n += v
		}
	}
	return n
}

func colSum(m map[provKey]int, b string) int {
	n := 0
	for k, v := range m {
		if k.B == b {
			n += v
		}
	}
	return n
}

// sumErrors checks every view of d against the universe and against each
// other; it returns one line per sum that does not hold.
func (d *provDir) sumErrors() []string {
	var errs []string
	check := func(what string, got, want int) {
		if got != want {
			errs = append(errs, fmt.Sprintf("%s sums to %d, want %d", what, got, want))
		}
	}
	u := d.Universe()
	check("the outcome matrix", sumCells(d.Outcome), u)
	check("the route-object matrix", sumCells(d.RouteObj), u)
	check("A's outcomes", u-rowSum(d.Outcome, provNoVerdict), d.Both+d.AOnly)
	check("the other run's outcomes", u-colSum(d.Outcome, provNoVerdict), d.Both+d.OtherOnly)
	check("A's route objects", u-rowSum(d.RouteObj, provNoVerdict), d.Both+d.AOnly)
	check("the other run's route objects", u-colSum(d.RouteObj, provNoVerdict), d.Both+d.OtherOnly)
	check("the no-verdict reasons", sumCells(d.NoVerdict), rowSum(d.Outcome, provNoVerdict)+colSum(d.Outcome, provNoVerdict))
	check("the undecided reasons", sumCells(d.Undecided), rowSum(d.Outcome, provUndecided))
	check("the RPKI states of yes → no", sumCells(d.RPKIYesNo), d.RouteObj[provKey{"yes", "no"}])
	check("the RPKI states of accepted → rejected", sumCells(d.RPKIAccRej), d.Outcome[provKey{provAccepted, provRejected}])
	return errs
}

// provTally is the comparison of run A with another run, per direction
// ("import", "export"), and the self-check counters over the pairs it is
// taken on: A's import route-object "yes" answers, and the other run's import
// "yes" answers on the routes A has.
type provTally struct {
	Dirs                       map[string]*provDir
	SubsetAYes, SubsetOtherYes int
}

func newProvTally() *provTally {
	return &provTally{Dirs: map[string]*provDir{"import": newProvDir(), "export": newProvDir()}}
}

// Total is both directions added.
func (t *provTally) Total() *provDir {
	d := newProvDir()
	d.add(t.Dirs["import"])
	d.add(t.Dirs["export"])
	return d
}

// provNoVerdictKind is the kind of a route with no line in a run whose pair
// has the given status ("" when pairs.tsv does not list it).
func provNoVerdictKind(status string) string {
	switch status {
	case "checked":
		return provNoVerdict + " (no policy)"
	case "":
		return provNoVerdict + " (pair missing)"
	}
	return provNoVerdict + " (pair " + status + ")"
}

// comparePair adds one pair to t: a and b are its routes in run A and in the
// other run (nil when that run wrote none), aStatus and bStatus its pairs.tsv
// statuses ("" when absent). The universe is the union of a's and b's keys; a
// key missing from a side is "no verdict" there. A route object "no" in A and
// "yes" in the other run is an error naming the key. With subset50, the pair
// counts in the self-check.
func comparePair(t *provTally, a, b map[string]provRoute, aStatus, bStatus string, subset50 bool) error {
	count := func(key string, ra, rb provRoute, inA, inB bool) error {
		dir, err := provDirOf(key)
		if err != nil {
			return err
		}
		d := t.Dirs[dir]
		oa, ob, sa, sb := provNoVerdict, provNoVerdict, provNoVerdict, provNoVerdict
		if inA {
			oa, sa = ra.Outcome, ra.RouteObj
		}
		if inB {
			ob, sb = rb.Outcome, rb.RouteObj
		}
		if sa == "no" && sb == "yes" {
			return fmt.Errorf("key %q: route object no in A, yes in the other run", key)
		}
		switch {
		case inA && inB:
			d.Both++
		case inA:
			d.AOnly++
			d.NoVerdict[provKey{oa, provNoVerdictKind(bStatus)}]++
		default:
			d.OtherOnly++
			d.NoVerdict[provKey{provNoVerdictKind(aStatus), ob}]++
		}
		d.Outcome[provKey{oa, ob}]++
		d.RouteObj[provKey{sa, sb}]++
		if oa == provUndecided {
			detail := ra.Detail
			if detail == "" {
				detail = "(none)"
			}
			d.Undecided[provKey{detail, ob}]++
		}
		if sa == "yes" && sb == "no" {
			d.RPKIYesNo[ra.RPKI]++
		}
		if oa == provAccepted && ob == provRejected {
			d.RPKIAccRej[ra.RPKI]++
		}
		if subset50 && inA && dir == "import" && sa == "yes" {
			t.SubsetAYes++
		}
		if subset50 && inA && dir == "import" && sb == "yes" {
			t.SubsetOtherYes++
		}
		return nil
	}
	for key, ra := range a {
		rb, inB := b[key]
		if err := count(key, ra, rb, true, inB); err != nil {
			return err
		}
	}
	for key, rb := range b {
		if _, inA := a[key]; !inA {
			if err := count(key, provRoute{}, rb, false, true); err != nil {
				return err
			}
		}
	}
	return nil
}

// logProvMatrix logs a matrix with its rows and columns in the given order,
// each row with its sum, then the column sums.
func logProvMatrix(t *testing.T, title, other string, kinds []string, m map[provKey]int) {
	t.Logf("  %s (rows A, columns %s):", title, other)
	head := fmt.Sprintf("    %-12s", "")
	for _, k := range kinds {
		head += fmt.Sprintf(" %12s", k)
	}
	t.Logf("%s %12s", head, "sum")
	for _, ra := range kinds {
		row := fmt.Sprintf("    %-12s", ra)
		for _, rb := range kinds {
			row += fmt.Sprintf(" %12d", m[provKey{ra, rb}])
		}
		t.Logf("%s %12d", row, rowSum(m, ra))
	}
	row := fmt.Sprintf("    %-12s", "sum")
	for _, rb := range kinds {
		row += fmt.Sprintf(" %12d", colSum(m, rb))
	}
	t.Logf("%s %12d", row, sumCells(m))
}

// logProvCells logs a table's non-zero cells as "A → other", sorted.
func logProvCells(t *testing.T, title string, m map[provKey]int) {
	t.Logf("  %s, sum %d:", title, sumCells(m))
	keys := slices.SortedFunc(maps.Keys(m), func(x, y provKey) int {
		if c := strings.Compare(x.A, y.A); c != 0 {
			return c
		}
		return strings.Compare(x.B, y.B)
	})
	for _, k := range keys {
		t.Logf("    %-40s → %-32s %d", k.A, k.B, m[k])
	}
}

// logProvStates logs an RPKI table, sorted by state.
func logProvStates(t *testing.T, title string, m map[string]int) {
	t.Logf("  %s, sum %d:", title, sumCells(m))
	for _, s := range slices.Sorted(maps.Keys(m)) {
		t.Logf("    %-12s %d", s, m[s])
	}
}

// provShare is n as a percentage of of.
func provShare(n, of int) string {
	if of == 0 {
		return "n/a"
	}
	return fmt.Sprintf("%.2f%%", 100*float64(n)/float64(of))
}

// logProvDir logs one direction's tables and fails the test on a sum that does
// not hold.
func logProvDir(t *testing.T, name, other string, d *provDir) {
	t.Logf("%s: A against %s, %d routes: %d in both, %d in A only, %d in %s only (sum %d)",
		name, other, d.Universe(), d.Both, d.AOnly, d.OtherOnly, other, d.Both+d.AOnly+d.OtherOnly)
	logProvMatrix(t, "outcomes", other, provOutcomes, d.Outcome)
	logProvCells(t, "no verdict, by reason", d.NoVerdict)
	logProvCells(t, "undecided in A, by A's reasons → "+other+"'s outcome", d.Undecided)
	logProvMatrix(t, "route objects", other, provRouteObjs, d.RouteObj)
	aYes, otherYes := rowSum(d.RouteObj, "yes"), colSum(d.RouteObj, "yes")
	aDen, otherDen := aYes+rowSum(d.RouteObj, "no"), otherYes+colSum(d.RouteObj, "no")
	yesNo := d.RouteObj[provKey{"yes", "no"}]
	t.Logf("  route object yes → no: %d, %s of A's %d yes", yesNo, provShare(yesNo, aYes), aYes)
	logProvStates(t, "RPKI (A's) of route object yes → no", d.RPKIYesNo)
	logProvStates(t, "RPKI (A's) of accepted → rejected", d.RPKIAccRej)
	t.Logf("  totals only: A's yes %d - %s's yes %d = %d; route by route yes → no %d; equal: %v",
		aYes, other, otherYes, aYes-otherYes, yesNo, aYes-otherYes == yesNo)
	t.Logf("  route-object denominators (yes + no): A %d, %s %d", aDen, other, otherDen)
	if aDen != otherDen {
		t.Logf("  the denominators differ: the totals-only shortcut does not apply (design, settled 2)")
	}
	for _, e := range d.sumErrors() {
		t.Errorf("%s: %s", name, e)
	}
}

// provSplit splits a comma-separated list of directories, dropping empty
// items.
func provSplit(s string) []string {
	var out []string
	for _, f := range strings.Split(s, ",") {
		if f = strings.TrimSpace(f); f != "" {
			out = append(out, f)
		}
	}
	return out
}

// TestProvenanceCompare compares two real-data runs route by route: run A
// (ROUTECHECK_PROVENANCE_A) and the other run (ROUTECHECK_PROVENANCE_B,
// labelled R or V by ROUTECHECK_PROVENANCE_LABEL), each a comma-separated
// list of ROUTECHECK_REALDATA_OUT directories, its shards in order. The pairs
// not in ROUTECHECK_PROVENANCE_EXCLUDE (space- or comma-separated pair ids)
// are the self-check's: A's import route-object "yes" there must be
// 1,568,538. It writes nothing; the tables are its log.
func TestProvenanceCompare(t *testing.T) {
	aEnv := os.Getenv("ROUTECHECK_PROVENANCE_A")
	if aEnv == "" {
		t.Skip("ROUTECHECK_PROVENANCE_A is not set")
	}
	aDirs, bDirs := provSplit(aEnv), provSplit(os.Getenv("ROUTECHECK_PROVENANCE_B"))
	if len(bDirs) == 0 {
		t.Fatal("ROUTECHECK_PROVENANCE_B is needed")
	}
	label := os.Getenv("ROUTECHECK_PROVENANCE_LABEL")
	if label != "R" && label != "V" {
		t.Fatalf("ROUTECHECK_PROVENANCE_LABEL is %q, want R or V", label)
	}
	files := func(dirs []string, name string) []string {
		var out []string
		for _, d := range dirs {
			out = append(out, filepath.Join(d, name))
		}
		return out
	}
	aStatus, order, err := readPairStatus(files(aDirs, "pairs.tsv"))
	if err != nil {
		t.Fatalf("A: %v", err)
	}
	bStatus, bOrder, err := readPairStatus(files(bDirs, "pairs.tsv"))
	if err != nil {
		t.Fatalf("%s: %v", label, err)
	}
	if !slices.Equal(order, bOrder) {
		t.Fatalf("A and %s list other pairs or another order: %v and %v", label, order, bOrder)
	}
	exclude := map[string]bool{}
	for _, p := range strings.FieldsFunc(os.Getenv("ROUTECHECK_PROVENANCE_EXCLUDE"), func(r rune) bool { return r == ',' || r == ' ' }) {
		if !slices.Contains(order, p) {
			t.Fatalf("ROUTECHECK_PROVENANCE_EXCLUDE: %s is not a pair of the runs", p)
		}
		exclude[p] = true
	}
	if len(exclude) == 0 {
		t.Fatal("ROUTECHECK_PROVENANCE_EXCLUDE is needed: the pairs outside the self-check")
	}
	t.Logf("%d pairs; the self-check takes the %d not excluded (%d excluded)", len(order), len(order)-len(exclude), len(exclude))

	ar, err := newPairReader(files(aDirs, "routes.tsv.gz"))
	if err != nil {
		t.Fatalf("A: %v", err)
	}
	defer ar.Close()
	br, err := newPairReader(files(bDirs, "routes.tsv.gz"))
	if err != nil {
		t.Fatalf("%s: %v", label, err)
	}
	defer br.Close()
	tl := newProvTally()
	if err := zipPairs(order, ar, br, aStatus, bStatus, func(p string, am, bm map[string]provRoute) error {
		t.Logf("pair %s: A %s, %d routes; %s %s, %d routes; self-check %v", p, aStatus[p], len(am), label, bStatus[p], len(bm), !exclude[p])
		return comparePair(tl, am, bm, aStatus[p], bStatus[p], !exclude[p])
	}); err != nil {
		t.Fatal(err)
	}

	logProvDir(t, "import", label, tl.Dirs["import"])
	logProvDir(t, "export", label, tl.Dirs["export"])
	logProvDir(t, "total", label, tl.Total())

	diff := tl.SubsetAYes - tl.SubsetOtherYes
	t.Logf("self-check, %d pairs: A's import route-object yes %d (want %d); %s's yes on A's routes %d; difference %d, %s of the old rise %d (%d to %d)",
		len(order)-len(exclude), tl.SubsetAYes, provEveryRegistryImportYes, label, tl.SubsetOtherYes, diff,
		provShare(diff, provOldRise), provOldRise, provRIPEOnlyImportYes, provEveryRegistryImportYes)
	if tl.SubsetAYes != provEveryRegistryImportYes {
		t.Errorf("self-check: A's import route-object yes over the %d pairs is %d, want %d", len(order)-len(exclude), tl.SubsetAYes, provEveryRegistryImportYes)
	}
}

// writeProvRoutes writes lines, each ended by "\n", gzipped to dir/name and
// returns the file's path.
func writeProvRoutes(t *testing.T, dir, name string, lines ...string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	zw := gzip.NewWriter(f)
	for _, l := range lines {
		if _, err := zw.Write([]byte(l + "\n")); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

// provTestLine is a routes.tsv.gz line of pair, direction dir and route n
// (its prefix is 10.0.<n>.0/24), accepted with a route object, RPKI valid.
func provTestLine(pair, dir string, n int) string {
	return fmt.Sprintf("%s|%s|ipv4|AS1|10.0.%d.0/24|AS1 AS2\taccepted\tyes\tvalid\t", pair, dir, n)
}

// readAllPairs reads r to its end: the pair ids and their route counts, and
// the error that ended it (io.EOF at a clean end).
func readAllPairs(r *pairReader) (pairs []string, counts []int, err error) {
	for {
		p, routes, err := r.Next()
		if err != nil {
			return pairs, counts, err
		}
		pairs, counts = append(pairs, p), append(counts, len(routes))
	}
}

func TestPairReaderOrder(t *testing.T) {
	dir := t.TempDir()
	const p1, p2, p3 = "AS1-AS2", "AS3-AS4", "AS5-AS6"
	s1 := writeProvRoutes(t, dir, "s1.gz", provTestLine(p1, "import", 1), provTestLine(p1, "export", 1), provTestLine(p2, "import", 1))
	s2 := writeProvRoutes(t, dir, "s2.gz", provTestLine(p3, "import", 1))
	r, err := newPairReader([]string{s1, s2})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	pairs, counts, err := readAllPairs(r)
	if err != io.EOF {
		t.Fatalf("two shards: ended with %v, want io.EOF", err)
	}
	if fmt.Sprint(pairs, counts) != fmt.Sprint([]string{p1, p2, p3}, []int{2, 1, 1}) {
		t.Errorf("two shards: read %v with %v routes, want [%s %s %s] with [2 1 1]", pairs, counts, p1, p2, p3)
	}

	for _, tc := range []struct {
		name    string
		files   [][]string
		wantErr string
	}{
		{"again in another shard", [][]string{{provTestLine(p1, "import", 1)}, {provTestLine(p2, "import", 1), provTestLine(p1, "import", 2)}}, p1},
		{"again in one file", [][]string{{provTestLine(p1, "import", 1), provTestLine(p2, "import", 1), provTestLine(p1, "import", 2)}}, p1},
		{"continued in the next shard", [][]string{{provTestLine(p1, "import", 1)}, {provTestLine(p1, "import", 2)}}, p1},
		{"key repeated", [][]string{{provTestLine(p1, "import", 1), provTestLine(p1, "export", 1), provTestLine(p1, "import", 1)}}, p1 + "|import|ipv4|AS1|10.0.1.0/24|AS1 AS2"},
		{"four fields", [][]string{{p1 + "|import|ipv4|AS1|10.0.1.0/24|AS1\taccepted\tyes\tvalid"}}, "s0.gz:1"},
		{"bad outcome", [][]string{{p1 + "|import|ipv4|AS1|10.0.1.0/24|AS1\tnone\tyes\tvalid\t"}}, `"none"`},
		{"bad route object", [][]string{{p1 + "|import|ipv4|AS1|10.0.1.0/24|AS1\taccepted\tmaybe\tvalid\t"}}, `"maybe"`},
		{"bad direction", [][]string{{p1 + "|both|ipv4|AS1|10.0.1.0/24|AS1\taccepted\tyes\tvalid\t"}}, `"both"`},
		{"bad pair", [][]string{{"AS1|import|ipv4|AS1|10.0.1.0/24|AS1\taccepted\tyes\tvalid\t"}}, `"AS1"`},
	} {
		sub := t.TempDir()
		var files []string
		for i, lines := range tc.files {
			files = append(files, writeProvRoutes(t, sub, fmt.Sprintf("s%d.gz", i), lines...))
		}
		r, err := newPairReader(files)
		if err != nil {
			t.Fatal(err)
		}
		_, _, err = readAllPairs(r)
		r.Close()
		if err == nil || errors.Is(err, io.EOF) || !strings.Contains(err.Error(), tc.wantErr) {
			t.Errorf("%s: ended with %v, want an error naming %s", tc.name, err, tc.wantErr)
		}
	}
	if _, err := newPairReader([]string{filepath.Join(dir, "absent.gz")}); err == nil {
		t.Error("a missing file: no error")
	}
}

func TestPairReaderTruncated(t *testing.T) {
	dir := t.TempDir()
	var lines []string
	for i := range 5000 {
		lines = append(lines, fmt.Sprintf("AS%d-AS%d|import|ipv4|AS7|10.%d.%d.0/24|AS7 AS%d\taccepted\tyes\tvalid\t", 1+i/1000, 2+i/1000, i%251, i%241, i*7919))
	}
	path := writeProvRoutes(t, dir, "full.gz", lines...)
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	cut := filepath.Join(dir, "cut.gz")
	if err := os.WriteFile(cut, b[:len(b)/2], 0o644); err != nil {
		t.Fatal(err)
	}
	r, err := newPairReader([]string{cut})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	pairs, _, err := readAllPairs(r)
	if err == nil || errors.Is(err, io.EOF) {
		t.Fatalf("a gzip file cut in half: read %d pairs and ended with %v, want an error", len(pairs), err)
	}
	if _, _, again := r.Next(); again == nil || errors.Is(again, io.EOF) {
		t.Errorf("after the error, Next gives %v, want the error again", again)
	}
}

func TestReadPairStatus(t *testing.T) {
	dir := t.TempDir()
	write := func(name, text string) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(text), 0o644); err != nil {
			t.Fatal(err)
		}
		return path
	}
	s1 := write("s1", "AS1-AS2\tchecked\nAS3-AS4\tnot selected\nAS5-AS6\ttimeout\nAS7-AS8\tnot selected\n")
	s2 := write("s2", "AS1-AS2\tnot selected\nAS3-AS4\tchecked\nAS5-AS6\tnot selected\nAS7-AS8\tnot selected\n")
	status, order, err := readPairStatus([]string{s1, s2})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := fmt.Sprint(order), "[AS1-AS2 AS3-AS4 AS5-AS6 AS7-AS8]"; got != want {
		t.Errorf("order %s, want %s", got, want)
	}
	for p, want := range map[string]string{"AS1-AS2": "checked", "AS3-AS4": "checked", "AS5-AS6": "timeout", "AS7-AS8": "not selected"} {
		if status[p] != want {
			t.Errorf("%s: status %q, want %q", p, status[p], want)
		}
	}
	if len(status) != 4 {
		t.Errorf("%d statuses, want 4", len(status))
	}

	for _, tc := range []struct {
		name, text, wantErr string
	}{
		{"checked in two shards", "AS1-AS2\tchecked\nAS3-AS4\tnot selected\nAS5-AS6\tnot selected\nAS7-AS8\tnot selected\n", "AS1-AS2 is checked in two shards"},
		{"timeout in one, checked in another", "AS1-AS2\tnot selected\nAS3-AS4\tnot selected\nAS5-AS6\tchecked\nAS7-AS8\tnot selected\n", "AS5-AS6"},
		{"another order", "AS3-AS4\tnot selected\nAS1-AS2\tnot selected\nAS5-AS6\tnot selected\nAS7-AS8\tnot selected\n", "order"},
		{"bad status", "AS1-AS2\tnot selected\nAS3-AS4\tnot selected\nAS5-AS6\tdone\nAS7-AS8\tnot selected\n", `"done"`},
		{"one field", "AS1-AS2\n", "s3:1"},
		{"a pair twice", "AS1-AS2\tnot selected\nAS1-AS2\tnot selected\n", "AS1-AS2"},
	} {
		s3 := write("s3", tc.text)
		if _, _, err := readPairStatus([]string{s1, s3}); err == nil || !strings.Contains(err.Error(), tc.wantErr) {
			t.Errorf("%s: %v, want an error naming %s", tc.name, err, tc.wantErr)
		}
	}
}

// provR is a provRoute in a test: outcome, route object, RPKI and detail.
func provR(outcome, obj, rpki, detail string) provRoute {
	return provRoute{Outcome: outcome, RouteObj: obj, RPKI: rpki, Detail: detail}
}

func TestCompareNoVerdict(t *testing.T) {
	const key = "AS1-AS2|import|ipv4|AS1|10.0.0.0/24|AS1 AS2"
	a := map[string]provRoute{key: provR("accepted", "yes", "valid", "")}
	for _, tc := range []struct{ bStatus, want string }{
		{"checked", "no verdict (no policy)"},
		{"timeout", "no verdict (pair timeout)"},
		{"error", "no verdict (pair error)"},
		{"not selected", "no verdict (pair not selected)"},
		{"", "no verdict (pair missing)"},
	} {
		tl := newProvTally()
		if err := comparePair(tl, a, nil, "checked", tc.bStatus, false); err != nil {
			t.Fatal(err)
		}
		d := tl.Dirs["import"]
		if n := d.Outcome[provKey{"accepted", "no verdict"}]; n != 1 {
			t.Errorf("B %q: accepted → no verdict is %d, want 1", tc.bStatus, n)
		}
		if n := d.NoVerdict[provKey{"accepted", tc.want}]; n != 1 {
			t.Errorf("B %q: accepted → %s is %d, want 1 (no-verdict reasons %v)", tc.bStatus, tc.want, n, d.NoVerdict)
		}
		if n := d.RouteObj[provKey{"yes", "no verdict"}]; n != 1 {
			t.Errorf("B %q: route object yes → no verdict is %d, want 1", tc.bStatus, n)
		}
		if d.Both != 0 || d.AOnly != 1 || d.OtherOnly != 0 {
			t.Errorf("B %q: universe both %d, A only %d, other only %d; want 0, 1, 0", tc.bStatus, d.Both, d.AOnly, d.OtherOnly)
		}
		if errs := d.sumErrors(); len(errs) > 0 {
			t.Errorf("B %q: %v", tc.bStatus, errs)
		}
	}

	// The other way round: a key only the other run has.
	tl := newProvTally()
	if err := comparePair(tl, nil, a, "timeout", "checked", false); err != nil {
		t.Fatal(err)
	}
	d := tl.Dirs["import"]
	if n := d.NoVerdict[provKey{"no verdict (pair timeout)", "accepted"}]; n != 1 || d.OtherOnly != 1 || d.Universe() != 1 {
		t.Errorf("only in the other run: no verdict (pair timeout) → accepted %d, other only %d, universe %d; want 1, 1, 1", n, d.OtherOnly, d.Universe())
	}
}

func TestCompareRouteObj(t *testing.T) {
	const key = "AS1-AS2|import|ipv4|AS1|10.0.0.0/24|AS1 AS2"
	tl := newProvTally()
	a := map[string]provRoute{key: provR("accepted", "yes", "valid", "")}
	b := map[string]provRoute{key: provR("rejected", "no", "valid", "")}
	if err := comparePair(tl, a, b, "checked", "checked", false); err != nil {
		t.Fatal(err)
	}
	d := tl.Dirs["import"]
	if n := d.RouteObj[provKey{"yes", "no"}]; n != 1 {
		t.Errorf("yes → no is %d, want 1", n)
	}
	if n := d.RPKIYesNo["valid"]; n != 1 {
		t.Errorf("RPKI of yes → no: %v, want valid 1", d.RPKIYesNo)
	}
	if n := d.RPKIAccRej["valid"]; n != 1 {
		t.Errorf("RPKI of accepted → rejected: %v, want valid 1", d.RPKIAccRej)
	}

	err := comparePair(newProvTally(), b, a, "checked", "checked", false)
	if err == nil || !strings.Contains(err.Error(), key) {
		t.Errorf("no → yes: %v, want an error naming %s", err, key)
	}
}

func TestCompareSums(t *testing.T) {
	const pre = "AS1-AS2|"
	a := map[string]provRoute{
		pre + "import|ipv4|AS1|10.0.0.0/24|AS1": provR("accepted", "yes", "valid", ""),
		pre + "import|ipv4|AS1|10.0.1.0/24|AS1": provR("undecided", "unknown", "not_found", "peval,unevaluable"),
		pre + "export|ipv4|AS1|10.0.2.0/24|AS1": provR("accepted", "yes", "invalid", ""),
		pre + "export|ipv4|AS1|10.0.3.0/24|AS1": provR("rejected", "no", "none", ""),
	}
	b := map[string]provRoute{
		pre + "import|ipv4|AS1|10.0.0.0/24|AS1": provR("accepted", "no", "valid", ""),
		pre + "import|ipv4|AS1|10.0.1.0/24|AS1": provR("rejected", "unknown", "not_found", ""),
		pre + "export|ipv4|AS1|10.0.2.0/24|AS1": provR("rejected", "no", "invalid", ""),
		pre + "import|ipv4|AS1|10.0.4.0/24|AS1": provR("accepted", "no", "valid", ""),
	}
	tl := newProvTally()
	if err := comparePair(tl, a, b, "checked", "checked", true); err != nil {
		t.Fatal(err)
	}
	total := tl.Total()
	if n := total.Universe(); n != 5 {
		t.Errorf("universe %d, want 5", n)
	}
	for name, d := range map[string]*provDir{"import": tl.Dirs["import"], "export": tl.Dirs["export"], "total": total} {
		if errs := d.sumErrors(); len(errs) > 0 {
			t.Errorf("%s: %v", name, errs)
		}
	}
	for what, n := range map[string]int{
		"outcome matrix": sumCells(total.Outcome), "route-object matrix": sumCells(total.RouteObj),
		"universe split": total.Both + total.AOnly + total.OtherOnly,
	} {
		if n != 5 {
			t.Errorf("%s sums to %d, want 5", what, n)
		}
	}
	if tl.Dirs["import"].Universe() != 3 || tl.Dirs["export"].Universe() != 2 {
		t.Errorf("import %d, export %d routes; want 3, 2", tl.Dirs["import"].Universe(), tl.Dirs["export"].Universe())
	}
	if n := tl.Dirs["import"].Undecided[provKey{"peval,unevaluable", "rejected"}]; n != 1 {
		t.Errorf("undecided → rejected by peval,unevaluable is %d, want 1 (%v)", n, tl.Dirs["import"].Undecided)
	}
	if n := total.RPKIYesNo["valid"] + total.RPKIYesNo["invalid"]; n != 2 || total.RouteObj[provKey{"yes", "no"}] != 2 {
		t.Errorf("RPKI of yes → no: %v, want valid 1, invalid 1", total.RPKIYesNo)
	}
	if n := total.RPKIAccRej["invalid"]; n != 1 || len(total.RPKIAccRej) != 1 {
		t.Errorf("RPKI of accepted → rejected: %v, want invalid 1", total.RPKIAccRej)
	}
	if tl.SubsetAYes != 1 || tl.SubsetOtherYes != 0 {
		t.Errorf("self-check: A's import yes %d, other's %d; want 1, 0", tl.SubsetAYes, tl.SubsetOtherYes)
	}
	tl2 := newProvTally()
	if err := comparePair(tl2, a, b, "checked", "checked", false); err != nil {
		t.Fatal(err)
	}
	if tl2.SubsetAYes != 0 || tl2.SubsetOtherYes != 0 {
		t.Errorf("an excluded pair counts in the self-check: %d, %d", tl2.SubsetAYes, tl2.SubsetOtherYes)
	}
}

func TestCompareZipOrder(t *testing.T) {
	dir := t.TempDir()
	const p1, p2, p3 = "AS1-AS2", "AS3-AS4", "AS5-AS6"
	order := []string{p1, p2, p3}
	checked := map[string]string{p1: "checked", p2: "checked", p3: "checked"}
	open := func(name string, lines ...string) *pairReader {
		r, err := newPairReader([]string{writeProvRoutes(t, dir, name, lines...)})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(r.Close)
		return r
	}
	a := open("a.gz", provTestLine(p1, "import", 1), provTestLine(p3, "import", 1))
	b := open("b.gz", provTestLine(p2, "import", 1), provTestLine(p3, "import", 1), provTestLine(p3, "import", 2))
	var got []string
	err := zipPairs(order, a, b, checked, checked, func(p string, am, bm map[string]provRoute) error {
		got = append(got, fmt.Sprintf("%s %d %d", p, len(am), len(bm)))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if want := "[AS1-AS2 1 0 AS3-AS4 0 1 AS5-AS6 1 2]"; fmt.Sprint(got) != want {
		t.Errorf("zip gave %v, want %s", got, want)
	}

	nop := func(string, map[string]provRoute, map[string]provRoute) error { return nil }
	for _, tc := range []struct {
		name    string
		a       *pairReader
		aStatus map[string]string
		wantErr string
	}{
		{"out of order", open("o.gz", provTestLine(p3, "import", 1), provTestLine(p1, "import", 1)), checked, p1},
		{"not in pairs.tsv", open("n.gz", provTestLine("AS9-AS9", "import", 1)), checked, "AS9-AS9"},
		{"routes of a pair not checked", open("t.gz", provTestLine(p2, "import", 1)), map[string]string{p1: "checked", p2: "timeout", p3: "checked"}, p2},
	} {
		err := zipPairs(order, tc.a, open(tc.name+".b.gz"), tc.aStatus, checked, nop)
		if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
			t.Errorf("%s: %v, want an error naming %s", tc.name, err, tc.wantErr)
		}
	}
}
