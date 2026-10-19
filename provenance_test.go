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
	"unicode"
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
	// CommonRouteObj is RouteObj over the pairs both runs checked, where the
	// totals-only shortcut is taken (design, goal 2). Every yes → no is in it,
	// since a key both runs have is in a pair both checked.
	CommonRouteObj map[provKey]int
	// RPKIYesNo and RPKIAccRej are A's RPKI state of the routes whose route
	// object goes yes → no, and of those accepted → rejected. Both runs load
	// the same VRPs.
	RPKIYesNo, RPKIAccRej map[string]int
	// The universe, split: keys in both runs, in A only, in the other only.
	Both, AOnly, OtherOnly int
}

func newProvDir() *provDir {
	return &provDir{Outcome: map[provKey]int{}, NoVerdict: map[provKey]int{}, Undecided: map[provKey]int{},
		RouteObj: map[provKey]int{}, CommonRouteObj: map[provKey]int{}, RPKIYesNo: map[string]int{}, RPKIAccRej: map[string]int{}}
}

// Universe is the number of route keys compared.
func (d *provDir) Universe() int { return d.Both + d.AOnly + d.OtherOnly }

// add adds e's counts to d.
func (d *provDir) add(e *provDir) {
	for _, mm := range [][2]map[provKey]int{{d.Outcome, e.Outcome}, {d.NoVerdict, e.NoVerdict}, {d.Undecided, e.Undecided}, {d.RouteObj, e.RouteObj}, {d.CommonRouteObj, e.CommonRouteObj}} {
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
	check("yes → no over the pairs both runs checked", d.CommonRouteObj[provKey{"yes", "no"}], d.RouteObj[provKey{"yes", "no"}])
	return errs
}

// provTally is the comparison of run A with another run, per direction
// ("import", "export"), and the self-check's import route-object matrix over
// the pairs it is taken on (over provRouteObjs, route by route, as RouteObj).
type provTally struct {
	Dirs           map[string]*provDir
	SubsetRouteObj map[provKey]int
	// Pairs is each pair's figures, both directions added, by pair id.
	Pairs map[string]provPairFig
	// AccRej counts the accepted → rejected routes by report: pair,
	// direction and neighbour, "|"-joined.
	AccRej map[string]int
}

// provPairFig is one pair's figures: A's route-object "yes" answered in both
// runs (yes → yes or yes → no), how many of them go yes → no, and its
// accepted → rejected routes.
type provPairFig struct{ Answered, YesNo, AccRej int }

func newProvTally() *provTally {
	return &provTally{Dirs: map[string]*provDir{"import": newProvDir(), "export": newProvDir()}, SubsetRouteObj: map[provKey]int{},
		Pairs: map[string]provPairFig{}, AccRej: map[string]int{}}
}

// provAnsweredYes is A's route-object "yes" answered in both runs in a
// route-object matrix: yes → yes plus yes → no. It is the denominator of the
// published yes → no shares.
func provAnsweredYes(m map[provKey]int) int {
	return m[provKey{"yes", "yes"}] + m[provKey{"yes", "no"}]
}

// provConc is how concentrated the comparison is over the pairs: the pairs
// with the most answered yes, the median pair's yes → no share, the share
// without those pairs, and the report with the most accepted → rejected.
type provConc struct {
	// Top is the pairs with the most answered yes, most first (ties by id);
	// TopAnswered is their answered yes, Answered every pair's.
	Top                   []string
	TopAnswered, Answered int
	// Pairs is the number of pairs with an answered yes, and Median the
	// median of their yes → no shares, in percent: with an even number, the
	// mean of the middle two.
	Pairs  int
	Median float64
	// RestYesNo and RestAnswered are the yes → no and answered yes of the
	// pairs not in Top.
	RestYesNo, RestAnswered int
	// MaxReport is the report with the most accepted → rejected (ties by id),
	// MaxAccRej its count, AccRej every report's, and AccRejPairs the number of
	// pairs with any.
	MaxReport                      string
	MaxAccRej, AccRej, AccRejPairs int
}

// provConcOf reads t's per-pair and per-report figures, with the top pairs
// by answered yes.
func provConcOf(t *provTally, top int) provConc {
	var c provConc
	ids := slices.Sorted(maps.Keys(t.Pairs))
	byAnswered := slices.Clone(ids)
	slices.SortStableFunc(byAnswered, func(x, y string) int { return t.Pairs[y].Answered - t.Pairs[x].Answered })
	c.Top = byAnswered[:min(top, len(byAnswered))]
	var shares []float64
	for _, id := range ids {
		f := t.Pairs[id]
		c.Answered += f.Answered
		if slices.Contains(c.Top, id) {
			c.TopAnswered += f.Answered
		} else {
			c.RestYesNo += f.YesNo
			c.RestAnswered += f.Answered
		}
		if f.Answered > 0 {
			shares = append(shares, 100*float64(f.YesNo)/float64(f.Answered))
		}
		if f.AccRej > 0 {
			c.AccRejPairs++
		}
	}
	c.Pairs = len(shares)
	if n := len(shares); n > 0 {
		slices.Sort(shares)
		c.Median = shares[n/2]
		if n%2 == 0 {
			c.Median = (shares[n/2-1] + shares[n/2]) / 2
		}
	}
	for _, r := range slices.Sorted(maps.Keys(t.AccRej)) {
		c.AccRej += t.AccRej[r]
		if t.AccRej[r] > c.MaxAccRej {
			c.MaxReport, c.MaxAccRej = r, t.AccRej[r]
		}
	}
	return c
}

// SubsetAYes is A's import route-object "yes" answers over the self-check's
// pairs: the figure that must be 1,568,538.
func (t *provTally) SubsetAYes() int { return rowSum(t.SubsetRouteObj, "yes") }

// SubsetYesNo is the self-check's import routes whose route object is "yes"
// in A and "no" in the other run: the part of the old rise that rests on the
// route objects the other run lacks. A route with no answer in one run
// ("unknown" or "no verdict") is not in it.
func (t *provTally) SubsetYesNo() int { return t.SubsetRouteObj[provKey{"yes", "no"}] }

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
// counts in the self-check's import route-object matrix.
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
		if aStatus == "checked" && bStatus == "checked" {
			d.CommonRouteObj[provKey{sa, sb}]++
		}
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
		pair, _, _ := strings.Cut(key, "|")
		fig := t.Pairs[pair]
		if sa == "yes" && (sb == "yes" || sb == "no") {
			fig.Answered++
			if sb == "no" {
				fig.YesNo++
			}
		}
		if oa == provAccepted && ob == provRejected {
			d.RPKIAccRej[ra.RPKI]++
			f := strings.Split(key, "|")
			if len(f) < 4 {
				return fmt.Errorf("key %q: no neighbour field", key)
			}
			t.AccRej[f[0]+"|"+f[1]+"|"+f[3]]++
			fig.AccRej++
		}
		t.Pairs[pair] = fig
		if subset50 && dir == "import" {
			t.SubsetRouteObj[provKey{sa, sb}]++
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

// logProvStates logs an RPKI table, sorted by state, each state with its
// share of the sum.
func logProvStates(t *testing.T, title string, m map[string]int) {
	t.Logf("  %s, sum %d:", title, sumCells(m))
	for _, s := range slices.Sorted(maps.Keys(m)) {
		t.Logf("    %-12s %d (%s)", s, m[s], provShare(m[s], sumCells(m)))
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
	yesNo, aYes := d.RouteObj[provKey{"yes", "no"}], rowSum(d.RouteObj, "yes")
	t.Logf("  route object yes → no: %d, %s of A's %d yes", yesNo, provShare(yesNo, aYes), aYes)
	ans := provAnsweredYes(d.RouteObj)
	t.Logf("  route object yes → no over the routes answered in both runs: %d of A's %d yes there (yes → yes + yes → no), %s",
		yesNo, ans, provShare(yesNo, ans))
	logProvStates(t, "RPKI (A's) of route object yes → no", d.RPKIYesNo)
	accRej := d.Outcome[provKey{provAccepted, provRejected}]
	t.Logf("  accepted → rejected: %d, %s of the %d routes in both runs", accRej, provShare(accRej, d.Both), d.Both)
	logProvStates(t, "RPKI (A's) of accepted → rejected", d.RPKIAccRej)
	tot := provTotalsOf(d)
	t.Logf("  totals only, over the pairs both runs checked: A's yes %d - %s's yes %d = %d; route by route yes → no %d; equal: %v",
		tot.AYes, other, tot.OtherYes, tot.AYes-tot.OtherYes, tot.YesNo, tot.AYes-tot.OtherYes == tot.YesNo)
	t.Logf("  route-object denominators (yes + no) over the pairs both runs checked: A %d, %s %d", tot.ADen, other, tot.OtherDen)
	if tot.ADen != tot.OtherDen {
		t.Logf("  the denominators differ: the totals-only shortcut does not apply (design, settled 2)")
	} else {
		t.Logf("  the denominators are equal: the totals-only shortcut applies and was checked")
	}
	if err := tot.check(name); err != nil {
		t.Error(err)
	}
	for _, e := range d.sumErrors() {
		t.Errorf("%s: %s", name, e)
	}
}

// logProvConc logs how concentrated the comparison is over the pairs (both
// directions added).
func logProvConc(t *testing.T, c provConc) {
	t.Logf("concentration, both directions, A's route-object yes answered in both runs:")
	t.Logf("  the %d pairs with the most (%s) hold %d of %d (%s)",
		len(c.Top), strings.Join(c.Top, ", "), c.TopAnswered, c.Answered, provShare(c.TopAnswered, c.Answered))
	t.Logf("  the median pair's yes → no share, over the %d pairs with an answered yes (even: the mean of the middle two): %.2f%%", c.Pairs, c.Median)
	t.Logf("  without those %d pairs: yes → no %d of %d (%s)", len(c.Top), c.RestYesNo, c.RestAnswered, provShare(c.RestYesNo, c.RestAnswered))
	t.Logf("  accepted → rejected: the report with the most (pair|direction|neighbour) %s has %d of %d (%s); %d pairs have at least one",
		c.MaxReport, c.MaxAccRej, c.AccRej, provShare(c.MaxAccRej, c.AccRej), c.AccRejPairs)
}

// provTotals is one direction's route-object figures over the pairs both runs
// checked: A's and the other run's "yes" answers, their denominators
// (yes + no), and the route-by-route yes → no count.
type provTotals struct{ AYes, OtherYes, ADen, OtherDen, YesNo int }

// provTotalsOf reads d's route-object matrix over the pairs both runs checked.
func provTotalsOf(d *provDir) provTotals {
	m := d.CommonRouteObj
	aYes, otherYes := rowSum(m, "yes"), colSum(m, "yes")
	return provTotals{
		AYes: aYes, OtherYes: otherYes,
		ADen: aYes + rowSum(m, "no"), OtherDen: otherYes + colSum(m, "no"),
		YesNo: m[provKey{"yes", "no"}],
	}
}

// check holds the totals-only shortcut to the route-by-route count (design,
// goal 2), over the pairs both runs checked: when both runs' denominators
// there are equal, A's yes minus the other run's must be the yes → no count,
// or the measurement fails. When they differ the shortcut does not apply and
// nothing is checked.
func (p provTotals) check(dir string) error {
	if p.ADen != p.OtherDen || p.AYes-p.OtherYes == p.YesNo {
		return nil
	}
	return fmt.Errorf("%s: the denominators are equal (%d) but the totals-only figure %d (A's yes %d - the other run's %d) is not the route-by-route yes → no %d",
		dir, p.ADen, p.AYes-p.OtherYes, p.AYes, p.OtherYes, p.YesNo)
}

// provSelfCheckPairs is the number of pairs the self-check is taken on: the
// 50 the every-registry and RIPE-only runs both checked.
const provSelfCheckPairs = 50

// parseProvExclude reads ROUTECHECK_PROVENANCE_EXCLUDE: pair ids separated by
// commas or white space. They must be distinct pairs of order, and exactly
// len(order) - 50 of them, so that the self-check keeps its 50 pairs.
func parseProvExclude(s string, order []string) (map[string]bool, error) {
	want := len(order) - provSelfCheckPairs
	exclude := map[string]bool{}
	for _, p := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || unicode.IsSpace(r) }) {
		if !slices.Contains(order, p) {
			return nil, fmt.Errorf("ROUTECHECK_PROVENANCE_EXCLUDE: %s is not a pair of the runs", p)
		}
		if exclude[p] {
			return nil, fmt.Errorf("ROUTECHECK_PROVENANCE_EXCLUDE: %s is given twice", p)
		}
		exclude[p] = true
	}
	if len(exclude) != want {
		return nil, fmt.Errorf("ROUTECHECK_PROVENANCE_EXCLUDE names %d pairs; the runs have %d, so %d must be excluded to leave the self-check's %d",
			len(exclude), len(order), want, provSelfCheckPairs)
	}
	return exclude, nil
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
	exclude, err := parseProvExclude(os.Getenv("ROUTECHECK_PROVENANCE_EXCLUDE"), order)
	if err != nil {
		t.Fatal(err)
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
		if err := comparePair(tl, am, bm, aStatus[p], bStatus[p], !exclude[p]); err != nil {
			return err
		}
		f := tl.Pairs[p]
		t.Logf("pair %s: A's route-object yes answered in both runs %d, yes → no %d (%s); accepted → rejected %d",
			p, f.Answered, f.YesNo, provShare(f.YesNo, f.Answered), f.AccRej)
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	both := 0
	for _, p := range order {
		if aStatus[p] == "checked" && bStatus[p] == "checked" {
			both++
		}
	}
	t.Logf("%d of %d pairs checked in both runs; the totals-only shortcut is taken over them", both, len(order))
	logProvDir(t, "import", label, tl.Dirs["import"])
	logProvDir(t, "export", label, tl.Dirs["export"])
	logProvDir(t, "total", label, tl.Total())
	logProvConc(t, provConcOf(tl, 3))

	n := len(order) - len(exclude)
	logProvMatrix(t, fmt.Sprintf("self-check, %d pairs: import route objects", n), label, provRouteObjs, tl.SubsetRouteObj)
	sub := func(a, b string) int { return tl.SubsetRouteObj[provKey{a, b}] }
	t.Logf("self-check, %d pairs: A's import route-object yes %d (want %d); yes → yes %d, yes → no %d, yes → unknown %d, yes → no verdict %d, unknown → yes %d",
		n, tl.SubsetAYes(), provEveryRegistryImportYes, sub("yes", "yes"), sub("yes", "no"), sub("yes", "unknown"), sub("yes", provNoVerdict), sub("unknown", "yes"))
	t.Logf("self-check, %d pairs: yes → no %d is %s of A's %d yes and %s of the old rise %d (%d to %d); routes without an answer in both runs are not in it",
		n, tl.SubsetYesNo(), provShare(tl.SubsetYesNo(), tl.SubsetAYes()), tl.SubsetAYes(),
		provShare(tl.SubsetYesNo(), provOldRise), provOldRise, provRIPEOnlyImportYes, provEveryRegistryImportYes)
	if tl.SubsetAYes() != provEveryRegistryImportYes {
		t.Errorf("self-check: A's import route-object yes over the %d pairs is %d, want %d", n, tl.SubsetAYes(), provEveryRegistryImportYes)
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
	if n := sumCells(tl.SubsetRouteObj); tl.SubsetAYes() != 1 || tl.SubsetYesNo() != 1 || n != 3 {
		t.Errorf("self-check: A's import yes %d, yes → no %d, %d import routes; want 1, 1, 3 (%v)", tl.SubsetAYes(), tl.SubsetYesNo(), n, tl.SubsetRouteObj)
	}
	tl2 := newProvTally()
	if err := comparePair(tl2, a, b, "checked", "checked", false); err != nil {
		t.Fatal(err)
	}
	if len(tl2.SubsetRouteObj) != 0 {
		t.Errorf("an excluded pair counts in the self-check: %v", tl2.SubsetRouteObj)
	}
}

func TestCompareSelfCheck(t *testing.T) {
	const k1, k2 = "AS1-AS2|import|ipv4|AS1|10.0.0.0/24|AS1", "AS3-AS4|import|ipv4|AS3|10.0.1.0/24|AS3"
	tl := newProvTally()
	// k1: yes → no, both pairs checked: it rests on the route objects the
	// other run lacks.
	if err := comparePair(tl, map[string]provRoute{k1: provR("accepted", "yes", "valid", "")},
		map[string]provRoute{k1: provR("accepted", "no", "valid", "")}, "checked", "checked", true); err != nil {
		t.Fatal(err)
	}
	// k2: yes → no verdict, the other run's pair timed out: no answer there,
	// so it is not in the share.
	if err := comparePair(tl, map[string]provRoute{k2: provR("accepted", "yes", "valid", "")}, nil, "checked", "timeout", true); err != nil {
		t.Fatal(err)
	}
	if tl.SubsetAYes() != 2 || tl.SubsetYesNo() != 1 || tl.SubsetRouteObj[provKey{"yes", provNoVerdict}] != 1 {
		t.Errorf("A's yes %d, yes → no %d, yes → no verdict %d; want 2, 1, 1", tl.SubsetAYes(), tl.SubsetYesNo(), tl.SubsetRouteObj[provKey{"yes", provNoVerdict}])
	}
}

func TestCompareTotalsOnly(t *testing.T) {
	// A's yes is 1 and the other's 0, with equal denominators (1 and 1), but no
	// route goes yes → no: one goes yes → unknown, another unknown → no.
	d := newProvDir()
	d.CommonRouteObj[provKey{"yes", "unknown"}] = 1
	d.CommonRouteObj[provKey{"unknown", "no"}] = 1
	err := provTotalsOf(d).check("import")
	if err == nil || !strings.Contains(err.Error(), "import") || !strings.Contains(err.Error(), "totals-only figure 1") || !strings.Contains(err.Error(), "yes → no 0") {
		t.Errorf("equal denominators, totals-only 1, route by route 0: %v, want an error naming import and both figures", err)
	}
	// Agreeing: yes → no 1 and yes → yes 1; denominators 2 and 2, totals-only
	// 2 - 1 = 1, yes → no 1.
	agree := newProvDir()
	agree.CommonRouteObj[provKey{"yes", "no"}] = 1
	agree.CommonRouteObj[provKey{"yes", "yes"}] = 1
	if err := provTotalsOf(agree).check("import"); err != nil {
		t.Errorf("agreeing figures: %v", err)
	}
	// Unequal denominators (1 and 2): the shortcut does not apply, whatever
	// the figures.
	d.CommonRouteObj[provKey{provNoVerdict, "no"}] = 1
	if p := provTotalsOf(d); p.ADen == p.OtherDen {
		t.Fatalf("denominators %d and %d, want them unequal", p.ADen, p.OtherDen)
	}
	if err := provTotalsOf(d).check("export"); err != nil {
		t.Errorf("unequal denominators: %v, want no check", err)
	}
}

func TestCompareTotalsOnlyCommonPairs(t *testing.T) {
	// AS1-AS2 is checked in both runs: one route goes yes → unknown, another
	// unknown → no, so A's yes 1 - the other's 0 = 1, but no route goes
	// yes → no; its denominators are 1 and 1. AS3-AS4 is checked in A only (the
	// other run timed out): its yes → no verdict makes the denominators over
	// every pair unequal (2 and 1). The shortcut is taken over AS1-AS2 alone,
	// where it fails.
	const k1, k2, k3 = "AS1-AS2|import|ipv4|AS2|10.0.0.0/24|AS2", "AS1-AS2|import|ipv4|AS2|10.0.1.0/24|AS2", "AS3-AS4|import|ipv4|AS4|10.0.2.0/24|AS4"
	tl := newProvTally()
	if err := comparePair(tl, map[string]provRoute{k1: provR("accepted", "yes", "valid", ""), k2: provR("accepted", "unknown", "valid", "")},
		map[string]provRoute{k1: provR("accepted", "unknown", "valid", ""), k2: provR("rejected", "no", "valid", "")}, "checked", "checked", false); err != nil {
		t.Fatal(err)
	}
	if err := comparePair(tl, map[string]provRoute{k3: provR("accepted", "yes", "valid", "")}, nil, "checked", "timeout", false); err != nil {
		t.Fatal(err)
	}
	d := tl.Dirs["import"]
	p := provTotalsOf(d)
	if p.ADen != 1 || p.OtherDen != 1 || p.AYes != 1 || p.OtherYes != 0 || p.YesNo != 0 {
		t.Errorf("over the pairs both runs checked: A's yes %d of %d, the other's %d of %d, yes → no %d; want 1 of 1, 0 of 1, 0",
			p.AYes, p.ADen, p.OtherYes, p.OtherDen, p.YesNo)
	}
	err := p.check("import")
	if err == nil || !strings.Contains(err.Error(), "totals-only figure 1") || !strings.Contains(err.Error(), "yes → no 0") {
		t.Errorf("disagreeing over the common pair: %v, want an error naming both figures", err)
	}

	// Agreeing over AS1-AS2 (yes → no and yes → yes), with AS3-AS4's yes →
	// no verdict outside: totals-only 2 - 1 = 1, yes → no 1.
	ok := newProvTally()
	if err := comparePair(ok, map[string]provRoute{k1: provR("accepted", "yes", "valid", ""), k2: provR("accepted", "yes", "valid", "")},
		map[string]provRoute{k1: provR("accepted", "yes", "valid", ""), k2: provR("rejected", "no", "valid", "")}, "checked", "checked", false); err != nil {
		t.Fatal(err)
	}
	if err := comparePair(ok, map[string]provRoute{k3: provR("accepted", "yes", "valid", "")}, nil, "checked", "timeout", false); err != nil {
		t.Fatal(err)
	}
	if p := provTotalsOf(ok.Dirs["import"]); p.ADen != 2 || p.OtherDen != 2 || p.check("import") != nil {
		t.Errorf("agreeing over the common pair: denominators %d and %d, check %v; want 2, 2, nil", p.ADen, p.OtherDen, p.check("import"))
	}
}

func TestCompareExclude(t *testing.T) {
	var order []string
	for i := range 60 {
		order = append(order, fmt.Sprintf("AS%d-AS%d", i+1, i+100))
	}
	ten := strings.Join(order[:10], " ")
	ex, err := parseProvExclude(strings.Join(order[:5], ",")+"\n\t"+strings.Join(order[5:10], ", "), order)
	if err != nil || len(ex) != 10 || !ex[order[0]] || !ex[order[9]] || ex[order[10]] {
		t.Errorf("10 ids, commas and white space: %v, %v", ex, err)
	}
	for _, tc := range []struct{ name, s, wantErr string }{
		{"nine", strings.Join(order[:9], " "), "names 9 pairs"},
		{"a duplicate", ten + " " + order[3], order[3] + " is given twice"},
		{"not in the order", strings.Join(order[:9], " ") + " AS9-AS9", "AS9-AS9 is not a pair"},
		{"none", "", "names 0 pairs"},
	} {
		if _, err := parseProvExclude(tc.s, order); err == nil || !strings.Contains(err.Error(), tc.wantErr) {
			t.Errorf("%s: %v, want an error with %q", tc.name, err, tc.wantErr)
		}
	}
}

func TestCompareSumErrors(t *testing.T) {
	const key = "AS1-AS2|import|ipv4|AS1|10.0.0.0/24|AS1"
	tl := newProvTally()
	if err := comparePair(tl, map[string]provRoute{key: provR("undecided", "yes", "valid", "peval")},
		map[string]provRoute{key: provR("rejected", "no", "valid", "")}, "checked", "checked", false); err != nil {
		t.Fatal(err)
	}
	d := tl.Dirs["import"]
	if errs := d.sumErrors(); len(errs) > 0 {
		t.Fatalf("before the change: %v", errs)
	}
	for _, tc := range []struct {
		name    string
		change  func(*provDir)
		wantErr string
	}{
		{"an extra outcome cell", func(d *provDir) { d.Outcome[provKey{provAccepted, provAccepted}]++ }, "outcome matrix"},
		{"an extra route-object cell", func(d *provDir) { d.RouteObj[provKey{"no", "no"}]++ }, "route-object matrix"},
		{"an undecided reason missing", func(d *provDir) { d.Undecided = map[provKey]int{} }, "undecided reasons"},
		{"an RPKI state missing", func(d *provDir) { d.RPKIYesNo = map[string]int{} }, "yes → no"},
		{"a universe count off", func(d *provDir) { d.AOnly++ }, "sums to"},
	} {
		c := newProvDir()
		c.add(d)
		tc.change(c)
		errs := c.sumErrors()
		if len(errs) == 0 || !strings.Contains(strings.Join(errs, "; "), tc.wantErr) {
			t.Errorf("%s: %v, want an error naming %q", tc.name, errs, tc.wantErr)
		}
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

func TestCompareByPair(t *testing.T) {
	// A's route-object yes answered in both runs (yes → yes, yes → no) counts
	// per pair over both directions; yes → no verdict and yes → unknown do not.
	// accepted → rejected counts per report: pair, direction, neighbour.
	tl := newProvTally()
	a := map[string]provRoute{
		"AS1-AS2|import|ipv4|AS2|10.0.0.0/24|AS2":   provR("accepted", "yes", "valid", ""),
		"AS1-AS2|export|ipv4|AS9|10.0.1.0/24|AS2":   provR("accepted", "yes", "valid", ""),
		"AS1-AS2|export|ipv6|AS9|2001:db8::/32|AS2": provR("accepted", "yes", "valid", ""),
		"AS1-AS2|export|ipv4|AS8|10.0.2.0/24|AS2":   provR("accepted", "yes", "valid", ""),
		"AS1-AS2|import|ipv4|AS2|10.0.3.0/24|AS2":   provR("accepted", "yes", "valid", ""),
		"AS1-AS2|import|ipv4|AS2|10.0.4.0/24|AS2":   provR("accepted", "yes", "valid", ""),
	}
	b := map[string]provRoute{
		"AS1-AS2|import|ipv4|AS2|10.0.0.0/24|AS2":   provR("accepted", "yes", "valid", ""),
		"AS1-AS2|export|ipv4|AS9|10.0.1.0/24|AS2":   provR("rejected", "no", "valid", ""),
		"AS1-AS2|export|ipv6|AS9|2001:db8::/32|AS2": provR("rejected", "no", "valid", ""),
		"AS1-AS2|export|ipv4|AS8|10.0.2.0/24|AS2":   provR("rejected", "no", "valid", ""),
		"AS1-AS2|import|ipv4|AS2|10.0.4.0/24|AS2":   provR("accepted", "unknown", "valid", ""),
	}
	if err := comparePair(tl, a, b, "checked", "checked", false); err != nil {
		t.Fatal(err)
	}
	if got, want := tl.Pairs["AS1-AS2"], (provPairFig{Answered: 4, YesNo: 3, AccRej: 3}); got != want {
		t.Errorf("AS1-AS2: %+v, want %+v", got, want)
	}
	if got, want := fmt.Sprint(tl.AccRej), "map[AS1-AS2|export|AS8:1 AS1-AS2|export|AS9:2]"; got != want {
		t.Errorf("accepted → rejected by report: %s, want %s", got, want)
	}
	if n := provAnsweredYes(tl.Total().RouteObj); n != 4 {
		t.Errorf("answered yes over both directions: %d, want 4", n)
	}
	if n := provAnsweredYes(tl.Dirs["import"].RouteObj); n != 1 {
		t.Errorf("answered yes on import: %d, want 1", n)
	}
}

func TestProvConcentration(t *testing.T) {
	tl := newProvTally()
	tl.Pairs = map[string]provPairFig{
		"AS1-AS1": {Answered: 100, YesNo: 50, AccRej: 1},
		"AS2-AS2": {Answered: 80, YesNo: 0},
		"AS3-AS3": {Answered: 80, YesNo: 40}, // ties AS2-AS2: by id, AS2-AS2 is in the top
		"AS4-AS4": {Answered: 10, YesNo: 5, AccRej: 2},
		"AS5-AS5": {Answered: 10, YesNo: 0},
		"AS6-AS6": {Answered: 0, YesNo: 0, AccRej: 0}, // no answered yes: not in the median
	}
	tl.AccRej = map[string]int{"AS1-AS1|export|AS7": 1, "AS4-AS4|export|AS8": 2}
	c := provConcOf(tl, 2)
	if got, want := fmt.Sprint(c.Top), "[AS1-AS1 AS2-AS2]"; got != want {
		t.Errorf("top: %s, want %s", got, want)
	}
	if c.TopAnswered != 180 || c.Answered != 280 || c.Pairs != 5 {
		t.Errorf("top %d of %d over %d pairs; want 180 of 280 over 5", c.TopAnswered, c.Answered, c.Pairs)
	}
	// Shares 50, 0, 50, 50, 0: sorted 0, 0, 50, 50, 50; median 50.
	if c.Median != 50 {
		t.Errorf("median %v, want 50", c.Median)
	}
	if c.RestYesNo != 45 || c.RestAnswered != 100 {
		t.Errorf("without the top: %d of %d, want 45 of 100", c.RestYesNo, c.RestAnswered)
	}
	if c.MaxReport != "AS4-AS4|export|AS8" || c.MaxAccRej != 2 || c.AccRej != 3 || c.AccRejPairs != 2 {
		t.Errorf("accepted → rejected: most %s %d of %d, %d pairs; want AS4-AS4|export|AS8 2 of 3, 2 pairs", c.MaxReport, c.MaxAccRej, c.AccRej, c.AccRejPairs)
	}
	// An even count: the mean of the middle two.
	delete(tl.Pairs, "AS5-AS5")
	tl.Pairs["AS4-AS4"] = provPairFig{Answered: 10, YesNo: 1, AccRej: 2}
	if c := provConcOf(tl, 2); c.Median != 30 {
		t.Errorf("even count (shares 0, 10, 50, 50): median %v, want 30", c.Median)
	}
}
