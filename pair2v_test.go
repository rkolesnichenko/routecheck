package routecheck_test

import (
	"bufio"
	"compress/gzip"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// vrLine is one 5-field routes.tsv.gz line: key, outcome, route object, RPKI, detail.
func vrLine(key, outcome, obj string) string {
	return key + "\t" + outcome + "\t" + obj + "\tvalid\t"
}

const (
	vrK6    = "AS1-AS2|export|ipv6.unicast|AS3|2001:db8::/32|AS3 AS4"
	vrK4a   = "AS1-AS2|export|ipv4.unicast|AS3|192.0.2.0/24|AS3"
	vrK4b   = "AS1-AS2|export|ipv4.unicast|AS3|198.51.100.0/24|AS3"
	vrKImp  = "AS1-AS2|import|ipv4.unicast|AS2|203.0.113.0/24|AS2"
	vrK4c   = "AS1-AS2|export|ipv4.unicast|AS3|10.0.0.0/8|AS3"
	vrK4d   = "AS1-AS2|export|ipv4.unicast|AS3|10.1.0.0/16|AS3"
	vrKROnl = "AS1-AS2|export|ipv4.unicast|AS3|10.2.0.0/16|AS3"
)

func TestJoinVR(t *testing.T) {
	dir := t.TempDir()
	vPath, rPath, aPath := filepath.Join(dir, "v.gz"), filepath.Join(dir, "r.gz"), filepath.Join(dir, "a.gz")
	writeGz(t, vPath,
		vrLine(vrK6, "rejected", "yes"),
		vrLine(vrK4a, "rejected", "no"),
		vrLine(vrK4b, "accepted", "yes"),
		vrLine(vrKImp, "accepted", "no"),
		vrLine(vrK4c, "accepted", "yes"),
		vrLine(vrK4d, "rejected", "no"),
	)
	writeGz(t, rPath,
		vrLine(vrK6, "accepted", "yes"),
		vrLine(vrK4a, "rejected", "no"),
		vrLine(vrK4b, "accepted", "yes"),
		vrLine(vrKImp, "accepted", "no"),
		vrLine(vrK4c, "rejected", "yes"),
		vrLine(vrK4d, "rejected", "yes"),
		vrLine(vrKROnl, "accepted", "no"),
	)
	writeGz(t, aPath,
		vrLine(vrK6, "accepted", "yes"),
		vrLine(vrK4a, "undecided", "no"),
		vrLine("AS5-AS6|export|ipv4.unicast|AS7|192.0.2.0/24|AS7", "rejected", "no"),
	)
	j, err := joinVR(vPath, rPath, aPath, "AS1-AS2")
	if err != nil {
		t.Fatal(err)
	}
	want := map[vrCell]int{
		{"ipv4.unicast", "no", "", "rejected"}:          1, // 10.1.0.0/16, not in A
		{"ipv4.unicast", "no", "undecided", "rejected"}: 1,
		{"ipv6.unicast", "yes", "accepted", "accepted"}: 1,
	}
	if !maps.Equal(j.Cells, want) {
		t.Errorf("Cells = %v, want %v", j.Cells, want)
	}
	if !slices.Equal(j.Rescued, []string{vrK6}) {
		t.Errorf("Rescued = %q", j.Rescued)
	}
	if j.AccRej != 1 {
		t.Errorf("AccRej = %d, want 1", j.AccRej)
	}
	acc := map[string]int{"accepted": 1}
	if !maps.Equal(j.ImportV, acc) || !maps.Equal(j.ImportR, acc) {
		t.Errorf("ImportV = %v, ImportR = %v, want %v", j.ImportV, j.ImportR, acc)
	}
	if j.VOnly != nil {
		t.Errorf("VOnly = %q, want nil", j.VOnly)
	}
	if !slices.Equal(j.ROnly, []string{vrKROnl}) {
		t.Errorf("ROnly = %q", j.ROnly)
	}
	if !slices.Equal(j.ObjDiffer, []string{vrK4d}) {
		t.Errorf("ObjDiffer = %q", j.ObjDiffer)
	}
	if !slices.Equal(j.NotInA, []string{vrK4d}) {
		t.Errorf("NotInA = %q", j.NotInA)
	}

	var sb strings.Builder
	if err := writeVRCross(&sb, j); err != nil {
		t.Fatal(err)
	}
	wantTable := "family\troute object\tA\tR\troutes\n" +
		"ipv4.unicast\tno\t\trejected\t1\n" +
		"ipv4.unicast\tno\tundecided\trejected\t1\n" +
		"ipv6.unicast\tyes\taccepted\taccepted\t1\n" +
		"sum\t\t\t\t3\n"
	if sb.String() != wantTable {
		t.Errorf("table:\n%s\nwant:\n%s", sb.String(), wantTable)
	}
}

func TestJoinVRErrors(t *testing.T) {
	good := []string{
		vrLine(vrK6, "rejected", "yes"),
		vrLine(vrK4a, "accepted", "no"),
	}
	cases := []struct {
		name string
		v, r []string
		cut  bool // cut R's file to half its gzip bytes
		want func(v, r string) string
	}{
		{"short line in V", []string{"AS1-AS2|export|ipv4.unicast|AS3|192.0.2.0/24|AS3\trejected\tno\tvalid"}, good, false,
			func(v, r string) string { return v + ":1" }},
		{"duplicate key in R", good, append(slices.Clone(good), good[0]), false,
			func(v, r string) string { return vrK6 }},
		{"other pair in V", append(slices.Clone(good), vrLine("AS5-AS6|export|ipv4.unicast|AS7|192.0.2.0/24|AS7", "rejected", "no")), good, false,
			func(v, r string) string { return "AS5-AS6" }},
		{"truncated R", good, manyVRLines(5000), true,
			func(v, r string) string { return r }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			v, r, a := filepath.Join(dir, "v.gz"), filepath.Join(dir, "r.gz"), filepath.Join(dir, "a.gz")
			writeGz(t, v, c.v...)
			writeGz(t, r, c.r...)
			writeGz(t, a)
			if c.cut {
				b, err := os.ReadFile(r)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(r, b[:len(b)/2], 0o644); err != nil {
					t.Fatal(err)
				}
			}
			_, err := joinVR(v, r, a, "AS1-AS2")
			if err == nil {
				t.Fatal("no error")
			}
			if w := c.want(v, r); !strings.Contains(err.Error(), w) {
				t.Errorf("error %q does not contain %q", err, w)
			}
		})
	}
}

// manyVRLines is n distinct export lines of pair AS1-AS2, enough gzip bytes
// that half of them still cut a stream in the middle.
func manyVRLines(n int) []string {
	out := make([]string, 0, n)
	for i := range n {
		key := "AS1-AS2|export|ipv4.unicast|AS3|10." + strconv.Itoa(i/256) + "." + strconv.Itoa(i%256) + ".0/24|AS3"
		out = append(out, vrLine(key, "accepted", "no"))
	}
	return out
}

// vrBase is a hand-built join that meets vrBaseWant.
func vrBase() *vrJoin {
	return &vrJoin{
		Cells: map[vrCell]int{
			{"ipv4.unicast", "yes", "undecided", "accepted"}: 2,
			{"ipv4.unicast", "no", "undecided", "rejected"}:  3,
			{"ipv6.unicast", "yes", "accepted", "accepted"}:  1,
			{"ipv6.unicast", "yes", "accepted", "rejected"}:  1,
			{"ipv6.unicast", "no", "rejected", "rejected"}:   4,
		},
		Rescued: []string{"k1", "k2", "k3"},
		ImportV: map[string]int{"accepted": 5},
		ImportR: map[string]int{"accepted": 5},
	}
}

var vrBaseWant = vrWant{VRejected: 11, RRejected: 8, Rescued4: 2, Kept4: 3,
	Rescued6: 1, Kept6: 1, ARejected6: 4, ImportAccepted: 5}

func TestVRControls(t *testing.T) {
	if errs := vrBase().controlErrors(vrBaseWant); len(errs) != 0 {
		t.Fatalf("clean join: %q", errs)
	}
	cases := []struct {
		name   string
		mutate func(j *vrJoin)
		names  string // a substring the error list must contain
	}{
		{"AccRej", func(j *vrJoin) { j.AccRej = 1 }, "AccRej"},
		{"ROnly", func(j *vrJoin) { j.ROnly = []string{"x"} }, "ROnly"},
		{"ObjDiffer", func(j *vrJoin) { j.ObjDiffer = []string{"x"} }, "ObjDiffer"},
		{"NotInA", func(j *vrJoin) { j.NotInA = []string{"x"} }, "NotInA"},
		{"VOnly", func(j *vrJoin) { j.VOnly = []string{"x"} }, "VOnly"},
		{"ipv4 A accepted", func(j *vrJoin) {
			j.Cells[vrCell{"ipv4.unicast", "yes", "accepted", "accepted"}] = 1
		}, "ipv4 A"},
		{"ipv6 A rejected R accepted", func(j *vrJoin) {
			j.Cells[vrCell{"ipv6.unicast", "yes", "rejected", "accepted"}] = 1
		}, "ipv6 A"},
		{"ImportR", func(j *vrJoin) { j.ImportR = map[string]int{"accepted": 5, "rejected": 1} }, "ImportR"},
		{"Rescued4", func(j *vrJoin) {
			j.Cells[vrCell{"ipv4.unicast", "yes", "undecided", "accepted"}] = 3
		}, "Rescued4"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			j := vrBase()
			c.mutate(j)
			errs := j.controlErrors(vrBaseWant)
			if !slices.ContainsFunc(errs, func(e string) bool { return strings.Contains(e, c.names) }) {
				t.Errorf("errors %q do not name %q", errs, c.names)
			}
		})
	}
}

// vrCell is one cell of the cross table over pair 2's export routes rejected in V.
type vrCell struct {
	Family string // the key's 3rd field: "ipv4.unicast" or "ipv6.unicast"
	Obj    string // V's route-object answer (equal to R's when the controls hold)
	A      string // A's outcome: accepted, rejected or undecided; "" when A's file lacks the key
	R      string // R's outcome
}

type vrJoin struct {
	Cells     map[vrCell]int
	Rescued   []string       // export keys rejected in V and accepted in R, sorted
	AccRej    int            // export keys accepted in V and rejected in R
	ImportV   map[string]int // import keys by V's outcome
	ImportR   map[string]int // import keys by R's outcome
	VOnly     []string       // keys in V's file only (any direction), sorted
	ROnly     []string       // keys in R's file only, sorted
	ObjDiffer []string       // keys whose route-object answer differs between V and R, sorted
	NotInA    []string       // export keys rejected in V that A's file lacks, sorted
}

// vrEntry is V's answer for one key, as indexes into provOutcomes and
// provRouteObjs (two strings per key would cost 2.6M × 32 bytes more).
type vrEntry struct {
	out, obj uint8
	seen     bool // R had the key
}

// forGzLines streams a gzip file's lines (without their newline) to fn with
// their numbers. Errors name the file and line.
func forGzLines(path string, fn func(n int, line string) error) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	z, err := gzip.NewReader(f)
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	r := bufio.NewReaderSize(z, 1<<20)
	for n := 1; ; n++ {
		line, err := r.ReadString('\n')
		if err != nil && err != io.EOF {
			return fmt.Errorf("%s:%d: %w", path, n, err)
		}
		if line == "" && err == io.EOF {
			return nil
		}
		if e := fn(n, strings.TrimSuffix(line, "\n")); e != nil {
			return fmt.Errorf("%s:%d: %w", path, n, e)
		}
		if err == io.EOF {
			return nil
		}
	}
}

// vrFamily is the key's 3rd "|" field.
func vrFamily(key string) string {
	f := strings.SplitN(key, "|", 4)
	if len(f) < 4 {
		return ""
	}
	return f[2]
}

// joinVR reads V's and R's routes.tsv.gz (pair's lines only; any other pair is an
// error), and A's (other pairs skipped).
func joinVR(vPath, rPath, aPath, pair string) (*vrJoin, error) {
	outs, objs := provOutcomes[:3], provRouteObjs[:3]
	vAns := make(map[string]vrEntry, 2_700_000)
	err := forGzLines(vPath, func(n int, line string) error {
		p, key, r, err := parseProvLine(line)
		if err != nil {
			return err
		}
		if p != pair {
			return fmt.Errorf("key %q: pair %q is not %q", key, p, pair)
		}
		if _, dup := vAns[key]; dup {
			return fmt.Errorf("key %q is in the file twice", key)
		}
		vAns[strings.Clone(key)] = vrEntry{out: uint8(slices.Index(outs, r.Outcome)), obj: uint8(slices.Index(objs, r.RouteObj))}
		return nil
	})
	if err != nil {
		return nil, err
	}

	j := &vrJoin{Cells: map[vrCell]int{}, ImportV: map[string]int{}, ImportR: map[string]int{}}
	rOf := map[string]string{} // R's outcome for each export key rejected in V
	err = forGzLines(rPath, func(n int, line string) error {
		p, key, r, err := parseProvLine(line)
		if err != nil {
			return err
		}
		if p != pair {
			return fmt.Errorf("key %q: pair %q is not %q", key, p, pair)
		}
		v, ok := vAns[key]
		if !ok {
			j.ROnly = append(j.ROnly, strings.Clone(key))
			return nil
		}
		if v.seen {
			return fmt.Errorf("key %q is in the file twice", key)
		}
		v.seen = true
		vAns[key] = v
		if objs[v.obj] != r.RouteObj {
			j.ObjDiffer = append(j.ObjDiffer, strings.Clone(key))
		}
		dir, _ := provDirOf(key)
		vOut := outs[v.out]
		switch {
		case dir == "import":
			j.ImportV[vOut]++
			j.ImportR[r.Outcome]++
		case vOut == "rejected":
			rOf[strings.Clone(key)] = r.Outcome
			if r.Outcome == "accepted" {
				j.Rescued = append(j.Rescued, strings.Clone(key))
			}
		case vOut == "accepted" && r.Outcome == "rejected":
			j.AccRej++
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	for key, v := range vAns {
		if !v.seen {
			j.VOnly = append(j.VOnly, key)
		}
	}

	aOf := make(map[string]string, len(rOf)) // A's outcome for those keys
	err = forGzLines(aPath, func(n int, line string) error {
		if p, _, _ := strings.Cut(line, "|"); p != pair {
			return nil
		}
		_, key, r, err := parseProvLine(line)
		if err != nil {
			return err
		}
		if _, ok := rOf[key]; ok {
			if _, dup := aOf[key]; dup {
				return fmt.Errorf("key %q is in the file twice", key)
			}
			aOf[strings.Clone(key)] = r.Outcome
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	for key, rOut := range rOf {
		v := vAns[key]
		a, ok := aOf[key]
		if !ok {
			j.NotInA = append(j.NotInA, key)
		}
		j.Cells[vrCell{Family: vrFamily(key), Obj: objs[v.obj], A: a, R: rOut}]++
	}
	for _, s := range [][]string{j.Rescued, j.VOnly, j.ROnly, j.ObjDiffer, j.NotInA} {
		slices.Sort(s)
	}
	return j, nil
}

type vrWant struct {
	VRejected, RRejected int // export
	Rescued4, Kept4      int // ipv4: A undecided; R accepted, R rejected
	Rescued6, Kept6      int // ipv6, A accepted: R accepted, R rejected
	ARejected6           int // ipv6, A rejected: R rejected
	ImportAccepted       int // in V and in R, nothing else
}

// controlErrors lists every control that fails, empty when all hold.
func (j *vrJoin) controlErrors(w vrWant) []string {
	var errs []string
	check := func(name string, want, got int) {
		if want != got {
			errs = append(errs, fmt.Sprintf("%s: want %d, got %d", name, want, got))
		}
	}
	for _, c := range []struct {
		name string
		keys []string
	}{{"VOnly", j.VOnly}, {"ROnly", j.ROnly}, {"ObjDiffer", j.ObjDiffer}, {"NotInA", j.NotInA}} {
		check(c.name, 0, len(c.keys))
	}
	check("AccRej", 0, j.AccRej)

	var vRej, rRej, res4, kept4, res6, kept6, aRej6 int
	bad := map[string]int{} // cells outside the expected shape
	for c, n := range j.Cells {
		vRej += n
		if c.R == "rejected" {
			rRej += n
		}
		switch {
		case c.Family == "ipv4.unicast" && c.A == "undecided" && c.R == "accepted":
			res4 += n
		case c.Family == "ipv4.unicast" && c.A == "undecided" && c.R == "rejected":
			kept4 += n
		case c.Family == "ipv6.unicast" && c.A == "accepted" && c.R == "accepted":
			res6 += n
		case c.Family == "ipv6.unicast" && c.A == "accepted" && c.R == "rejected":
			kept6 += n
		case c.Family == "ipv6.unicast" && c.A == "rejected" && c.R == "rejected":
			aRej6 += n
		case c.Family == "ipv4.unicast":
			bad[fmt.Sprintf("ipv4 A=%q R=%q", c.A, c.R)] += n
		case c.Family == "ipv6.unicast":
			bad[fmt.Sprintf("ipv6 A=%q R=%q", c.A, c.R)] += n
		default:
			bad[fmt.Sprintf("family %q", c.Family)] += n
		}
	}
	for _, k := range slices.Sorted(maps.Keys(bad)) {
		errs = append(errs, fmt.Sprintf("%s: want 0 routes, got %d", k, bad[k]))
	}
	check("VRejected", w.VRejected, vRej)
	check("RRejected", w.RRejected, rRej+j.AccRej)
	check("Rescued4", w.Rescued4, res4)
	check("Kept4", w.Kept4, kept4)
	check("Rescued6", w.Rescued6, res6)
	check("Kept6", w.Kept6, kept6)
	check("ARejected6", w.ARejected6, aRej6)
	check("len(Rescued)", w.Rescued4+w.Rescued6, len(j.Rescued))
	acc := map[string]int{"accepted": w.ImportAccepted}
	if !maps.Equal(j.ImportV, acc) {
		errs = append(errs, fmt.Sprintf("ImportV: want %v, got %v", acc, j.ImportV))
	}
	if !maps.Equal(j.ImportR, acc) {
		errs = append(errs, fmt.Sprintf("ImportR: want %v, got %v", acc, j.ImportR))
	}
	return errs
}

// writeVRCross writes the table: a header line, one tab-separated row per cell
// sorted by family, Obj, A, R, then a "sum" row.
func writeVRCross(w io.Writer, j *vrJoin) error {
	if _, err := fmt.Fprintln(w, "family\troute object\tA\tR\troutes"); err != nil {
		return err
	}
	cells := slices.SortedFunc(maps.Keys(j.Cells), func(a, b vrCell) int {
		return slices.Compare([]string{a.Family, a.Obj, a.A, a.R}, []string{b.Family, b.Obj, b.A, b.R})
	})
	sum := 0
	for _, c := range cells {
		n := j.Cells[c]
		sum += n
		if _, err := fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%d\n", c.Family, c.Obj, c.A, c.R, n); err != nil {
			return err
		}
	}
	_, err := fmt.Fprintf(w, "sum\t\t\t\t%d\n", sum)
	return err
}

// TestPair2VAgainstR joins pair 2's V run with R and A (opt-in; each input is a
// routes.tsv.gz of ~2.6M lines). ROUTECHECK_PAIR2V_V, _R and _A are the three
// files, ROUTECHECK_PAIR2V_OUT the directory for pair2-v-cross.txt and
// pair2-v-rescued.tsv.
func TestPair2VAgainstR(t *testing.T) {
	vPath := os.Getenv("ROUTECHECK_PAIR2V_V")
	if vPath == "" {
		t.Skip("set ROUTECHECK_PAIR2V_V, _R, _A and _OUT to join pair 2's V rejections with R")
	}
	rPath, aPath, out := os.Getenv("ROUTECHECK_PAIR2V_R"), os.Getenv("ROUTECHECK_PAIR2V_A"), os.Getenv("ROUTECHECK_PAIR2V_OUT")
	for name, v := range map[string]string{"ROUTECHECK_PAIR2V_R": rPath, "ROUTECHECK_PAIR2V_A": aPath, "ROUTECHECK_PAIR2V_OUT": out} {
		if v == "" {
			t.Fatalf("%s is not set", name)
		}
	}
	j, err := joinVR(vPath, rPath, aPath, "AS9086-AS6762")
	if err != nil {
		t.Fatal(err)
	}
	var sb strings.Builder
	if err := writeVRCross(&sb, j); err != nil {
		t.Fatal(err)
	}
	t.Logf("cross table:\n%s", sb.String())
	errs := j.controlErrors(vrWant{VRejected: 263472, RRejected: 252133, Rescued4: 9827, Kept4: 214472,
		Rescued6: 1512, Kept6: 3693, ARejected6: 33968, ImportAccepted: 978368})
	for _, e := range errs {
		t.Logf("control: %s", e)
	}
	if err := os.WriteFile(filepath.Join(out, "pair2-v-cross.txt"), []byte(sb.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	rescued := strings.Join(j.Rescued, "\n")
	if rescued != "" {
		rescued += "\n"
	}
	if err := os.WriteFile(filepath.Join(out, "pair2-v-rescued.tsv"), []byte(rescued), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, e := range errs {
		t.Errorf("control: %s", e)
	}
}
