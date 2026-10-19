package routecheck_test

import (
	"bufio"
	"cmp"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rkolesnichenko/mrt"
	"github.com/rkolesnichenko/rpsl/types"
)

// The answers below are whois.radb.net's and whois.ripe.net's, recorded on
// 2026-10-19, except the found ones: no lookup had found a set then, so those
// are built from an as-set object and RIPE's documented --list-versions layout.
const (
	radbNone   = "%  No entries found for the selected source(s).\n\n\n"
	ripeBanner = "% This is the RIPE Database query service.\n% The objects are in RPSL format.\n%\n" +
		"% The RIPE Database is subject to Terms and Conditions.\n% See https://docs.db.ripe.net/terms-conditions.html\n\n"
	ripeHistDeleted = ripeBanner + "% Version history for AS-SET object \"AS-STEFFANN-IPV4\"\n" +
		"% You can use \"--show-version rev#\" to get an exact version of the object.\n\n" +
		"% This object was deleted on 2024-02-09T21:50:56Z\n\n" +
		"% This query was served by the RIPE Database Query Service version 1.124.1 (DEXTER)\n\n\n"
	ripeHistNone = ripeBanner + "%ERROR:101: no entries found\n%\n% No entries found in source RIPE.\n\n" +
		"% This query was served by the RIPE Database Query Service version 1.124.1 (SHETLAND)\n\n\n"
	ripeHistVersions = ripeBanner + "% Version history for AS-SET object \"AS-EXAMPLE\"\n" +
		"% You can use \"--show-version rev#\" to get an exact version of the object.\n\n" +
		"rev#       Date              Op.\n\n1          2015-03-11 16:39  ADD/UPD\n2          2023-05-02 09:12  ADD/UPD\n\n" +
		"% This query was served by the RIPE Database Query Service version 1.124.1 (DEXTER)\n\n\n"
)

// asSet is an as-set object named name in source, with the date lines given.
func asSet(name, source string, dates ...string) string {
	return "as-set:         " + name + "\ndescr:          customers of an example network\n" +
		"members:        AS64500, AS64501\nmnt-by:         MAINT-EXAMPLE\n" + strings.Join(dates, "") +
		"source:         " + source + "\n"
}

// radbFound is RADB's answer holding objs.
func radbFound(objs ...string) string { return strings.Join(objs, "\n") + "\n\n" }

// ripeFound is RIPE's answer to ripeObjQuery holding obj.
func ripeFound(obj string) string {
	return ripeBanner + "% Information related to 'AS-EXAMPLE'\n\n" + obj +
		"\n% This query was served by the RIPE Database Query Service version 1.124.1 (DEXTER)\n\n\n"
}

func TestParseRADB(t *testing.T) {
	x := asSet("AS-X", "LEVEL3", "last-modified:  2023-04-01T10:00:00Z\n")
	y := asSet("as-x", "RADB")
	for _, c := range []struct {
		name, text, kind string
		objs             []string
	}{
		{"none", radbNone, "none", nil},
		{"found", radbFound(x), "found", []string{x}},
		{"found twice", radbFound(x, y), "found", []string{x, y}},
		{"empty", "", "bad", nil},
		{"cut short", radbFound(x)[:len(x)/2], "bad", nil},
		{"none cut short", radbNone[:20], "bad", nil},
		{"error", "%% ERROR: Unknown source FOO\n\n\n", "bad", nil},
		{"error beside none", "%% ERROR: Unknown source FOO\n" + radbNone, "bad", nil},
		{"another class", radbFound("aut-num: AS1\nsource: RADB\n"), "bad", nil},
		{"found, CRLF", strings.ReplaceAll(radbFound(x), "\n", "\r\n"), "found", []string{x}},
		{"none, CRLF", strings.ReplaceAll(radbNone, "\n", "\r\n"), "none", nil},
		{"found, CRLF, cut short", strings.ReplaceAll(radbFound(x), "\n", "\r\n")[:len(x)], "bad", nil},
	} {
		objs, kind := parseRADB(c.text)
		if kind != c.kind || !slices.Equal(objs, c.objs) {
			t.Errorf("%s: parseRADB = %q, %s; want %q, %s", c.name, objs, kind, c.objs, c.kind)
		}
	}
}

func TestParseRIPEHistory(t *testing.T) {
	for _, c := range []struct{ name, text, kind, deleted string }{
		{"deleted", ripeHistDeleted, "deleted", "2024-02-09"},
		{"none", ripeHistNone, "none", ""},
		{"exists", ripeHistVersions, "exists", ""},
		{"re-created after a deletion", strings.Replace(ripeHistVersions, "rev#       Date",
			"% This object was deleted on 2024-02-09T21:50:56Z\n\nrev#       Date", 1), "exists", ""},
		{"banner only (AS-ISPSERVICES)", ripeBanner, "bad", ""},
		{"empty", "", "bad", ""},
		{"versions cut short", ripeHistVersions[:len(ripeHistVersions)-90], "bad", ""},
		{"another error", strings.Replace(ripeHistNone, "%ERROR:101: no entries found", "%ERROR:201: access denied", 1), "bad", ""},
	} {
		if kind, deleted := parseRIPEHistory(c.text); kind != c.kind || deleted != c.deleted {
			t.Errorf("%s: parseRIPEHistory = %s %q; want %s %q", c.name, kind, deleted, c.kind, c.deleted)
		}
	}
	obj := asSet("AS-EXAMPLE", "RIPE", "created:        2015-03-11T16:39:00Z\n")
	if objs, kind := parseRIPEObjects(ripeFound(obj)); kind != "found" || !slices.Equal(objs, []string{obj}) {
		t.Errorf("parseRIPEObjects(found) = %q, %s", objs, kind)
	}
	if _, kind := parseRIPEObjects(ripeHistNone); kind != "none" {
		t.Errorf("parseRIPEObjects(none) = %s", kind)
	}
	if _, kind := parseRIPEObjects(ripeBanner); kind != "bad" {
		t.Errorf("parseRIPEObjects(banner only) = %s", kind)
	}
}

func TestObjectDate(t *testing.T) {
	for _, c := range []struct {
		obj, date string
		ok        bool
	}{
		{asSet("AS-X", "RIPE", "created:        2020-01-01T00:00:00Z\n", "last-modified:  2026-10-19T08:15:00Z\n"), "2026-10-19", true},
		{asSet("AS-X", "RADB", "changed:        a@b 20190305\n"), "2019-03-05", true},
		{asSet("AS-X", "RADB", "changed:        a@b 20190305\n", "changed:        a@b 20210101\n", "changed:        a@b 20200101\n"), "2021-01-01", true},
		{asSet("AS-X", "RADB", "Last-Modified:  2022-02-02T00:00:00Z\n", "changed:        a@b 20230101\n"), "2023-01-01", true},
		{asSet("AS-X", "LEVEL3"), "", false},
	} {
		if date, ok := objectDate(c.obj); date != c.date || ok != c.ok {
			t.Errorf("objectDate(%q) = %q, %v; want %q, %v", c.obj, date, ok, c.date, c.ok)
		}
	}
}

func TestClassifySet(t *testing.T) {
	level3 := asSet("AS-X", "LEVEL3", "last-modified:  2023-04-01T10:00:00Z\n")
	newer := asSet("AS-X", "RADB", "created:        2026-10-19T09:00:00Z\n")
	older := asSet("AS-X", "RADB", "changed:        a@b 20200101\n")
	undated := asSet("AS-X", "ALTDB")
	ripeObj := asSet("AS-X", "RIPE # Filtered", "last-modified:  2024-01-01T00:00:00Z\n")
	for _, c := range []struct {
		name          string
		held          bool
		radb          string
		radbObjs      []string
		ripe, deleted string
		ripeObjs      []string
		want          setLookup
	}{
		{"held", true, "", nil, "", "", nil, setLookup{Class: "held but refused"}},
		{"found in LEVEL3", false, "found", []string{level3}, ripeSkipped, "", nil,
			setLookup{Class: "elsewhere", Sub: "unloaded source", Copies: "LEVEL3@2023-04-01", InB: true}},
		{"found in RADB, newer", false, "found", []string{newer}, ripeSkipped, "", nil,
			setLookup{Class: "elsewhere", Sub: "newer than the dumps", Copies: "RADB@2026-10-19"}},
		{"none, RIPE deleted", false, "none", nil, "deleted", "2024-02-09", nil, setLookup{Class: "deleted", Deleted: "2024-02-09"}},
		{"none, none", false, "none", nil, "none", "", nil, setLookup{Class: "not found"}},
		{"none, RIPE not asked", false, "none", nil, ripeSkipped, "", nil, setLookup{Class: "not found"}},
		{"none, bad", false, "none", nil, "bad", "", nil, setLookup{Class: "inconclusive"}},
		{"bad, deleted", false, "bad", nil, "deleted", "2024-02-09", nil, setLookup{Class: "inconclusive", Deleted: "2024-02-09"}},
		{"found, bad", false, "found", []string{older}, "bad", "", nil,
			setLookup{Class: "elsewhere", Sub: "loaded source, not in its dump", Copies: "RADB@2020-01-01", InB: true}},
		{"RIPE exists, fetched", false, "none", nil, "exists", "", []string{ripeObj},
			setLookup{Class: "elsewhere", Sub: "loaded source, not in its dump", Copies: "RIPE@2024-01-01", InB: true}},
		{"RIPE exists, not fetched", false, "none", nil, "exists", "", nil, setLookup{Class: "inconclusive"}},
		{"undated", false, "found", []string{undated}, ripeSkipped, "", nil,
			setLookup{Class: "elsewhere", Sub: "loaded source, not in its dump", Copies: "ALTDB@undated", InB: true}},
		{"newer in LEVEL3, older in RADB", false, "found", []string{asSet("AS-X", "LEVEL3", "changed: a@b 20261019\n"), older}, ripeSkipped, "", nil,
			setLookup{Class: "elsewhere", Sub: "unloaded source", Copies: "LEVEL3@2026-10-19;RADB@2020-01-01", InB: true}},
	} {
		if got := classifySet(c.held, c.radb, c.radbObjs, c.ripe, c.deleted, c.ripeObjs); got != c.want {
			t.Errorf("%s: classifySet = %+v; want %+v", c.name, got, c.want)
		}
	}
}

// fakeWhois answers connections to radb.test:43 and ripe.test:43 in process,
// through a net.Pipe, and refuses any other address: no test reaches a
// network.
type fakeWhois struct {
	mu      sync.Mutex
	queries []string // "radb.test:43 <query>", in order
	answer  func(addr, query string) string
}

func (f *fakeWhois) dial(_ context.Context, _, addr string) (net.Conn, error) {
	if addr != "radb.test:43" && addr != "ripe.test:43" {
		return nil, errors.New("fakeWhois: refused " + addr)
	}
	c, s := net.Pipe()
	go func() {
		defer s.Close()
		q, err := bufio.NewReader(s).ReadString('\n')
		if err != nil {
			return
		}
		q = strings.TrimSuffix(q, "\r\n")
		f.mu.Lock()
		f.queries = append(f.queries, addr+" "+q)
		f.mu.Unlock()
		io.WriteString(s, f.answer(addr, q))
	}()
	return c, nil
}

// testRun is a lookupRun in dir, dialing with dial, whose retries wait not
// at all; waits counts them.
func testRun(t *testing.T, dir string, dial dialFunc, limit int, waits *int) *lookupRun {
	t.Helper()
	r, err := newLookupRun(dir, dial, "radb.test:43", "ripe.test:43", limit)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.close() })
	r.timeout = 5 * time.Second
	r.wait = func(d time.Duration) {
		if d != 5*time.Second {
			t.Errorf("retry waits %v, want 5s", d)
		}
		if waits != nil {
			*waits++
		}
	}
	return r
}

func mustRef(t *testing.T, s string) types.SetRef {
	t.Helper()
	ref, err := types.ParseSetRef(s)
	if err != nil {
		t.Fatal(err)
	}
	return ref
}

func TestLookupScoped(t *testing.T) {
	if got, want := radbQuery(mustRef(t, "ripe::as-x")), "-r -s RIPE -T as-set,route-set,filter-set,peering-set,rtr-set AS-X"; got != want {
		t.Errorf("radbQuery(RIPE::AS-X) = %q, want %q", got, want)
	}
	if got, want := radbQuery(mustRef(t, "AS1:AS-X")), "-r -s "+radbSources+" -T as-set,route-set,filter-set,peering-set,rtr-set AS1:AS-X"; got != want {
		t.Errorf("radbQuery(AS1:AS-X) = %q, want %q", got, want)
	}
	if got, want := ripeQuery(mustRef(t, "RIPE::rs-x")), "--list-versions -T route-set RS-X"; got != want {
		t.Errorf("ripeQuery = %q, want %q", got, want)
	}
	if got, want := ripeObjQuery(mustRef(t, "fltr-x")), "-r -B -T filter-set FLTR-X"; got != want {
		t.Errorf("ripeObjQuery = %q, want %q", got, want)
	}

	dump := filepath.Join(t.TempDir(), "radb.db")
	text := "# RADB dump\n\nas-set: as-x\nmembers: AS1\nsource: RADB\n\n" +
		"route-set: AS-EVIL\nsource: RIPE # Filtered\n\naut-num: AS1\nmember-of: AS-Y\nsource: RADB\n"
	if err := os.WriteFile(dump, []byte(text), 0o644); err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{"AS-X": true, "AS-EVIL": true, "AS-Y": true}
	held, err := readHeld([]string{dump}, want)
	if err != nil {
		t.Fatal(err)
	}
	for s, h := range map[string]bool{"AS-X": true, "RADB::AS-X": true, "RIPE::AS-X": false,
		"AS-EVIL": true, "RIPE::AS-EVIL": true, "AS-Y": false} {
		if got := held.has(mustRef(t, s)); got != h {
			t.Errorf("held.has(%s) = %v, want %v", s, got, h)
		}
	}

	// RIPE::AS-X is asked of RADB in RIPE only and of RIPE's history;
	// RADB::AS-Z of RADB only (ruling R2).
	f := &fakeWhois{answer: func(addr, q string) string {
		if addr == "radb.test:43" {
			return radbNone
		}
		return ripeHistNone
	}}
	r := testRun(t, t.TempDir(), f.dial, 100, nil)
	r.held = held
	for _, c := range []struct{ ref, class string }{{"RIPE::AS-X", "not found"}, {"RADB::AS-Z", "not found"}, {"AS-X", "held but refused"}} {
		row, _, err := r.lookupSet(context.Background(), mustRef(t, c.ref))
		if err != nil || row.Class != c.class || row.Set != c.ref {
			t.Errorf("lookupSet(%s) = %+v, %v; want class %s", c.ref, row, err, c.class)
		}
	}
	wantQ := []string{
		"radb.test:43 -r -s RIPE -T as-set,route-set,filter-set,peering-set,rtr-set AS-X",
		"ripe.test:43 --list-versions -T as-set AS-X",
		"radb.test:43 -r -s RADB -T as-set,route-set,filter-set,peering-set,rtr-set AS-Z",
	}
	if !slices.Equal(f.queries, wantQ) {
		t.Errorf("queries = %q, want %q", f.queries, wantQ)
	}
}

// whoisServer is a localhost whois server that reads one query per
// connection and lets serve answer it; it counts the connections.
func whoisServer(t *testing.T, serve func(c net.Conn, query string)) (string, *atomic.Int32) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var n atomic.Int32
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			n.Add(1)
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer c.Close()
				q, err := bufio.NewReader(c).ReadString('\n')
				if err == nil {
					serve(c, strings.TrimSuffix(q, "\r\n"))
				}
			}()
		}
	}()
	t.Cleanup(func() { ln.Close(); wg.Wait() })
	return ln.Addr().String(), &n
}

func TestWhoisCutShort(t *testing.T) {
	found := radbFound(asSet("AS-X", "LEVEL3"))
	hold := func(c net.Conn, text string) { io.WriteString(c, text); io.Copy(io.Discard, c) }
	for _, c := range []struct {
		name string
		svc  string // the service cut short; the other answers none
		cut  func(c net.Conn)
	}{
		{"half an answer", "radb", func(c net.Conn) { io.WriteString(c, found[:len(found)/2]) }},
		{"nothing", "radb", func(net.Conn) {}},
		{"no answer before the deadline", "radb", func(c net.Conn) { hold(c, "") }},
		{"full answer, then the deadline", "radb", func(c net.Conn) { hold(c, radbNone) }},
		{"history: full answer, then the deadline", "ripe", func(c net.Conn) { hold(c, ripeHistNone) }},
		{"history: deleted, then the deadline", "ripe", func(c net.Conn) { hold(c, ripeHistDeleted) }},
	} {
		t.Run(c.name, func(t *testing.T) {
			serve := map[string]func(net.Conn, string){
				"radb": func(conn net.Conn, _ string) { io.WriteString(conn, radbNone) },
				"ripe": func(conn net.Conn, _ string) { io.WriteString(conn, ripeHistNone) },
			}
			serve[c.svc] = func(conn net.Conn, _ string) { c.cut(conn) }
			radb, radbConns := whoisServer(t, serve["radb"])
			ripe, ripeConns := whoisServer(t, serve["ripe"])
			var waits int
			r := testRun(t, t.TempDir(), (&net.Dialer{}).DialContext, 100, &waits)
			r.radbAddr, r.ripeAddr, r.timeout = radb, ripe, 300*time.Millisecond
			row, _, err := r.lookupSet(context.Background(), mustRef(t, "AS-X"))
			if err != nil {
				t.Fatal(err)
			}
			conns := map[string]int32{"radb": radbConns.Load(), "ripe": ripeConns.Load()}
			if row.Class != "inconclusive" || conns[c.svc] != 2 || radbConns.Load()+ripeConns.Load() != 3 || waits != 1 || r.asked != 3 {
				t.Errorf("class %q after %d RADB and %d RIPE connections, %d waits, %d queries; want inconclusive after 2 to %s and 1 to the other, 1, 3",
					row.Class, radbConns.Load(), ripeConns.Load(), waits, r.asked, c.svc)
			}
			name := cacheName("AS-X")
			for _, svc := range []string{"radb", "ripe"} {
				_, err := os.Stat(filepath.Join(r.dir, "cache", svc, name+".txt"))
				if svc == c.svc && !errors.Is(err, os.ErrNotExist) {
					t.Errorf("%s: an inconclusive answer is cached (%v); it must be asked again", svc, err)
				}
				if svc != c.svc && err != nil {
					t.Errorf("%s: a conclusive answer is not cached: %v", svc, err)
				}
			}
		})
	}

	big, _ := whoisServer(t, func(c net.Conn, _ string) { c.Write(make([]byte, 4<<20+1)) })
	if _, err := whoisQuery(context.Background(), (&net.Dialer{}).DialContext, big, "AS-X"); err == nil {
		t.Error("an answer over 4 MiB is not an error")
	}
}

func TestNamingChecksClass(t *testing.T) {
	asX := asSet("as-x", "RADB")
	rsX := "route-set:      AS-X\nmembers:        192.0.2.0/24\nsource:         RADB\n"
	name, err := types.ParseSetName("AS-X")
	if err != nil {
		t.Fatal(err)
	}
	if got := naming([]string{rsX, asX, asSet("AS-Y", "RADB")}, name); !slices.Equal(got, []string{asX}) {
		t.Errorf("naming(AS-X) = %q, want the as-set alone", got)
	}
}

func TestCachedAnswerRechecked(t *testing.T) {
	dir := t.TempDir()
	f := &fakeWhois{answer: func(string, string) string { return radbNone }}
	r := testRun(t, dir, f.dial, 100, nil)
	routeSetD := "route-set:      AS-D\nmembers:        192.0.2.0/24\nsource:         RADB\n"
	cached := map[string]string{
		"RADB::AS-A": radbNone[:20],                        // cut short
		"RADB::AS-B": radbFound(asSet("AS-OTHER", "RADB")), // names another set
		"RADB::AS-C": radbNone,                             // conclusive
		"RADB::AS-D": radbFound(routeSetD),                 // names the set in another class
	}
	var refs []types.SetRef
	for _, s := range []string{"RADB::AS-A", "RADB::AS-B", "RADB::AS-C", "RADB::AS-D"} {
		refs = append(refs, mustRef(t, s))
		if err := os.WriteFile(filepath.Join(dir, "cache", "radb", cacheName(s)+".txt"), []byte(cached[s]), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	rows, err := r.lookupAll(context.Background(), refs)
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range rows {
		if row.Class != "not found" {
			t.Errorf("%s: class %q, want not found", row.Set, row.Class)
		}
	}
	want := []string{
		"radb.test:43 -r -s RADB -T " + setClasses + " AS-A",
		"radb.test:43 -r -s RADB -T " + setClasses + " AS-B",
		"radb.test:43 -r -s RADB -T " + setClasses + " AS-D",
	}
	if !slices.Equal(f.queries, want) {
		t.Errorf("queries = %q, want %q", f.queries, want)
	}
	for _, s := range []string{"RADB::AS-A", "RADB::AS-B", "RADB::AS-D"} {
		file := filepath.Join(dir, "cache", "radb", cacheName(s))
		if b, err := os.ReadFile(file + ".txt"); err != nil || string(b) != radbNone {
			t.Errorf("%s: cache holds %q (%v), want the new answer", s, b, err)
		}
		if b, err := os.ReadFile(file + ".bad.txt"); err != nil || string(b) != cached[s] {
			t.Errorf("%s: .bad.txt holds %q (%v), want the old answer", s, b, err)
		}
	}
	ents, _ := os.ReadDir(filepath.Join(dir, "cache", "radb"))
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), ".tmp-") {
			t.Errorf("a temp file is left: %s", e.Name())
		}
	}
}

func TestServiceStops(t *testing.T) {
	dir := t.TempDir()
	reset := func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("read tcp: connection reset by peer")
	}
	r := testRun(t, dir, reset, 100, nil)
	r.stopAfter = 5
	var refs []types.SetRef
	for i := 1; i <= 7; i++ {
		refs = append(refs, mustRef(t, fmt.Sprintf("RADB::AS-S%d", i)))
	}
	rows, err := r.lookupAll(context.Background(), refs)
	if err != nil {
		t.Fatal(err)
	}
	for i, row := range rows {
		want := "inconclusive"
		if i >= 5 {
			want = "not looked up"
		}
		if row.Class != want {
			t.Errorf("%s: class %q, want %q", row.Set, row.Class, want)
		}
	}
	b, err := os.ReadFile(filepath.Join(dir, "queries.log"))
	if err != nil || strings.Count(string(b), "\tradb\t") != 10 || strings.Count(string(b), "\n") != 10 {
		t.Errorf("queries.log = %q (%v), want 10 RADB lines (5 sets, each retried once)", b, err)
	}
	if !strings.Contains(r.stopped, "radb.test:43 after 5 inconclusive lookups in a row") || !strings.Contains(r.stopped, "connection reset") {
		t.Errorf("stopped = %q", r.stopped)
	}
}

func TestCacheName(t *testing.T) {
	if a, b := cacheName("AS1:AS-X:AS2"), cacheName("as1:as-x:as2"); a != b {
		t.Errorf("cacheName is not case-folded: %q, %q", a, b)
	}
	names := []string{"AS-A/B", "AS-A:B", "AS-A%3aB", "RIPE::AS-X", "AS-X", "AS1:AS-X:AS2",
		"AS-" + strings.Repeat("LONG", 100), "AS-" + strings.Repeat("LONG", 100) + "X", "AS-A..B", "AS-A_B"}
	dir := t.TempDir()
	seen := map[string]string{}
	for _, n := range names {
		c := cacheName(n)
		if o, dup := seen[c]; dup {
			t.Errorf("cacheName(%q) = cacheName(%q) = %q", n, o, c)
		}
		seen[c] = n
		if len(c) > 200 || strings.ContainsAny(c, ":/.") {
			t.Errorf("cacheName(%q) = %q is not a safe file name", n, c)
		}
		if err := os.WriteFile(filepath.Join(dir, c+".txt"), []byte(n), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(ents) != len(names) {
		t.Fatalf("%d files for %d names", len(ents), len(names))
	}
	for _, e := range ents {
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil || cacheName(string(b))+".txt" != e.Name() {
			t.Errorf("%s holds %q (%v)", e.Name(), b, err)
		}
	}
}

func TestQueryCap(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "missing-sets.tsv")
	text := "import\tRADB::AS-C\t5\nexport\tRADB::AS-B\t20\nexport\tRADB::AS-A\t30\nexport\tRADB::AS-C\t5\n"
	if err := os.WriteFile(in, []byte(text), 0o644); err != nil {
		t.Fatal(err)
	}
	refs, err := readMissingSets([]string{in})
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, r := range refs {
		got = append(got, r.String())
	}
	if want := []string{"RADB::AS-A", "RADB::AS-B", "RADB::AS-C"}; !slices.Equal(got, want) {
		t.Fatalf("readMissingSets = %q, want %q (most routes first)", got, want)
	}
	objA := asSet("AS-A", "RADB", "changed:        a@b 20200101\n")
	f := &fakeWhois{answer: func(_, q string) string {
		switch {
		case strings.HasSuffix(q, " AS-A"):
			return radbFound(objA)
		case strings.HasSuffix(q, " AS-B"):
			return radbFound(asSet("AS-B", "RADB", "last-modified:  2026-10-19T00:00:00Z\n"))
		}
		return radbNone
	}}
	for round := 1; round <= 2; round++ {
		r := testRun(t, dir, f.dial, 2, nil)
		if _, err := r.lookupAll(context.Background(), refs); err != nil {
			t.Fatal(err)
		}
		if want := 2 - (round-1)*2; r.asked != want {
			t.Errorf("round %d asked %d queries, want %d", round, r.asked, want)
		}
		sets, err := readSets(filepath.Join(dir, "sets.tsv"))
		if err != nil {
			t.Fatal(err)
		}
		want := map[string]setLookup{
			"RADB::AS-A": {Set: "RADB::AS-A", Class: "elsewhere", Sub: "loaded source, not in its dump", Copies: "RADB@2020-01-01", InB: true},
			"RADB::AS-B": {Set: "RADB::AS-B", Class: "elsewhere", Sub: "newer than the dumps", Copies: "RADB@2026-10-19"},
			"RADB::AS-C": {Set: "RADB::AS-C", Class: "not looked up"},
		}
		if !maps.Equal(sets, want) {
			t.Errorf("round %d: sets.tsv = %+v, want %+v", round, sets, want)
		}
		b, err := os.ReadFile(filepath.Join(dir, "queries.log"))
		if err != nil || strings.Count(string(b), "\n") != 2 {
			t.Errorf("round %d: queries.log = %q (%v), want 2 lines", round, b, err)
		}
		fz, err := os.Open(filepath.Join(dir, "extra.db.gz"))
		if err != nil {
			t.Fatal(err)
		}
		zr, err := gzip.NewReader(fz)
		if err != nil {
			t.Fatal(err)
		}
		if b, err := io.ReadAll(zr); err != nil || string(b) != objA {
			t.Errorf("round %d: extra.db.gz = %q (%v), want AS-A's object only", round, b, err)
		}
		fz.Close()
	}
	if len(f.queries) != 2 {
		t.Errorf("%d queries reached the services, want 2: %q", len(f.queries), f.queries)
	}
}

// TestMissingSetsLookup is the opt-in live lookup of the missing-sets
// measurement (docs/superpowers/specs/2026-10-19-missing-sets-design.md):
// each set in the missing-sets.tsv files ROUTECHECK_MISSINGSETS_IN names
// (comma-separated, every round so far) is classified, and
// ROUTECHECK_MISSINGSETS_DIR gets sets.tsv (set, class, sub, copies, deleted,
// in_b) and extra.db.gz (the copies dated on or before the dumps, for
// ROUTECHECK_REALDATA_EXTRA). A set an object in a loaded dump names
// (ROUTECHECK_REALDATA's MANIFEST, honoring ROUTECHECK_REALDATA_REGISTRIES)
// is "held but refused" without a query. The others are asked of
// whois.radb.net (radbQuery) and, unless RADB found them or they are scoped
// to another registry (ruling R2), of RIPE's version history (ripeQuery),
// then of RIPE's object (ripeObjQuery) when the history says it exists and
// RADB did not find it; one query at a time, one connection per query.
//
// Every conclusive answer is kept in DIR/cache/<service>/<cacheName>.txt and
// never asked again; an inconclusive one (an error, or an answer neither a
// set object nor "no entries", after one retry 5 s later) is kept as
// <cacheName>.bad.txt and asked again by the next run (so is a cached answer
// that is no longer conclusive). After 5 inconclusive lookups in a row from one
// service the run stops asking, logs why, and the sets left are "not looked
// up". Cache files are written whole (a temp file renamed). Every query is a line
// of DIR/queries.log (time, service, query, bytes, error), and the lines
// count against the measurement's cap of 5,000: past it, the sets left are
// "not looked up". Sets are asked most routes first. It skips unless
// ROUTECHECK_MISSINGSETS_LIVE=1:
//
//	ROUTECHECK_MISSINGSETS_LIVE=1 ROUTECHECK_MISSINGSETS_DIR=$PWD/.data/missing-sets \
//	  ROUTECHECK_MISSINGSETS_IN=$PWD/.data/missing-sets/A/missing-sets.tsv ROUTECHECK_REALDATA=$PWD/.data/realdata \
//	  go test -count=1 -timeout 6h -run TestMissingSetsLookup -v .
func TestMissingSetsLookup(t *testing.T) {
	if os.Getenv("ROUTECHECK_MISSINGSETS_LIVE") != "1" {
		t.Skip("ROUTECHECK_MISSINGSETS_LIVE=1 is not set (it queries whois.radb.net and whois.ripe.net)")
	}
	dir, in := os.Getenv("ROUTECHECK_MISSINGSETS_DIR"), os.Getenv("ROUTECHECK_MISSINGSETS_IN")
	if dir == "" || in == "" {
		t.Fatal("ROUTECHECK_MISSINGSETS_DIR and ROUTECHECK_MISSINGSETS_IN are needed")
	}
	rd := openRealData(t)
	refs, err := readMissingSets(strings.Split(in, ","))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{}
	for _, r := range refs {
		want[r.Name().String()] = true
	}
	t0 := time.Now()
	held, err := readHeld(rd.dumps, want)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%d sets; %d names held by %d dumps, read in %s", len(refs), len(held), len(rd.dumps), since(t0))
	r, err := newLookupRun(dir, (&net.Dialer{}).DialContext, "whois.radb.net:43", "whois.ripe.net:43", queryCap)
	if err != nil {
		t.Fatal(err)
	}
	defer r.close()
	r.held = held
	rows, err := r.lookupAll(context.Background(), refs)
	if err != nil {
		t.Fatal(err)
	}
	counts, undated := map[string]int{}, 0
	for _, row := range rows {
		counts[row.Class+" / "+row.Sub]++
		undated += strings.Count(row.Copies, "@undated")
	}
	for _, k := range slices.Sorted(maps.Keys(counts)) {
		t.Logf("  %-60s %d", k, counts[k])
	}
	t.Logf("queries: %d this run, %d in total of the cap of %d (cap hit: %v); undated copies: %d; in %s",
		r.asked, r.used, r.limit, r.capped, undated, since(t0))
	if r.stopped != "" {
		t.Logf("STOPPED asking: %s; the sets after it are not looked up", r.stopped)
	}
}

const (
	// queryCap is the most queries the whole measurement asks.
	queryCap = 5000
	// dumpDate is the date of the dumps: a copy dated later stays out of run B.
	dumpDate = "2026-10-18"
	// radbSources is whois.radb.net's !s-lc of 2026-10-19, less RPKI.
	radbSources = "RADB,LACNIC,IDNIC,AFRINIC,RIPE,RIPE-NONAUTH,BELL,NTTCOM,ALTDB,PANIX,NESTEGG,LEVEL3,ARIN,JPIRR,BBOI,CANARIE,REACH,TC,APNIC"
	// setClasses is every set class, as RADB's -T takes them.
	setClasses = "as-set,route-set,filter-set,peering-set,rtr-set"
	// ripeSkipped is classifySet's ripe when RIPE was not asked: RADB found
	// the set, or it is scoped to another registry.
	ripeSkipped = "skipped"
	// whoisMaxAnswer is the longest answer whoisQuery accepts.
	whoisMaxAnswer = 4 << 20
)

// unloadedSources are RADB's sources routecheck loads no dump of.
var unloadedSources = map[string]bool{"IDNIC": true, "RIPE-NONAUTH": true, "LEVEL3": true}

// dialFunc is net.Dialer.DialContext's shape: the live dialer, or a test's.
type dialFunc = func(ctx context.Context, network, addr string) (net.Conn, error)

// setLookup is one row of sets.tsv.
type setLookup struct {
	Set, Class, Sub, Copies, Deleted string
	InB                              bool
}

// readSets reads sets.tsv, keyed by setKey(Set).
func readSets(path string) (map[string]setLookup, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	out := map[string]setLookup{}
	for _, line := range strings.SplitAfter(string(b), "\n") {
		if line == "" {
			continue // after the last newline
		}
		line = strings.TrimSuffix(line, "\n")
		f := strings.Split(line, "\t")
		if len(f) != 6 || (f[5] != "yes" && f[5] != "no") {
			return nil, fmt.Errorf("%s: %q is not set, class, sub, copies, deleted, in_b", path, line)
		}
		out[setKey(f[0])] = setLookup{f[0], f[1], f[2], f[3], f[4], f[5] == "yes"}
	}
	return out, nil
}

// setKey is the case-folded set: upper case, as SetRef.String() writes it.
func setKey(s string) string { return strings.ToUpper(s) }

// readMissingSets reads missing-sets.tsv files (dir, set, routes), each set
// once, the most routes (summed over files and directions) first, then by name.
func readMissingSets(files []string) ([]types.SetRef, error) {
	routes := map[types.SetRef]int{}
	for _, file := range files {
		b, err := os.ReadFile(file)
		if err != nil {
			return nil, err
		}
		for _, line := range strings.Split(strings.TrimSuffix(string(b), "\n"), "\n") {
			f := strings.Split(line, "\t")
			if line == "" {
				continue
			}
			n, err := strconv.Atoi(f[len(f)-1])
			if len(f) != 3 || err != nil {
				return nil, fmt.Errorf("%s: %q is not dir, set, routes", file, line)
			}
			ref, err := types.ParseSetRef(f[1])
			if err != nil {
				return nil, fmt.Errorf("%s: %w", file, err)
			}
			routes[ref] += n
		}
	}
	refs := slices.Collect(maps.Keys(routes))
	slices.SortFunc(refs, func(a, b types.SetRef) int {
		return cmp.Or(cmp.Compare(routes[b], routes[a]), cmp.Compare(a.String(), b.String()))
	})
	return refs, nil
}

// heldIndex is the sets the loaded dumps hold an object of, by canonical
// name, with each object's source.
type heldIndex map[string][]string

// has reports whether a dump holds ref: any object of its name, or, for a
// scoped ref, one of its name in its source.
func (h heldIndex) has(ref types.SetRef) bool {
	srcs := h[ref.Name().String()]
	return len(srcs) > 0 && (!ref.IsScoped() || slices.Contains(srcs, ref.Source()))
}

// setClassLine is the class line of a set object of any class.
var setClassLine = regexp.MustCompile(`(?i)^(as-set|route-set|filter-set|peering-set|rtr-set):\s*(\S+)`)

// readHeld scans the dumps (gzip or plain) for set objects whose names want
// holds (canonical names), whatever their class.
func readHeld(dumps []string, want map[string]bool) (heldIndex, error) {
	h := heldIndex{}
	for _, d := range dumps {
		if err := h.scan(d, want); err != nil {
			return nil, fmt.Errorf("%s: %w", d, err)
		}
	}
	return h, nil
}

func (h heldIndex) scan(file string, want map[string]bool) error {
	f, err := os.Open(file)
	if err != nil {
		return err
	}
	defer f.Close()
	r, err := mrt.Decompress(bufio.NewReaderSize(f, 1<<20))
	if err != nil {
		return err
	}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), 64<<20)
	name, first := "", true
	for sc.Scan() {
		line := sc.Text()
		switch {
		case strings.TrimSpace(line) == "":
			name, first = "", true
		case line[0] == '#' || line[0] == '%':
		case first:
			first = false
			if m := setClassLine.FindStringSubmatch(line); m != nil && want[canonSet(m[2])] {
				name = canonSet(m[2])
			}
		case name != "":
			if v, ok := attrValue(line, "source"); ok {
				h[name] = append(h[name], sourceOf(v))
			}
		}
	}
	return sc.Err()
}

// canonSet is name's canonical form, or name upper-cased when it does not parse.
func canonSet(name string) string {
	if n, err := types.ParseSetName(name); err == nil {
		return n.String()
	}
	return strings.ToUpper(name)
}

// attrValue is line's value when line is the attribute attr (any case).
func attrValue(line, attr string) (string, bool) {
	k, v, ok := strings.Cut(line, ":")
	if !ok || !strings.EqualFold(strings.TrimSpace(k), attr) {
		return "", false
	}
	return strings.TrimSpace(v), true
}

// sourceOf is a source: value's name, without RIPE's "# Filtered".
func sourceOf(v string) string {
	v, _, _ = strings.Cut(v, "#")
	if f := strings.Fields(v); len(f) > 0 {
		return strings.ToUpper(f[0])
	}
	return "?"
}

// whoisQuery asks query of the whois server at addr on one connection and
// reads its answer to EOF, within 30 s (or ctx's deadline, if sooner). An
// answer over whoisMaxAnswer is an error; on any error the text read so far
// is returned too.
func whoisQuery(ctx context.Context, dial func(ctx context.Context, network, addr string) (net.Conn, error), addr, query string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	conn, err := dial(ctx, "tcp", addr)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	if dl, ok := ctx.Deadline(); ok {
		if err := conn.SetDeadline(dl); err != nil {
			return "", err
		}
	}
	if _, err := io.WriteString(conn, query+"\r\n"); err != nil {
		return "", err
	}
	b, err := io.ReadAll(io.LimitReader(conn, whoisMaxAnswer+1))
	if err == nil && len(b) > whoisMaxAnswer {
		err = fmt.Errorf("answer over %d bytes", whoisMaxAnswer)
	}
	return string(b), err
}

func radbQuery(ref types.SetRef) string {
	src := radbSources
	if ref.IsScoped() {
		src = ref.Source()
	}
	return "-r -s " + src + " -T " + setClasses + " " + ref.Name().String()
}

func ripeQuery(ref types.SetRef) string {
	return "--list-versions -T " + ref.Name().Class().String() + " " + ref.Name().String()
}

func ripeObjQuery(ref types.SetRef) string {
	return "-r -B -T " + ref.Name().Class().String() + " " + ref.Name().String()
}

// paragraphs splits a whois answer at blank lines into its objects (the
// paragraphs whose first line is a set class line, as returned) and tells
// whether any other paragraph that is not comment ('%' lines) is in it.
func paragraphs(text string) (objs []string, other bool) {
	for _, p := range strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n\n") {
		var lines []string
		for _, l := range strings.Split(strings.Trim(p, "\n"), "\n") {
			if l != "" && l[0] != '%' {
				lines = append(lines, l)
			}
		}
		switch {
		case len(lines) == 0:
		case setClassLine.MatchString(lines[0]):
			objs = append(objs, strings.Join(lines, "\n")+"\n")
		default:
			other = true
		}
	}
	return objs, other
}

// radbError is an IRRd error line.
var radbError = regexp.MustCompile(`(?m)^%% ?ERROR`)

// parseRADB reads RADB's answer to radbQuery: "found" with its set objects,
// "none", or "bad" for anything else, an answer not ending in a blank line
// (cut short) or holding an IRRd "%% ERROR" line (even beside "No entries
// found") among them. Whether an object names the set is the caller's.
func parseRADB(text string) (objs []string, kind string) {
	objs, other := paragraphs(text)
	switch {
	case !strings.HasSuffix(strings.ReplaceAll(text, "\r\n", "\n"), "\n\n") || other || radbError.MatchString(text):
		return nil, "bad"
	case len(objs) > 0:
		return objs, "found"
	case strings.Contains(text, "No entries found"):
		return nil, "none"
	}
	return nil, "bad"
}

// ripeComplete reports whether RIPE's answer reached its last line.
func ripeComplete(text string) bool {
	return strings.Contains(text, "\n% This query was served by the RIPE Database Query Service")
}

var (
	ripeDeletedLine = regexp.MustCompile(`(?m)^% This object was deleted on (\S+)`)
	ripeVersionRow  = regexp.MustCompile(`(?m)^\d+\s+\d{4}-\d{2}-\d{2}\s`)
)

// parseRIPEHistory reads RIPE's answer to ripeQuery: "deleted" with the
// date, "none", "exists" (a version table) or "bad", an answer without RIPE's
// last line among them.
func parseRIPEHistory(text string) (kind, deleted string) {
	if !ripeComplete(text) {
		return "bad", ""
	}
	if ripeVersionRow.MatchString(text) {
		return "exists", "" // a re-created object's rows win over an old deletion
	}
	if m := ripeDeletedLine.FindStringSubmatch(text); m != nil {
		at, err := time.Parse(time.RFC3339, m[1])
		if err != nil {
			return "bad", ""
		}
		return "deleted", at.UTC().Format(time.DateOnly)
	}
	switch {
	case strings.Contains(text, "%ERROR:101: no entries found"):
		return "none", ""
	case strings.Contains(text, "%ERROR:"):
		return "bad", ""
	}
	return "bad", ""
}

// parseRIPEObjects reads RIPE's answer to ripeObjQuery as parseRADB reads RADB's.
func parseRIPEObjects(text string) (objs []string, kind string) {
	objs, other := paragraphs(text)
	switch {
	case !ripeComplete(text) || other:
		return nil, "bad"
	case len(objs) > 0:
		return objs, "found"
	case strings.Contains(text, "%ERROR:101: no entries found"):
		return nil, "none"
	}
	return nil, "bad"
}

// objectDate is obj's newest date (YYYY-MM-DD) of last-modified:, created:
// and changed:; ok is false when it has none.
func objectDate(obj string) (date string, ok bool) {
	for _, line := range strings.Split(obj, "\n") {
		var d string
		if v, ok := attrValue(line, "last-modified"); ok {
			d = isoDate(v)
		} else if v, ok := attrValue(line, "created"); ok {
			d = isoDate(v)
		} else if v, ok := attrValue(line, "changed"); ok {
			if f := strings.Fields(v); len(f) > 1 {
				if at, err := time.Parse("20060102", f[len(f)-1]); err == nil {
					d = at.Format(time.DateOnly)
				}
			}
		}
		if d > date {
			date = d
		}
	}
	return date, date != ""
}

// isoDate is an ISO 8601 time's UTC date, or its leading date; "" when it has neither.
func isoDate(v string) string {
	if at, err := time.Parse(time.RFC3339, v); err == nil {
		return at.UTC().Format(time.DateOnly)
	}
	if len(v) >= 10 {
		if at, err := time.Parse(time.DateOnly, v[:10]); err == nil {
			return at.Format(time.DateOnly)
		}
	}
	return ""
}

// inB reports whether obj goes into run B: undated, or dated on or before the dumps.
func inB(obj string) bool {
	d, ok := objectDate(obj)
	return !ok || d <= dumpDate
}

// classifySet is a set's class from its lookups (the caller fills Set).
// radb is parseRADB's kind and radbObjs the objects naming the set; ripe is
// parseRIPEHistory's kind (or ripeSkipped) and ripeObjs the objects RIPE
// returned naming the set. Any copy makes the set "elsewhere" (found wins),
// its sub "newer than the dumps" when no copy goes into run B, else
// "unloaded source" when a copy is in IDNIC, RIPE-NONAUTH or LEVEL3, else
// "loaded source, not in its dump"; an undated copy shows in Copies only.
// Without a copy, any bad answer, or a RIPE history saying the object exists
// that no service returned, is "inconclusive".
func classifySet(held bool, radb string, radbObjs []string, ripe, ripeDeleted string, ripeObjs []string) setLookup {
	if held {
		return setLookup{Class: "held but refused"}
	}
	if objs := slices.Concat(radbObjs, ripeObjs); len(objs) > 0 {
		row := setLookup{Class: "elsewhere", Sub: "loaded source, not in its dump", Deleted: ripeDeleted}
		var copies []string
		for _, o := range objs {
			src := "?"
			for _, line := range strings.Split(o, "\n") {
				if v, ok := attrValue(line, "source"); ok {
					src = sourceOf(v)
				}
			}
			d, ok := objectDate(o)
			if !ok {
				d = "undated"
			}
			copies = append(copies, src+"@"+d)
			row.InB = row.InB || inB(o)
			if unloadedSources[src] {
				row.Sub = "unloaded source"
			}
		}
		if !row.InB {
			row.Sub = "newer than the dumps"
		}
		row.Copies = strings.Join(copies, ";")
		return row
	}
	row := setLookup{Class: "inconclusive", Deleted: ripeDeleted}
	switch {
	case radb == "bad" || ripe == "bad" || ripe == "exists":
	case radb == "none" && ripe == "deleted":
		row.Class = "deleted"
	case radb == "none" && (ripe == "none" || ripe == ripeSkipped):
		row.Class = "not found"
	}
	return row
}

// cacheName is ref's file name: case-folded, every byte but [a-z0-9_-]
// escaped as %xx (so ':' and '/' never reach the file system and no two refs
// share a name), and a name over 200 bytes cut to 100 and ~sha256.
func cacheName(ref string) string {
	var b strings.Builder
	for _, c := range []byte(strings.ToLower(ref)) {
		if c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_' {
			b.WriteByte(c)
		} else {
			fmt.Fprintf(&b, "%%%02x", c)
		}
	}
	s := b.String()
	if len(s) > 200 {
		sum := sha256.Sum256([]byte(s))
		s = s[:100] + "~" + hex.EncodeToString(sum[:])
	}
	return s
}

// lookupRun is one run of the live lookup: where it asks, how many queries
// it may ask, and where it keeps the answers.
type lookupRun struct {
	dir                string
	dial               dialFunc
	radbAddr, ripeAddr string
	limit              int           // the cap on queries.log's lines
	timeout            time.Duration // per query
	wait               func(time.Duration)
	held               heldIndex
	stopAfter          int            // inconclusive lookups in a row that stop a service
	used, asked        int            // queries.log's lines; queries this run
	capped             bool           // a query was not asked for the cap
	fails              map[string]int // inconclusive lookups in a row, by address
	stopped            string         // why the run stopped asking, "" while it asks
	log                *os.File
}

// askResult is how ask ended.
type askResult int

const (
	answered     askResult = iota // a conclusive answer, cached or asked
	inconclusive                  // an error or an answer not conclusive, after the retry
	notAsked                      // the cap or a stopped service kept it from being asked
)

// newLookupRun makes dir's cache directories and opens its queries.log.
func newLookupRun(dir string, dial dialFunc, radbAddr, ripeAddr string, limit int) (*lookupRun, error) {
	for _, svc := range []string{"radb", "ripe", "ripe-obj"} {
		if err := os.MkdirAll(filepath.Join(dir, "cache", svc), 0o755); err != nil {
			return nil, err
		}
	}
	logFile := filepath.Join(dir, "queries.log")
	b, err := os.ReadFile(logFile)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	f, err := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, err
	}
	return &lookupRun{dir: dir, dial: dial, radbAddr: radbAddr, ripeAddr: ripeAddr, limit: limit,
		timeout: 30 * time.Second, wait: time.Sleep, stopAfter: 5, used: strings.Count(string(b), "\n"),
		fails: map[string]int{}, log: f}, nil
}

func (r *lookupRun) close() error { return r.log.Close() }

// ask returns svc's cached answer to ref's query, when conclusive says it
// is one, or asks it of addr, once more r.wait(5 s) later when the first
// answer is an error or not conclusive. A cached answer that is not
// conclusive is moved to .bad.txt and asked again. A conclusive answer is
// cached (.txt); an inconclusive one is returned only for the record, kept as
// .bad.txt, and counts toward stopping addr: after r.stopAfter of them in a
// row the run asks nothing more of any service (a rate limit or a refused
// query form would otherwise spend the cap).
func (r *lookupRun) ask(ctx context.Context, svc, addr string, ref types.SetRef, query string, conclusive func(string) bool) (string, askResult, error) {
	file := filepath.Join(r.dir, "cache", svc, cacheName(ref.String()))
	if b, err := os.ReadFile(file + ".txt"); err == nil {
		if conclusive(string(b)) {
			return string(b), answered, nil
		}
		if err := os.Rename(file+".txt", file+".bad.txt"); err != nil {
			return "", notAsked, err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", notAsked, err
	}
	var text, why string
	for try := range 2 {
		if r.stopped != "" {
			return "", notAsked, nil
		}
		if r.used >= r.limit {
			r.capped = true
			return "", notAsked, nil
		}
		if try > 0 {
			r.wait(5 * time.Second)
		}
		qctx, cancel := context.WithTimeout(ctx, r.timeout)
		var qerr error
		text, qerr = whoisQuery(qctx, r.dial, addr, query)
		cancel()
		r.used++
		r.asked++
		why = "an answer that is not conclusive"
		msg := ""
		if qerr != nil {
			msg = strings.Join(strings.Fields(qerr.Error()), " ")
			why = msg
		}
		if _, err := fmt.Fprintf(r.log, "%s\t%s\t%s\t%d\t%s\n", time.Now().UTC().Format(time.RFC3339), svc, query, len(text), msg); err != nil {
			return "", notAsked, err
		}
		if qerr == nil && conclusive(text) {
			r.fails[addr] = 0
			return text, answered, writeAtomic(file+".txt", text)
		}
	}
	if r.fails[addr]++; r.fails[addr] >= r.stopAfter {
		r.stopped = fmt.Sprintf("%s after %d inconclusive lookups in a row (the last: %s)", addr, r.fails[addr], why)
	}
	return text, inconclusive, writeAtomic(file+".bad.txt", text)
}

// writeAtomic writes file through a temp file in its directory and a
// rename, so a cache file is whole or absent.
func writeAtomic(file, text string) error {
	f, err := os.CreateTemp(filepath.Dir(file), ".tmp-*")
	if err != nil {
		return err
	}
	_, err = f.WriteString(text)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(f.Name(), file)
	}
	if err != nil {
		os.Remove(f.Name())
	}
	return err
}

// naming is the objects whose class line names name in name's own class: a
// route-set named AS-X is not a copy of the as-set AS-X.
func naming(objs []string, name types.SetName) []string {
	var out []string
	for _, o := range objs {
		if m := setClassLine.FindStringSubmatch(o); m != nil && strings.EqualFold(m[1], name.Class().String()) &&
			canonSet(m[2]) == name.String() {
			out = append(out, o)
		}
	}
	return out
}

// lookupSet classifies ref (see TestMissingSetsLookup) and returns its
// copies. An answer is read only when ask found it conclusive: a found answer
// with no object naming the set is not, and an inconclusive lookup is "bad"
// whatever its text holds.
func (r *lookupRun) lookupSet(ctx context.Context, ref types.SetRef) (setLookup, []string, error) {
	name := ref.Name()
	notLooked := func(err error) (setLookup, []string, error) {
		return setLookup{Set: ref.String(), Class: "not looked up"}, nil, err
	}
	names := func(parse func(string) ([]string, string)) func(string) bool {
		return func(s string) bool {
			objs, k := parse(s)
			return k == "none" || k == "found" && len(naming(objs, name)) > 0
		}
	}
	held, radb, ripe, deleted := r.held.has(ref), "", ripeSkipped, ""
	var radbObjs, ripeObjs []string
	if !held {
		text, res, err := r.ask(ctx, "radb", r.radbAddr, ref, radbQuery(ref), names(parseRADB))
		if err != nil || res == notAsked {
			return notLooked(err)
		}
		if radb = "bad"; res == answered {
			radbObjs, radb = parseRADB(text)
			radbObjs = naming(radbObjs, name)
		}
		if radb != "found" && (!ref.IsScoped() || ref.Source() == "RIPE") {
			text, res, err := r.ask(ctx, "ripe", r.ripeAddr, ref, ripeQuery(ref), func(s string) bool { k, _ := parseRIPEHistory(s); return k != "bad" })
			if err != nil || res == notAsked {
				return notLooked(err)
			}
			if ripe = "bad"; res == answered {
				ripe, deleted = parseRIPEHistory(text)
			}
			if ripe == "exists" {
				text, res, err := r.ask(ctx, "ripe-obj", r.ripeAddr, ref, ripeObjQuery(ref), names(parseRIPEObjects))
				if err != nil || res == notAsked {
					return notLooked(err)
				}
				if res == answered {
					objs, _ := parseRIPEObjects(text)
					ripeObjs = naming(objs, name)
				}
			}
		}
	}
	row := classifySet(held, radb, radbObjs, ripe, deleted, ripeObjs)
	row.Set = ref.String()
	return row, slices.Concat(radbObjs, ripeObjs), nil
}

// lookupAll looks up every ref in turn and writes sets.tsv (sorted by set)
// and extra.db.gz (each copy going into run B once, as returned, separated by
// blank lines).
func (r *lookupRun) lookupAll(ctx context.Context, refs []types.SetRef) ([]setLookup, error) {
	var rows []setLookup
	var extra []string
	for _, ref := range refs {
		row, copies, err := r.lookupSet(ctx, ref)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", ref, err)
		}
		rows = append(rows, row)
		for _, o := range copies {
			if inB(o) && !slices.Contains(extra, o) {
				extra = append(extra, o)
			}
		}
	}
	slices.SortFunc(rows, func(a, b setLookup) int { return cmp.Compare(a.Set, b.Set) })
	err := writeFileChecked(filepath.Join(r.dir, "sets.tsv"), func(w *bufio.Writer) error {
		for _, x := range rows {
			yes := map[bool]string{true: "yes", false: "no"}[x.InB]
			if _, err := fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n", x.Set, x.Class, x.Sub, x.Copies, x.Deleted, yes); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return rows, writeFileChecked(filepath.Join(r.dir, "extra.db.gz"), func(w *bufio.Writer) error {
		z := gzip.NewWriter(w)
		if _, err := io.WriteString(z, strings.Join(extra, "\n")); err != nil {
			return err
		}
		return z.Close()
	})
}
