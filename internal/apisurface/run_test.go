package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestRun: a fresh golden checks clean; a changed signature, a package with
// no golden and a golden with no package are each reported; an update
// rewrites api/ to match, removing the stale golden.
func TestRun(t *testing.T) {
	root := t.TempDir()
	write := func(name, src string) {
		t.Helper()
		path := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	var out strings.Builder
	check := func(update, wantOK bool) {
		t.Helper()
		out.Reset()
		ok, err := run(root, update, &out)
		if err != nil || ok != wantOK {
			t.Fatalf("run(update=%v) = %v, %v; want %v\n%s", update, ok, err, wantOK, out.String())
		}
	}

	write("a.go", "package a\n\nfunc F(x int) int { return x }\n")
	check(true, true)
	if b, err := os.ReadFile(filepath.Join(root, "api", "routecheck.txt")); err != nil || string(b) != "package a\nfunc F(x int) int\n" {
		t.Fatalf("api/routecheck.txt = %q, %v", b, err)
	}
	check(false, true)

	write("a.go", "package a\n\nfunc F(x int64) int { return int(x) }\n")
	write("b/b.go", "package b\n\nfunc G() {}\n")
	write("api/gone.txt", "package gone\n")
	check(false, false)
	for _, want := range []string{
		"api/b.txt: missing",
		"api/gone.txt: no public package",
		"- func F(x int) int",
		"+ func F(x int64) int",
		"ROUTECHECK_API_UPDATE=1",
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("output lacks %q:\n%s", want, out.String())
		}
	}

	check(true, true)
	if _, err := os.Stat(filepath.Join(root, "api", "gone.txt")); !os.IsNotExist(err) {
		t.Errorf("api/gone.txt survived an update: %v", err)
	}
	check(false, true)
}
