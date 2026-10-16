// Command apisurface keeps api/, the golden of the public API's signatures
// (one file per public package), and checks the API conventions (spec §3,
// C1-C3). scripts/check.sh runs it:
//
//	go run ./internal/apisurface -check                    # compare with api/
//	ROUTECHECK_API_UPDATE=1 go run ./internal/apisurface -check  # rewrite api/; review the diff
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

func main() {
	check := flag.Bool("check", false, "compare api/ with the source and check the conventions (ROUTECHECK_API_UPDATE=1 rewrites api/)")
	root := flag.String("root", ".", "the repository root")
	flag.Parse()
	if !*check || flag.NArg() != 0 {
		flag.Usage()
		os.Exit(2)
	}
	ok, err := run(*root, os.Getenv("ROUTECHECK_API_UPDATE") == "1", os.Stdout)
	if err != nil {
		fmt.Fprintln(os.Stderr, "apisurface:", err)
		os.Exit(2)
	}
	if !ok {
		os.Exit(1)
	}
}

// run renders the public API below root and compares it with root/api — or,
// with update, rewrites root/api to match — then checks the conventions. It
// writes every difference and violation to w and reports whether there were
// none.
func run(root string, update bool, w io.Writer) (bool, error) {
	pkgs, err := discover(root)
	if err != nil {
		return false, err
	}
	want := map[string]string{}
	for _, p := range pkgs {
		want[goldenName(p.dir)] = render(p)
	}
	dir := filepath.Join(root, "api")
	have, err := readGoldens(dir)
	if err != nil {
		return false, err
	}
	ok := true
	if update {
		if err := writeGoldens(dir, have, want); err != nil {
			return false, err
		}
	} else {
		names := maps.Clone(want)
		maps.Copy(names, have)
		for _, name := range slices.Sorted(maps.Keys(names)) {
			wantText, inWant := want[name]
			haveText, inHave := have[name]
			switch {
			case !inHave:
				fmt.Fprintf(w, "api/%s: missing; a public package has no golden\n", name)
			case !inWant:
				fmt.Fprintf(w, "api/%s: no public package has this surface\n", name)
			case wantText != haveText:
				fmt.Fprintf(w, "api/%s differs from the source (- golden, + source):\n", name)
				for _, l := range diffLines(lines(haveText), lines(wantText)) {
					fmt.Fprintln(w, l)
				}
			default:
				continue
			}
			ok = false
		}
		if !ok {
			fmt.Fprintln(w, "ROUTECHECK_API_UPDATE=1 go run ./internal/apisurface -check rewrites api/; review the diff")
		}
	}
	for _, v := range conventions(root, pkgs) {
		fmt.Fprintln(w, v)
		ok = false
	}
	return ok, nil
}

// readGoldens returns the .txt files in dir by name; a missing dir has none.
func readGoldens(dir string) (map[string]string, error) {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return map[string]string{}, nil
	}
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".txt") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, err
		}
		out[e.Name()] = string(b)
	}
	return out, nil
}

// writeGoldens makes dir hold exactly want: stale goldens are removed.
func writeGoldens(dir string, have, want map[string]string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	for name := range have {
		if _, ok := want[name]; !ok {
			if err := os.Remove(filepath.Join(dir, name)); err != nil {
				return err
			}
		}
	}
	for name, text := range want {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(text), 0o644); err != nil {
			return err
		}
	}
	return nil
}

func lines(s string) []string { return strings.Split(strings.TrimSuffix(s, "\n"), "\n") }

// diffLines is a minimal line diff of a against b, by longest common
// subsequence: "- " for a line only in a, "+ " for one only in b, no context.
// A golden is a few hundred lines, so the quadratic table is small.
func diffLines(a, b []string) []string {
	lcs := make([][]int, len(a)+1)
	for i := range lcs {
		lcs[i] = make([]int, len(b)+1)
	}
	for i := len(a) - 1; i >= 0; i-- {
		for j := len(b) - 1; j >= 0; j-- {
			if a[i] == b[j] {
				lcs[i][j] = lcs[i+1][j+1] + 1
			} else {
				lcs[i][j] = max(lcs[i+1][j], lcs[i][j+1])
			}
		}
	}
	var out []string
	i, j := 0, 0
	for i < len(a) || j < len(b) {
		switch {
		case i < len(a) && j < len(b) && a[i] == b[j]:
			i, j = i+1, j+1
		case j < len(b) && (i == len(a) || lcs[i][j+1] >= lcs[i+1][j]):
			out = append(out, "+ "+b[j])
			j++
		default:
			out = append(out, "- "+a[i])
			i++
		}
	}
	return out
}
