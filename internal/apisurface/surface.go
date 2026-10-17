package main

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// pkg is one public package: its directory below the repository root and its
// parsed non-test files.
type pkg struct {
	dir   string // slash-separated; "." for the root
	fset  *token.FileSet
	files []*ast.File
}

// skipped reports whether the walk leaves a directory out: nothing below
// internal/, cmd/, examples/ or testdata/ is public, nor anything hidden.
func skipped(name string) bool {
	switch name {
	case "internal", "cmd", "examples", "testdata", "vendor":
		return true
	}
	return strings.HasPrefix(name, ".") || strings.HasPrefix(name, "_")
}

// discover returns the public packages below root, sorted by directory: every
// directory holding non-test Go files of a package other than main. Files are
// parsed, not type-checked, so no module plumbing is needed.
func discover(root string) ([]*pkg, error) {
	var pkgs []*pkg
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			return nil
		}
		if path != root && skipped(d.Name()) {
			return filepath.SkipDir
		}
		p, err := parseDir(root, path)
		if p != nil {
			pkgs = append(pkgs, p)
		}
		return err
	})
	slices.SortFunc(pkgs, func(a, b *pkg) int { return strings.Compare(a.dir, b.dir) })
	return pkgs, err
}

// parseDir parses dir's non-test Go files; it returns nil for a directory with
// none, or holding package main.
func parseDir(root, dir string) (*pkg, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	rel, err := filepath.Rel(root, dir)
	if err != nil {
		return nil, err
	}
	p := &pkg{dir: filepath.ToSlash(rel), fset: token.NewFileSet()}
	for _, e := range entries {
		n := e.Name()
		if e.IsDir() || !strings.HasSuffix(n, ".go") || strings.HasSuffix(n, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(p.fset, filepath.Join(dir, n), nil, parser.SkipObjectResolution)
		if err != nil {
			return nil, err
		}
		if f.Name.Name == "main" {
			return nil, nil
		}
		p.files = append(p.files, f)
	}
	if len(p.files) == 0 {
		return nil, nil
	}
	return p, nil
}

// goldenName is the file under api/ holding the surface of the package in dir.
func goldenName(dir string) string {
	if dir == "." {
		return "routecheck.txt"
	}
	return strings.ReplaceAll(dir, "/", "_") + ".txt"
}

// typeDecl is one exported type: its head line, its members (exported struct
// fields, or every element of an interface) in declaration order, and its
// exported methods by name.
type typeDecl struct {
	head    string
	members []string
	methods map[string]string
}

// render returns p's surface: a package line, then the consts, vars, funcs and
// types, each sorted by name, every type followed by its members and then its
// methods sorted by name.
func render(p *pkg) string {
	consts, vars, funcs := map[string]string{}, map[string]string{}, map[string]string{}
	types := map[string]*typeDecl{}
	type method struct{ recv, name, line string }
	var methods []method
	for _, f := range p.files {
		for _, d := range f.Decls {
			switch d := d.(type) {
			case *ast.GenDecl:
				switch d.Tok {
				case token.CONST:
					addConsts(p.fset, d, consts)
				case token.VAR:
					addVars(p.fset, d, vars)
				case token.TYPE:
					for _, s := range d.Specs {
						if ts := s.(*ast.TypeSpec); ts.Name.IsExported() {
							types[ts.Name.Name] = newTypeDecl(p.fset, ts)
						}
					}
				}
			case *ast.FuncDecl:
				if !d.Name.IsExported() {
					continue
				}
				sig := strings.TrimPrefix(text(p.fset, d.Type), "func")
				if d.Recv == nil {
					funcs[d.Name.Name] = "func " + d.Name.Name + sig
					continue
				}
				r := d.Recv.List[0].Type
				methods = append(methods, method{baseName(r), d.Name.Name, "func (" + text(p.fset, r) + ") " + d.Name.Name + sig})
			}
		}
	}
	for _, m := range methods {
		if t, ok := types[m.recv]; ok {
			t.methods[m.name] = m.line
		}
	}
	var b strings.Builder
	b.WriteString("package " + p.files[0].Name.Name + "\n")
	for _, group := range []map[string]string{consts, vars, funcs} {
		for _, name := range slices.Sorted(maps.Keys(group)) {
			b.WriteString(group[name] + "\n")
		}
	}
	for _, name := range slices.Sorted(maps.Keys(types)) {
		t := types[name]
		b.WriteString(t.head + "\n")
		for _, m := range t.members {
			b.WriteString("\t" + m + "\n")
		}
		for _, mn := range slices.Sorted(maps.Keys(t.methods)) {
			b.WriteString(t.methods[mn] + "\n")
		}
	}
	return b.String()
}

// newTypeDecl describes ts: a struct or interface is headed by its kind alone,
// its members listed below it; any other type, an alias included, is one line.
func newTypeDecl(fset *token.FileSet, ts *ast.TypeSpec) *typeDecl {
	t := &typeDecl{methods: map[string]string{}}
	head := *ts
	head.Doc, head.Comment = nil, nil
	switch x := ts.Type.(type) {
	case *ast.StructType:
		head.Type = ast.NewIdent("struct")
		for _, f := range x.Fields.List {
			t.members = append(t.members, fieldLines(fset, f)...)
		}
	case *ast.InterfaceType:
		head.Type = ast.NewIdent("interface")
		for _, f := range x.Methods.List {
			t.members = append(t.members, elemLine(fset, f))
		}
	}
	t.head = "type " + text(fset, &head)
	return t
}

// fieldLines returns a struct field's exported names, one line each, with its
// type and tag; an embedded field is listed when its type is exported.
func fieldLines(fset *token.FileSet, f *ast.Field) []string {
	typ := text(fset, f.Type)
	if f.Tag != nil {
		typ += " " + f.Tag.Value
	}
	if len(f.Names) == 0 {
		if ast.IsExported(baseName(f.Type)) {
			return []string{typ}
		}
		return nil
	}
	var out []string
	for _, n := range f.Names {
		if n.IsExported() {
			out = append(out, n.Name+" "+typ)
		}
	}
	return out
}

// elemLine is one element of an interface, exported or not (an unexported
// method seals the interface, which is API too): a method with its signature,
// or an embedded type or type set.
func elemLine(fset *token.FileSet, f *ast.Field) string {
	if len(f.Names) == 0 {
		return text(fset, f.Type)
	}
	return f.Names[0].Name + strings.TrimPrefix(text(fset, f.Type), "func")
}

// baseName is the name of the type t denotes, without a pointer, a package or
// type arguments: Set for *Set[T], Diagnostic for ast.Diagnostic.
func baseName(t ast.Expr) string {
	for {
		switch x := t.(type) {
		case *ast.StarExpr:
			t = x.X
		case *ast.IndexExpr:
			t = x.X
		case *ast.IndexListExpr:
			t = x.X
		case *ast.SelectorExpr:
			return x.Sel.Name
		case *ast.Ident:
			return x.Name
		default:
			return ""
		}
	}
}

// addConsts records a const declaration's exported names with their type —
// written, or carried down a group from the last spec that has one, as Go
// carries it — and their value where one is written: a constant's value is
// compiled into its callers.
func addConsts(fset *token.FileSet, d *ast.GenDecl, out map[string]string) {
	var typ ast.Expr
	for _, s := range d.Specs {
		vs := s.(*ast.ValueSpec)
		if vs.Type != nil || len(vs.Values) > 0 {
			typ = vs.Type
		}
		for i, n := range vs.Names {
			if !n.IsExported() {
				continue
			}
			line := "const " + n.Name
			if typ != nil {
				line += " " + text(fset, typ)
			}
			if i < len(vs.Values) {
				line += " = " + text(fset, vs.Values[i])
			}
			out[n.Name] = line
		}
	}
}

// addVars records a var declaration's exported names: with the type written,
// or else what the value tells of it — a composite literal's type, a call's
// function, or the expression itself.
func addVars(fset *token.FileSet, d *ast.GenDecl, out map[string]string) {
	for _, s := range d.Specs {
		vs := s.(*ast.ValueSpec)
		for i, n := range vs.Names {
			if !n.IsExported() {
				continue
			}
			line := "var " + n.Name
			switch {
			case vs.Type != nil:
				line += " " + text(fset, vs.Type)
			case i < len(vs.Values):
				line += describe(fset, vs.Values[i])
			}
			out[n.Name] = line
		}
	}
}

// describe is what a var's value says of the var, for a var with no type.
func describe(fset *token.FileSet, v ast.Expr) string {
	switch x := v.(type) {
	case *ast.CompositeLit:
		return " " + text(fset, x.Type)
	case *ast.UnaryExpr:
		if cl, ok := x.X.(*ast.CompositeLit); ok && x.Op == token.AND {
			return " *" + text(fset, cl.Type)
		}
	case *ast.CallExpr:
		return " = " + text(fset, x.Fun) + "(…)"
	}
	return " = " + text(fset, v)
}

var squeeze = strings.NewReplacer("( ", "(", ", )", ")", " )", ")", "[ ", "[", ", ]", "]", " ]", "]")

// text prints n on one line: go/printer's output with each run of white space
// made one space and none just inside brackets, so a signature reads the same
// however its source was wrapped.
func text(fset *token.FileSet, n any) string {
	var buf bytes.Buffer
	if err := printer.Fprint(&buf, fset, n); err != nil {
		panic(err) // n came from go/parser; printing it to memory cannot fail
	}
	return squeeze.Replace(strings.Join(strings.Fields(buf.String()), " "))
}
