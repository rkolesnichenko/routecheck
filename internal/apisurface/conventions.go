package main

import (
	"fmt"
	"go/ast"
	"go/token"
	"maps"
	"path/filepath"
	"slices"
	"strings"
	"unicode"
)

// conventions checks the API conventions (spec §3, C1-C3) over
// pkgs and returns each violation as "file:line: Cn: message", file relative
// to root, in declaration order.
func conventions(root string, pkgs []*pkg) []string {
	var out []string
	for _, p := range pkgs {
		report := func(pos token.Pos, msg string) {
			at := p.fset.Position(pos)
			name, err := filepath.Rel(root, at.Filename)
			if err != nil {
				name = at.Filename
			}
			out = append(out, fmt.Sprintf("%s:%d: %s", filepath.ToSlash(name), at.Line, msg))
		}
		funcs := map[string]*ast.FuncDecl{} // by receiver type and name: "Thing.Parse", ".Parse"
		for _, f := range p.files {
			for _, d := range f.Decls {
				switch d := d.(type) {
				case *ast.FuncDecl:
					checkParseBool(d, report)
					funcs[recvKey(d)+d.Name.Name] = d
				case *ast.GenDecl:
					if d.Tok == token.VAR {
						checkSentinels(d, report)
					}
				}
			}
		}
		checkWith(p.fset, funcs, report)
	}
	return out
}

// recvKey is the receiver part of a function's key in conventions' map: the
// receiver's type name and a dot, or a dot alone for a function.
func recvKey(d *ast.FuncDecl) string {
	if d.Recv == nil {
		return "."
	}
	return baseName(d.Recv.List[0].Type) + "."
}

// checkWith is C1: an exported XWith has a sibling X with the same receiver,
// whose parameters are XWith's less the last (the options) and whose results
// are XWith's. A bare With is not an XWith.
func checkWith(fset *token.FileSet, funcs map[string]*ast.FuncDecl, report func(token.Pos, string)) {
	for _, key := range slices.Sorted(maps.Keys(funcs)) {
		d := funcs[key]
		name := d.Name.Name
		if !d.Name.IsExported() || name == "With" || !strings.HasSuffix(name, "With") {
			continue
		}
		plainName := strings.TrimSuffix(name, "With")
		plain, ok := funcs[strings.TrimSuffix(key, "With")]
		if !ok {
			report(d.Pos(), "C1: "+name+" has no "+plainName)
			continue
		}
		wp, pp := fieldTypes(fset, d.Type.Params), fieldTypes(fset, plain.Type.Params)
		if len(wp) == 0 || !slices.Equal(wp[:len(wp)-1], pp) {
			report(d.Pos(), "C1: "+name+"'s parameters are not "+plainName+"'s plus one options parameter")
		}
		if !slices.Equal(fieldTypes(fset, d.Type.Results), fieldTypes(fset, plain.Type.Results)) {
			report(d.Pos(), "C1: "+name+"'s results are not "+plainName+"'s")
		}
	}
}

// fieldTypes lists a parameter or result list's types, one per name.
func fieldTypes(fset *token.FileSet, fl *ast.FieldList) []string {
	if fl == nil {
		return nil
	}
	var out []string
	for _, f := range fl.List {
		t := text(fset, f.Type)
		for range max(len(f.Names), 1) {
			out = append(out, t)
		}
	}
	return out
}

// checkParseBool is C2: no exported Parse function or method returns bool as
// its last result. Malformed input is an error; comma-ok is for an expected
// false, such as a lookup miss or an empty result.
func checkParseBool(d *ast.FuncDecl, report func(token.Pos, string)) {
	if !d.Name.IsExported() || !strings.HasPrefix(d.Name.Name, "Parse") || d.Type.Results == nil {
		return
	}
	rs := d.Type.Results.List
	if id, ok := rs[len(rs)-1].Type.(*ast.Ident); ok && id.Name == "bool" {
		report(d.Pos(), "C2: "+d.Name.Name+" returns bool as its last result; malformed input is an error")
	}
}

// checkSentinels is C3: every exported ErrX var is declared with errors.New.
func checkSentinels(d *ast.GenDecl, report func(token.Pos, string)) {
	for _, s := range d.Specs {
		vs := s.(*ast.ValueSpec)
		for i, n := range vs.Names {
			if !n.IsExported() || !isSentinelName(n.Name) {
				continue
			}
			if i < len(vs.Values) && isErrorsNew(vs.Values[i]) {
				continue
			}
			report(n.Pos(), "C3: "+n.Name+" is not declared with errors.New")
		}
	}
}

// isSentinelName reports whether name reads as a sentinel error: "Err" and a
// capital (ErrNotFound, not Errors).
func isSentinelName(name string) bool {
	return len(name) > 3 && strings.HasPrefix(name, "Err") && unicode.IsUpper(rune(name[3]))
}

// isErrorsNew reports whether e is a call of errors.New.
func isErrorsNew(e ast.Expr) bool {
	call, ok := e.(*ast.CallExpr)
	if !ok {
		return false
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	pkg, ok := sel.X.(*ast.Ident)
	return ok && pkg.Name == "errors" && sel.Sel.Name == "New"
}
