package cli

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/rkolesnichenko/routecheck"
	"github.com/rkolesnichenko/routecheck/verdict"
	"github.com/rkolesnichenko/rpsl/resolve/peval"
)

// The JSON the command writes (spec §8) is []routecheck.Result as a view
// that keeps every field name of Result, Report, RouteVerdict, Verdict, Fail
// and Route, with values a reader needs no Go source for. Each view type
// embeds the type it shows and shadows the fields whose Go encoding is not
// readable:
//
//   - a policy is its clauses as {Index, Term, Filter}: the attribute's
//     position (peval's Clause.Index, 0-based: the import:/mp-import: or
//     export:/mp-export: attribute the clause comes from), the term as
//     written ("from AS1 accept AS-X") and its normalized filter
//     (resolve.NormalFilter's String: prefix ranges, regexps, community
//     tests); and its undecided terms as {Index, Term, Why}. The expanded
//     sets inside a filter (they can be millions of prefixes) and peval's
//     Clause.Actions and Clause.Remote are left out. A clause's Index is not
//     its position: Verdict.Clause, Verdict.EarlierUndecided, Fails[].Clause
//     and Reasons[].Clause are positions in the Clauses array (0-based), and
//     one attribute with REFINE or EXCEPT gives several clauses of one
//     Index;
//   - an outcome is "accepted", "rejected" or "undecided"; an RPKI state
//     "valid", "invalid" or "not_found" (rpki.State's String);
//   - communities are "hi:lo"; missing sets are their names; a verdict's
//     AnySets is the names of the sets reaching AS-ANY that let the route
//     through (Verdict.AnySets), null when none;
//   - a report whose policy peval could not evaluate (ruling R19, R21) has
//     Unevaluable set to the error's text (also with no routes), an empty
//     Policy, and each of its routes one reason of Kind "unevaluable" whose
//     Why is that text and whose Clause and Index are -1; Unevaluable is
//     "" for every other report.
//
// Every other field (AF, Coverage, Evidence, ASNs, prefixes, times, the
// reasons) is Go's own encoding, which is text or numbers already.

type jsonResult struct {
	routecheck.Result
	Import *jsonReport
	Export []jsonReport
}

type jsonReport struct {
	routecheck.Report
	Policy jsonPolicy
	Routes []jsonRouteVerdict
}

type jsonPolicy struct {
	Clauses   []jsonClause
	Undecided []jsonUndecided
}

type jsonClause struct {
	Index  int
	Term   string
	Filter string
}

type jsonUndecided struct {
	Index int
	Term  string // "" for an attribute peval skipped whole
	Why   string
}

type jsonRouteVerdict struct {
	routecheck.RouteVerdict
	Route   jsonRoute
	Verdict jsonVerdict
	RPKI    *string
}

type jsonRoute struct {
	verdict.Route
	Communities []string
}

type jsonVerdict struct {
	verdict.Verdict
	Outcome string
	Fails   []jsonFail
}

type jsonFail struct {
	verdict.Fail
	Missing []string
}

// writeJSON writes the results' view as one JSON document.
func writeJSON(w io.Writer, results []routecheck.Result) error {
	view := make([]jsonResult, len(results))
	for i, r := range results {
		view[i] = jsonResult{Result: r}
		// The embedded originals are shadowed: not held twice.
		view[i].Result.Import, view[i].Result.Export = nil, nil
		if r.Import != nil {
			rep := viewReport("import", *r.Import)
			view[i].Import = &rep
		}
		if r.Export != nil {
			view[i].Export = make([]jsonReport, len(r.Export))
			for j, e := range r.Export {
				view[i].Export[j] = viewReport("export", e)
			}
		}
	}
	return encodeJSON(w, view)
}

func encodeJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false) // AS-path regexps are written <...>
	return enc.Encode(v)
}

// viewReport is rep's view; dir ("import" or "export") words its terms.
func viewReport(dir string, rep routecheck.Report) jsonReport {
	out := jsonReport{Report: rep}
	out.Report.Policy, out.Report.Routes = peval.Policy{}, nil
	for _, c := range rep.Policy.Clauses {
		out.Policy.Clauses = append(out.Policy.Clauses, jsonClause{Index: c.Index, Term: termText(dir, c.Term), Filter: c.Filter.String()})
	}
	for _, u := range rep.Policy.Undecided {
		t := ""
		if u.Term.Peering != nil || u.Term.Filter != nil {
			t = termText(dir, u.Term)
		}
		out.Policy.Undecided = append(out.Policy.Undecided, jsonUndecided{Index: u.Index, Term: t, Why: u.Why})
	}
	if rep.Routes != nil {
		out.Routes = make([]jsonRouteVerdict, len(rep.Routes))
	}
	for i, rv := range rep.Routes {
		v := jsonRouteVerdict{
			RouteVerdict: rv,
			Route:        jsonRoute{Route: rv.Route},
			Verdict:      jsonVerdict{Verdict: rv.Verdict, Outcome: rv.Verdict.Outcome.String()},
		}
		v.RouteVerdict.Route, v.RouteVerdict.Verdict, v.RouteVerdict.RPKI = verdict.Route{}, verdict.Verdict{}, nil
		if rv.Route.Communities != nil {
			v.Route.Communities = make([]string, len(rv.Route.Communities))
			for j, c := range rv.Route.Communities {
				v.Route.Communities[j] = fmt.Sprintf("%d:%d", c>>16, c&0xffff)
			}
		}
		for _, f := range rv.Verdict.Fails {
			jf := jsonFail{Fail: f}
			if f.Missing != nil {
				jf.Missing = make([]string, len(f.Missing))
				for k, m := range f.Missing {
					jf.Missing[k] = m.String()
				}
			}
			v.Verdict.Fails = append(v.Verdict.Fails, jf)
		}
		if rv.RPKI != nil {
			s := rv.RPKI.String()
			v.RPKI = &s
		}
		out.Routes[i] = v
	}
	return out
}
