package cli

import (
	"encoding/json"
	"io"

	"github.com/rkolesnichenko/routecheck"
)

// writeJSON writes the results as one JSON document: []routecheck.Result
// with Go's field names (spec §8). Values without exported fields (a
// resolve.RangeSet or ASNSet inside a policy's filters) encode as {}: the
// policy's text is in each clause's Term.
func writeJSON(w io.Writer, results []routecheck.Result) error {
	if results == nil {
		results = []routecheck.Result{}
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false) // AS-path regexps are written <...>
	return enc.Encode(results)
}
