package cli

import (
	"context"
	"io"
	"runtime"

	"github.com/rkolesnichenko/mrt"
)

// inputKind is a kind of input file the command decompresses.
type inputKind int

const (
	kindMRT  inputKind = iota // -session and -collector
	kindRPSL                  // -dump and -policy
	kindVRPs                  // -vrps
)

// serialKinds are the kinds read with no workers, exactly as mrt.Decompress
// reads. RPSL dumps measured no faster in parallel (decision 7 of
// docs/superpowers/specs/2026-10-21-parallel-decompress-design.md).
var serialKinds = map[inputKind]bool{kindRPSL: true}

// workersFor is the number of goroutines that decompress an input of kind
// k: min(4, GOMAXPROCS), and 0 (mrt.Decompress itself) when GOMAXPROCS is 1
// or k is in serialKinds. Tests replace it to reach the parallel path.
var workersFor = func(k inputKind) int {
	if serialKinds[k] {
		return 0
	}
	if n := min(4, runtime.GOMAXPROCS(0)); n > 1 {
		return n
	}
	return 0
}

// decompress reads r through gzip or bzip2 when it is compressed, with
// workersFor(k) workers (mrt.DecompressWith). The caller must cancel ctx
// when it stops reading before io.EOF or an error, to end the goroutines
// DecompressWith started. After a cancel a Read returns ctx.Err() only when
// workersFor(k) > 0, the input is compressed and its output has not ended;
// with no workers ctx is ignored.
func decompress(ctx context.Context, r io.Reader, k inputKind) (io.Reader, error) {
	return mrt.DecompressWith(r, mrt.DecompressOptions{Workers: workersFor(k), Context: ctx})
}
