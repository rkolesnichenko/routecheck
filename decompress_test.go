package routecheck_test

import (
	"bytes"
	"context"
	"io"
	"os"
	"runtime"
	"testing"

	"github.com/rkolesnichenko/mrt"
)

func TestDecompressFileMatches(t *testing.T) {
	for _, name := range []string{
		"testdata/mrt/rv2-rib.20261015.1200.gz",
		"testdata/mrt/rv2-rib.20261015.1200.bz2",
	} {
		t.Run(name, func(t *testing.T) {
			read := func(wrap func(io.Reader) (io.Reader, error)) []byte {
				f, err := os.Open(name)
				if err != nil {
					t.Fatal(err)
				}
				defer f.Close()
				r, err := wrap(f)
				if err != nil {
					t.Fatal(err)
				}
				b, err := io.ReadAll(r)
				if err != nil {
					t.Fatal(err)
				}
				return b
			}
			want := read(mrt.Decompress)
			got := read(func(r io.Reader) (io.Reader, error) {
				d, cancel, err := decompressFile(r)
				if err != nil {
					return nil, err
				}
				t.Cleanup(cancel)
				return d, nil
			})
			if !bytes.Equal(got, want) {
				t.Errorf("decompressFile read %d bytes, mrt.Decompress %d", len(got), len(want))
			}
		})
	}
}

// decompressFile reads r through gzip or bzip2 when it is compressed, in
// parallel as the command does: it mirrors internal/cli's workersFor, which
// is unexported (min(4, GOMAXPROCS) workers, none when GOMAXPROCS is 1). The
// caller defers the returned cancel, which ends the goroutines DecompressWith
// started when it stops reading before io.EOF or an error.
func decompressFile(r io.Reader) (io.Reader, context.CancelFunc, error) {
	workers := 0
	if n := min(4, runtime.GOMAXPROCS(0)); n > 1 {
		workers = n
	}
	ctx, cancel := context.WithCancel(context.Background())
	d, err := mrt.DecompressWith(r, mrt.DecompressOptions{Workers: workers, Context: ctx})
	if err != nil {
		cancel()
		return nil, nil, err
	}
	return d, cancel, nil
}
