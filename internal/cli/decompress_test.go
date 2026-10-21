package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rkolesnichenko/mrt"
)

// The RouteViews slice, gzip and bzip2 (testdata/README.md).
const (
	ribGz  = "testdata/mrt/rv2-rib.20261015.1200.gz"
	ribBz2 = "testdata/mrt/rv2-rib.20261015.1200.bz2"
)

// parallelWorkers makes every kind of input decompress with 4 workers, so
// that the tests reach DecompressWith's parallel path whatever GOMAXPROCS is.
func parallelWorkers(t *testing.T) {
	t.Helper()
	orig := workersFor
	t.Cleanup(func() { workersFor = orig })
	workersFor = func(inputKind) int { return 4 }
}

// yielded is one (record, error) pair of a sequence: the record's bytes and
// the error's text.
type yielded struct {
	raw []byte
	err string
}

// collect ranges over seq to its end. A record's bytes are cloned, since
// they may share a buffer that the next iteration reuses.
func collect(seq func(func(mrt.Record, error) bool)) []yielded {
	var got []yielded
	for rec, err := range seq {
		var y yielded
		if rec != nil {
			y.raw = bytes.Clone(rec.Raw())
		}
		if err != nil {
			y.err = err.Error()
		}
		got = append(got, y)
	}
	return got
}

// serialRecords is the reference: f read through mrt.Decompress, with the
// errors wrapped as readInput wraps them.
func serialRecords(t *testing.T, f string) []yielded {
	t.Helper()
	return collect(func(yield func(mrt.Record, error) bool) {
		file, err := os.Open(f)
		if err != nil {
			t.Fatal(err)
		}
		defer file.Close()
		r, err := mrt.Decompress(file)
		if err != nil {
			yield(nil, fmt.Errorf("%s: %w", f, err))
			return
		}
		for rec, err := range mrt.Records(r) {
			if err != nil {
				err = fmt.Errorf("%s: %w", f, err)
			}
			if !yield(rec, err) {
				return
			}
		}
	})
}

// TestRecordsMatchDecompress: records, decompressing in parallel, yields
// what mrt.Decompress gives, record for record, and the same error, for
// whole and truncated gzip and bzip2 files and for raw MRT.
func TestRecordsMatchDecompress(t *testing.T) {
	parallelWorkers(t)
	gz, bz2 := mustRead(t, ribGz), mustRead(t, ribBz2)
	r, err := mrt.Decompress(bytes.NewReader(gz))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ name, file string }{
		{"gzip", ribGz},
		{"bzip2", ribBz2},
		{"raw", write(t, "rib.mrt", raw)},
		{"truncated gzip", write(t, "half.gz", gz[:len(gz)/2])},
		{"truncated bzip2", write(t, "half.bz2", bz2[:len(bz2)/2])},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := collect(records(context.Background(), []string{tc.file}))
			want := serialRecords(t, tc.file)
			if len(got) != len(want) {
				t.Fatalf("%d yields, want %d", len(got), len(want))
			}
			for i := range got {
				if !bytes.Equal(got[i].raw, want[i].raw) {
					t.Errorf("yield %d: the record's bytes differ", i)
				}
				if got[i].err != want[i].err {
					t.Errorf("yield %d: error %q, want %q", i, got[i].err, want[i].err)
				}
			}
		})
	}
}

// TestRecordsEarlyStopReleases: whether records is ranged to its end or
// stopped after the first record of a compressed file, every goroutine
// DecompressWith started has ended soon after.
func TestRecordsEarlyStopReleases(t *testing.T) {
	parallelWorkers(t)
	inGz := len(serialRecords(t, ribGz))
	for _, tc := range []struct {
		name  string
		after int // records read before the break; -1 reads to the end
	}{
		{"to the end", -1},
		{"break in the bzip2 file", inGz + 1},
		{"break in the gzip file", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			base := runtime.NumGoroutine()
			n := 0
			for _, err := range records(context.Background(), []string{ribGz, ribBz2}) {
				if err != nil {
					t.Fatal(err)
				}
				n++
				if n == tc.after {
					break
				}
			}
			now := runtime.NumGoroutine()
			for i := 0; i < 200 && now > base; i++ {
				time.Sleep(10 * time.Millisecond)
				now = runtime.NumGoroutine()
			}
			if now > base {
				t.Errorf("after %d records, %d goroutines 2 s later, %d before", n, now, base)
			}
		})
	}
}

// TestRecordsCancelMidRead: a cancel while a compressed file is read, after
// some of its records, ends records with context.Canceled before the file's
// last record.
func TestRecordsCancelMidRead(t *testing.T) {
	parallelWorkers(t)
	for _, file := range []string{ribGz, ribBz2} {
		t.Run(file, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var (
				n    int
				last error
			)
			for rec, err := range records(ctx, []string{file}) {
				if rec != nil {
					if n++; n == 10 {
						cancel()
					}
				}
				last = err
			}
			if !errors.Is(last, context.Canceled) {
				t.Errorf("last error %v, want context.Canceled", last)
			}
			if all := len(serialRecords(t, file)); n < 10 || n >= all {
				t.Errorf("%d records, want at least 10 and fewer than the file's %d", n, all)
			}
		})
	}
}

// cancelHalfway replaces openInput so that the file named target, and only
// it, calls cancel once it has returned at least half its size in bytes.
// The decompressed output cannot have ended by then, so the next Read of it
// returns the context's error.
func cancelHalfway(t *testing.T, target string, cancel context.CancelFunc) {
	t.Helper()
	fi, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	orig := openInput
	t.Cleanup(func() { openInput = orig })
	openInput = func(name string) (io.ReadCloser, error) {
		f, err := orig(name)
		if err != nil || name != target {
			return f, err
		}
		return &cancelReader{ReadCloser: f, half: fi.Size() / 2, cancel: cancel}, nil
	}
}

type cancelReader struct {
	io.ReadCloser
	half   int64        // cancel once this many bytes are read
	read   atomic.Int64 // bytes read so far
	cancel context.CancelFunc
}

func (c *cancelReader) Read(p []byte) (int, error) {
	n, err := c.ReadCloser.Read(p)
	if c.read.Add(int64(n)) >= c.half {
		c.cancel()
	}
	return n, err
}

// TestRunCancelMidRead: a run cancelled while its compressed input is read,
// half-way through, ends as an interrupted run does: exit 3, nothing on
// stdout.
func TestRunCancelMidRead(t *testing.T) {
	parallelWorkers(t)
	for _, file := range []string{ribBz2, ribGz} {
		t.Run(file, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			cancelHalfway(t, file, cancel)
			code, stdout, stderr := runCtx(t, ctx, "-local", "AS64496", "-peer", "AS4766", "-collector", file,
				"-dump", registry, "-direction", "import")
			if code != exitFailed {
				t.Errorf("exit %d, want %d; stderr %s", code, exitFailed, stderr)
			}
			if stdout != "" {
				t.Errorf("stdout %q, want nothing", stdout)
			}
			wantContains(t, "stderr", stderr, "context canceled")
		})
	}
}
