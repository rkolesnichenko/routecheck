package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rkolesnichenko/mrt"
	"github.com/rkolesnichenko/rpsl"
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

// TestSerialKinds: by default RPSL files are read with no workers, and MRT
// and VRP files with min(4, GOMAXPROCS), none when GOMAXPROCS is 1.
func TestSerialKinds(t *testing.T) {
	if n := workersFor(kindRPSL); n != 0 {
		t.Errorf("workersFor(kindRPSL) = %d, want 0", n)
	}
	want := 0
	if n := min(4, runtime.GOMAXPROCS(0)); n > 1 {
		want = n
	}
	for k, name := range map[inputKind]string{kindMRT: "kindMRT", kindVRPs: "kindVRPs"} {
		if n := workersFor(k); n != want {
			t.Errorf("workersFor(%s) = %d, want %d", name, n, want)
		}
	}
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
			// The bz2 subcase cancels before the first record: mrt's parallel
			// bzip2 reader reads past half the small fixture before returning
			// output. The bz2 mid-stream cancel is covered by
			// TestRecordsCancelMidRead.
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

// noWorkers makes every kind of input decompress with no worker, as
// mrt.Decompress does.
func noWorkers(t *testing.T) {
	t.Helper()
	orig := workersFor
	t.Cleanup(func() { workersFor = orig })
	workersFor = func(inputKind) int { return 0 }
}

// bigRegistry is the golden registry repeated until it is at least 1 MiB,
// so that the gzip readahead hands over more than one chunk. Each copy has
// keys of its own: its ASNs shifted by 100000 a copy, its as-set renamed and
// every route and route6 given a prefix of its own.
func bigRegistry(t *testing.T) []byte {
	t.Helper()
	reg := string(mustRead(t, registry))
	asn := regexp.MustCompile(`\bAS[0-9]+\b`)
	route := regexp.MustCompile(`(?m)^(route6?:\s+)\S+`)
	var b strings.Builder
	n := 0 // the routes so far
	for i := 0; b.Len() < 1<<20; i++ {
		c := asn.ReplaceAllStringFunc(reg, func(m string) string {
			v, err := strconv.ParseUint(m[2:], 10, 32)
			if err != nil {
				t.Fatal(err)
			}
			return "AS" + strconv.FormatUint(v+uint64(i)*100000, 10)
		})
		c = strings.ReplaceAll(c, "AS-GOLDEN-BEHIND", "AS-GOLDEN-BEHIND-"+strconv.Itoa(i))
		c = route.ReplaceAllStringFunc(c, func(m string) string {
			head := route.FindStringSubmatch(m)[1]
			n++
			if strings.HasPrefix(head, "route6") {
				return fmt.Sprintf("%s2001:db8:%x::/48", head, n)
			}
			return fmt.Sprintf("%s10.%d.%d.0/24", head, n>>8, n&0xff)
		})
		if i > 0 {
			b.WriteString("\n")
		}
		b.WriteString(c)
	}
	return []byte(b.String())
}

// rpslObject is what readRPSL hands its function for one object, as text.
type rpslObject struct{ class, key, source, text, diags string }

func readRPSLAll(t *testing.T, name string) []rpslObject {
	t.Helper()
	var got []rpslObject
	err := readRPSL(context.Background(), name, func(o rpsl.Object, class, key, source string, diags []rpsl.Diagnostic) {
		got = append(got, rpslObject{class, key, source, o.Raw().String(), fmt.Sprint(diags)})
	})
	if err != nil {
		t.Fatal(err)
	}
	return got
}

// TestReadRPSLMatchesDecompress: readRPSL hands over the same objects from a
// 1 MiB registry, raw or gzipped, decompressed with no worker or with 4, and
// readDraft reads the same draft from the gzipped file either way, with the
// same warnings.
func TestReadRPSLMatchesDecompress(t *testing.T) {
	text := bigRegistry(t)
	raw := write(t, "registry.txt", text)
	gz := write(t, "registry.txt.gz", gzipped(t, text))
	modes := []struct {
		name  string
		force func(*testing.T)
	}{{"workers=0", noWorkers}, {"workers=4", parallelWorkers}}

	var want []rpslObject
	for _, file := range []struct{ name, path string }{{"raw", raw}, {"gzip", gz}} {
		for _, m := range modes {
			t.Run(file.name+"/"+m.name, func(t *testing.T) {
				m.force(t)
				got := readRPSLAll(t, file.path)
				if want == nil {
					want = got
					if len(want) == 0 {
						t.Fatal("no object")
					}
					return
				}
				if !reflect.DeepEqual(got, want) {
					t.Errorf("%d objects differ from the first read's %d", len(got), len(want))
				}
			})
		}
	}

	type draftRead struct {
		objs, sources, supplies []string
		stderr                  string
	}
	var wantDraft *draftRead
	autNums := len(regexp.MustCompile(`(?m)^aut-num:`).FindAll(text, -1))
	for _, m := range modes {
		t.Run("draft/"+m.name, func(t *testing.T) {
			m.force(t)
			var stderr bytes.Buffer
			d, err := readDraft(context.Background(), gz, &stderr)
			if err != nil {
				t.Fatal(err)
			}
			got := &draftRead{sources: d.sources, supplies: d.supplies, stderr: stderr.String()}
			for _, o := range d.objs {
				got.objs = append(got.objs, o.Raw().String())
			}
			if wantDraft == nil {
				wantDraft = got
				if len(got.supplies) != autNums {
					t.Errorf("the draft supplies %d objects, want the file's %d aut-nums", len(got.supplies), autNums)
				}
				return
			}
			if !reflect.DeepEqual(got, wantDraft) {
				t.Errorf("the draft differs from the first read's: %d objects, %d supplies, %d bytes on stderr; want %d, %d, %d",
					len(got.objs), len(got.supplies), len(got.stderr), len(wantDraft.objs), len(wantDraft.supplies), len(wantDraft.stderr))
			}
		})
	}
}

// TestRunCancelDuringDump: a run cancelled while its gzipped -dump is read,
// half-way through, ends as an interrupted run does: exit 3, nothing on
// stdout, the cause on stderr.
func TestRunCancelDuringDump(t *testing.T) {
	parallelWorkers(t) // the default for RPSL is serial, which ignores the cancel
	dump := write(t, "registry.txt.gz", gzipped(t, bigRegistry(t)))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cancelHalfway(t, dump, cancel)
	code, stdout, stderr := runCtx(t, ctx, "-local", "AS64496", "-peer", "AS64500", "-session", capture, "-dump", dump)
	if code != exitFailed {
		t.Errorf("exit %d, want %d; stderr %s", code, exitFailed, stderr)
	}
	if stdout != "" {
		t.Errorf("stdout %q, want nothing", stdout)
	}
	wantContains(t, "stderr", stderr, dump+": reading: ", "context canceled")
}

// TestReadVRPsGzip: readVRPs reads the same VRPs from a gzipped file,
// decompressed with 4 workers, as from the raw one.
func TestReadVRPsGzip(t *testing.T) {
	parallelWorkers(t)
	const raw = "testdata/rpki/vrps.json"
	want, err := readVRPs(context.Background(), raw)
	if err != nil {
		t.Fatal(err)
	}
	got, err := readVRPs(context.Background(), write(t, "vrps.json.gz", gzipped(t, mustRead(t, raw))))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("the gzipped file's VRPs differ from the raw file's")
	}
}

// BenchmarkReadVRPs reads the VRP file that ROUTECHECK_BENCH_VRPS names
// (relative to the repository's root) with no worker and with workersFor's
// own count. It is opt-in: skipped when the variable is unset.
func BenchmarkReadVRPs(b *testing.B) {
	name := os.Getenv("ROUTECHECK_BENCH_VRPS")
	if name == "" {
		b.Skip("set ROUTECHECK_BENCH_VRPS to a VRP JSON file to benchmark readVRPs")
	}
	fi, err := os.Stat(name)
	if err != nil {
		b.Fatal(err)
	}
	orig := workersFor
	for _, bc := range []struct {
		name    string
		workers func(inputKind) int
	}{
		{"workers=0", func(inputKind) int { return 0 }},
		{"workers=default", orig},
	} {
		b.Run(bc.name, func(b *testing.B) {
			workersFor = bc.workers
			b.Cleanup(func() { workersFor = orig })
			b.SetBytes(fi.Size())
			for range b.N {
				if _, err := readVRPs(context.Background(), name); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
