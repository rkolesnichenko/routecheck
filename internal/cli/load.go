package cli

import (
	"context"
	"errors"
	"fmt"
	"iter"
	"net"
	"os"
	"slices"
	"strings"

	"github.com/rkolesnichenko/mrt"
	"github.com/rkolesnichenko/rpsl"
	"github.com/rkolesnichenko/rpsl/object"
	"github.com/rkolesnichenko/rpsl/resolve"
	"github.com/rkolesnichenko/rpsl/resolve/irrd"
	"github.com/rkolesnichenko/rpsl/resolve/rpki"
	"github.com/rkolesnichenko/rpsl/types"
)

// inputs are the MRT files of -session or -collector, opened.
type inputs struct {
	names []string
	files []*os.File
}

// openInputs opens every input file, so that a name that cannot be opened
// fails the run before anything is loaded.
func openInputs(names []string) (*inputs, error) {
	in := &inputs{names: names}
	for _, name := range names {
		f, err := os.Open(name)
		if err != nil {
			in.close()
			return nil, err
		}
		in.files = append(in.files, f)
	}
	return in, nil
}

func (in *inputs) close() {
	for _, f := range in.files {
		f.Close()
	}
}

// records reads the inputs one after another, in the order given, each
// through gzip or bzip2 when it is compressed (mrt.Decompress). Every error
// is wrapped with its file's name; the wrapping keeps *mrt.RecordError and
// mrt.ErrTruncated visible to errors.As and errors.Is, which observe reads.
func (in *inputs) records() iter.Seq2[mrt.Record, error] {
	return func(yield func(mrt.Record, error) bool) {
		for i, f := range in.files {
			name := in.names[i]
			r, err := mrt.Decompress(f)
			if err != nil {
				yield(nil, fmt.Errorf("%s: %w", name, err))
				return
			}
			for rec, err := range mrt.Records(r) {
				if err != nil {
					err = fmt.Errorf("%s: %w", name, err)
				}
				if !yield(rec, err) {
					return
				}
			}
		}
	}
}

// readVRPs reads a VRP JSON file (rpki.ReadJSON), compressed or not.
func readVRPs(name string) (*rpki.VRPs, error) {
	f, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	r, err := mrt.Decompress(f)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	v, err := rpki.ReadJSON(r)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	return v, nil
}

// loadPolicy builds the policy source the command line names, wrapped in a
// resolve.Cache (peval reads the same aut-nums and sets for every report),
// and a function that releases it.
//
// With -dump the files are parsed (rpsl.Parse, object.Decode) into one
// resolve.Corpus that keeps policy objects, in the order given; the source
// precedence is the order in which each source: first appears in them, so an
// object of the first dump's registry wins over another registry's. -policy
// is read last into the same Corpus, so its objects replace any of the same
// class, primary key and source (its new sources rank last).
//
// With -irrd the server is an irrd.Source with -sources as its precedence.
//
// Either way, -policy's aut-nums and inet-rtrs also answer before the
// registry's, under any source: a draft written with another source: than
// the registry's is still the one checked. Its sets reach the policy only
// with -dump; with -irrd sets always come from the server (spec §5).
func loadPolicy(cfg *config) (resolve.PolicySource, func(), error) {
	var draftObjs []rpsl.Object
	var draftSources []string
	if cfg.policyFile != "" {
		err := readRPSL(cfg.policyFile, func(o rpsl.Object, source string) {
			draftObjs = append(draftObjs, o)
			if source != "" && !slices.Contains(draftSources, source) {
				draftSources = append(draftSources, source)
			}
		})
		if err != nil {
			return nil, nil, err
		}
	}

	var reg resolve.PolicySource
	closeReg := func() {}
	if len(cfg.dumps) > 0 {
		c := &resolve.Corpus{KeepPolicy: true}
		var order []string
		for _, name := range cfg.dumps {
			err := readRPSL(name, func(o rpsl.Object, source string) {
				if source != "" && !slices.Contains(order, source) {
					order = append(order, source)
				}
				c.Put(o)
			})
			if err != nil {
				return nil, nil, err
			}
		}
		for _, o := range draftObjs {
			c.Put(o)
		}
		for _, s := range draftSources {
			if !slices.Contains(order, s) {
				order = append(order, s)
			}
		}
		reg = c.Source(order...)
	} else {
		host := cfg.irrd
		if _, _, err := net.SplitHostPort(host); err != nil {
			host = net.JoinHostPort(host, "43")
		}
		s := &irrd.Source{Addr: host, Sources: cfg.sources}
		reg, closeReg = s, func() { s.Close() }
	}
	if len(draftObjs) > 0 {
		c := &resolve.Corpus{KeepPolicy: true}
		for _, o := range draftObjs {
			c.Put(o)
		}
		reg = &draftFirst{PolicySource: reg, draft: c.Source(draftSources...)}
	}
	return resolve.NewCache(reg, 0), closeReg, nil
}

// draftFirst answers AutNum and InetRtr from the -policy file's objects
// first, and from the registry when the file has none; everything else
// (sets, routes) from the registry.
type draftFirst struct {
	resolve.PolicySource
	draft *resolve.MemSource
}

func (d *draftFirst) AutNum(ctx context.Context, as types.ASN, source string) (*object.AutNum, error) {
	a, err := d.draft.AutNum(ctx, as, source)
	if err == nil || !errors.Is(err, resolve.ErrNotFound) {
		return a, err
	}
	return d.PolicySource.AutNum(ctx, as, source)
}

func (d *draftFirst) InetRtr(ctx context.Context, name, source string) (*object.InetRtr, error) {
	r, err := d.draft.InetRtr(ctx, name, source)
	if err == nil || !errors.Is(err, resolve.ErrNotFound) {
		return r, err
	}
	return d.PolicySource.InetRtr(ctx, name, source)
}

// readRPSL parses an RPSL file (a dump or -policy), compressed or not, and
// calls fn with each object, decoded, and its source: in upper case ("" when
// it has none). A failure to read the file is an error naming it, so that a
// truncated dump is never taken for a short one.
func readRPSL(name string, fn func(o rpsl.Object, source string)) error {
	f, err := os.Open(name)
	if err != nil {
		return err
	}
	defer f.Close()
	r, err := mrt.Decompress(f)
	if err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	for o, ds := range rpsl.Parse(r) {
		for _, d := range ds {
			if d.Rule == "rpsl/read-error" {
				return fmt.Errorf("%s: reading: %s", name, d.Message)
			}
		}
		if o == nil {
			continue
		}
		obj, _ := rpsl.Decode(o)
		if obj == nil {
			continue
		}
		source := ""
		for _, a := range o.Attributes() {
			if f := strings.Fields(a.Value); strings.EqualFold(a.Name, "source") && len(f) > 0 {
				source = strings.ToUpper(f[0])
				break
			}
		}
		fn(obj, source)
	}
	return nil
}
