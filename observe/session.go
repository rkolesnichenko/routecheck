package observe

import (
	"cmp"
	"errors"
	"iter"
	"net/netip"
	"slices"
	"time"

	"github.com/rkolesnichenko/mrt"
	"github.com/rkolesnichenko/mrt/bgp"
	"github.com/rkolesnichenko/routecheck/verdict"
	"github.com/rkolesnichenko/rpsl/types"
)

// ErrRIBNotPrePolicy is Session's error for a RIB dump in its input when
// SessionSel.PrePolicyRIB is not set.
var ErrRIBNotPrePolicy = errors.New("observe: a RIB dump is a post-policy table; pass PrePolicyRIB if it is an Adj-RIB-In")

// SessionSel selects the session Session replays.
type SessionSel struct {
	Peer         types.ASN  // X: records whose peer AS is Peer
	PeerAddr     netip.Addr // when valid, only records whose peer address is PeerAddr
	At           time.Time  // the state at this time (records at At included); zero: at the end
	PrePolicyRIB bool       // RIB dumps in the input are X's Adj-RIB-In before import policy
}

// SessionInfo is what Session found about the capture besides the routes.
type SessionInfo struct {
	// The first selected BGP4MP record's local AS and addresses (a hint for
	// the router addresses; zero when no BGP4MP record was selected).
	LocalAS             types.ASN
	LocalAddr, PeerAddr netip.Addr

	// MidSession: a session's state at the end descends from an UPDATE seen
	// with no transition into Established (or RIB dump) before it, so routes
	// X announced before the capture began are missing.
	MidSession bool
	// DownAtEnd: every selected session was down at the end (its last state
	// change, or a malformed reset, left it down and no UPDATE followed); the
	// result is empty.
	DownAtEnd bool
	// NoRecordsBeforeAt: At is set and every selected record is after it.
	NoRecordsBeforeAt bool

	NotFirstAS      int // announcements whose path does not start with X: skipped, and the key's earlier route deleted
	Malformed       int // announcements treated as withdrawals (RFC 7606 treat-as-withdraw; a RIB entry counts one)
	MalformedResets int // UPDATEs RFC 7606 answers with a session reset: the session's state was cleared and it is down until X's next UPDATE
	Skipped         int // records mrt could not read (a *mrt.RecordError), and RIB entries it could not frame or place
}

// Session replays the BGP messages X sent on a session (BGP4MP and
// BGP4MP_ET, non-LOCAL subtypes) and yields X's Adj-RIB-Out toward the local
// AS at the end of the capture, or at sel.At, in prefix order (then address
// family, then add-path ID, then peer address). It reads the whole input before it yields
// anything. The info function is valid after the sequence is drained.
//
// The rules (spec §6.2, controller ruling R8):
//   - A record is selected when its peer AS is sel.Peer and, if
//     sel.PeerAddr is valid, its peer address is sel.PeerAddr. Each peer
//     address is a session of its own, with its own Adj-RIB-Out; the result
//     is their union, and Evidence.PeerAddr says which session a route is
//     from. Two sessions holding the same key give two observations, even
//     when their routes are identical.
//   - The state is keyed by (address family, prefix, add-path ID; 0 for a
//     message without add-path). In an UPDATE the withdrawals are applied
//     first, then the announcements; an announcement replaces the key's route.
//   - Every state change clears the session's state: into Established a
//     new session begins, and in any other state there is no session.
//   - An announcement whose path is empty or does not start with an
//     AS_SEQUENCE whose first AS is X is not a route: the key's earlier route
//     is deleted and it is counted in NotFirstAS.
//   - RFC 7606 decides a malformed UPDATE (see classify): treat-as-withdraw
//     deletes its announcements' keys (Malformed), and a session reset, or a
//     BGP message header that does not parse, clears the state and leaves the
//     session down until X's next UPDATE (MalformedResets).
//   - Records after sel.At are not applied.
//   - A RIB dump (TABLE_DUMP_V2 or TABLE_DUMP) ends the sequence with
//     ErrRIBNotPrePolicy unless sel.PrePolicyRIB. Then a dump is a baseline:
//     a PEER_INDEX_TABLE (or the first record of a run of legacy TABLE_DUMP
//     records) clears the state of every selected session it names, and each
//     entry for the peer is an announcement, so UPDATEs before the dump are
//     superseded and UPDATEs after it apply on top.
//
// A *mrt.RecordError from records is counted in Skipped; any other error
// (a truncated stream, a read error) is yielded and ends the sequence with no
// observations. Observations from one UPDATE or RIB entry share their Path
// and Communities slices; callers must not modify them.
func Session(records iter.Seq2[mrt.Record, error], sel SessionSel) (iter.Seq2[Observation, error], func() SessionInfo) {
	var info SessionInfo
	seq := func(yield func(Observation, error) bool) {
		r := replay{sel: sel, sessions: map[netip.Addr]*session{}}
		obs, err := r.run(records)
		info = r.info
		if err != nil {
			yield(Observation{}, err)
			return
		}
		for _, o := range obs {
			if !yield(o, nil) {
				return
			}
		}
	}
	return seq, func() SessionInfo { return info }
}

// key is one route of a session's Adj-RIB-Out.
type key struct {
	fam    bgp.Family
	prefix netip.Prefix
	id     uint32
}

// session is the replay state of one peer address.
type session struct {
	addr     netip.Addr
	routes   map[key]Observation
	complete bool // a transition into Established, a RIB baseline or a reset since the last clear
	mid      bool // an UPDATE was applied while not complete
	down     bool // the last event was a state change out of (or not into) Established, or a reset
	ribGen   int  // the RIB baseline this session's state was last cleared for
}

func (s *session) clear(complete bool) {
	clear(s.routes)
	s.complete, s.mid = complete, false
}

// replay is one run of Session.
type replay struct {
	sel             SessionSel
	info            SessionInfo
	sessions        map[netip.Addr]*session
	table           []mrt.Peer // the latest PEER_INDEX_TABLE's peers
	before, after   int        // selected records at or before At, and after it
	sawFirstMessage bool
	ribGen          int  // counts RIB baselines: PEER_INDEX_TABLEs and runs of TABLE_DUMP records
	inTableDump     bool // the previous record was a legacy TABLE_DUMP
}

func (r *replay) selected(as bgp.ASN, addr netip.Addr) bool {
	return types.ASN(as) == r.sel.Peer && (!r.sel.PeerAddr.IsValid() || addr == r.sel.PeerAddr)
}

// applies counts a selected record and reports whether it is at or before At.
func (r *replay) applies(t time.Time) bool {
	if !r.sel.At.IsZero() && t.After(r.sel.At) {
		r.after++
		return false
	}
	r.before++
	return true
}

func (r *replay) session(addr netip.Addr) *session {
	s := r.sessions[addr]
	if s == nil {
		s = &session{addr: addr, routes: map[key]Observation{}}
		r.sessions[addr] = s
	}
	return s
}

func (r *replay) first(localAS bgp.ASN, local, peer netip.Addr) {
	if !r.sawFirstMessage {
		r.sawFirstMessage = true
		r.info.LocalAS, r.info.LocalAddr, r.info.PeerAddr = types.ASN(localAS), local, peer
	}
}

func (r *replay) run(records iter.Seq2[mrt.Record, error]) ([]Observation, error) {
	for rec, err := range records {
		if err != nil {
			var re *mrt.RecordError
			if !errors.As(err, &re) || errors.Is(err, mrt.ErrTruncated) {
				return nil, err
			}
			// A broken PEER_INDEX_TABLE must not leave the previous one in force.
			if re.Header.Type == mrt.TypeTableDumpV2 && re.Header.Subtype == mrt.SubPeerIndexTable {
				r.table = nil
			}
			if r.sel.At.IsZero() || !re.Header.Time.After(r.sel.At) {
				r.info.Skipped++
			}
			continue
		}
		_, isTableDump := rec.(mrt.TableDump)
		if isTableDump && !r.inTableDump {
			r.ribGen++
		}
		r.inTableDump = isTableDump
		switch rec := rec.(type) {
		case mrt.PeerIndexTable:
			if !r.sel.PrePolicyRIB {
				return nil, ErrRIBNotPrePolicy
			}
			r.table = rec.Peers
			r.ribGen++
			r.baseline(rec)
		case mrt.RIB:
			if !r.sel.PrePolicyRIB {
				return nil, ErrRIBNotPrePolicy
			}
			r.rib(rec)
		case mrt.TableDump:
			if !r.sel.PrePolicyRIB {
				return nil, ErrRIBNotPrePolicy
			}
			fam := bgp.Family{AFI: bgp.AFIIPv4, SAFI: bgp.SAFIUnicast}
			if rec.Header().Subtype == mrt.SubAFIIPv6 {
				fam.AFI = bgp.AFIIPv6
			}
			if r.selected(rec.Peer.AS, rec.Peer.Addr) && r.applies(rec.Header().Time) {
				r.ribEntry(rec.Peer.Addr, key{fam, rec.Prefix, 0}, rec.Attrs, entryTime(rec.Originated, rec.Header().Time))
			}
		case mrt.BGP4MPStateChange:
			if !r.selected(rec.PeerAS, rec.PeerAddr) {
				continue
			}
			r.first(rec.LocalAS, rec.LocalAddr, rec.PeerAddr)
			if !r.applies(rec.Header().Time) {
				continue
			}
			s := r.session(rec.PeerAddr)
			s.clear(rec.New == mrt.StateEstablished)
			s.down = rec.New != mrt.StateEstablished
		case mrt.BGP4MPMessage:
			if rec.Local || !r.selected(rec.PeerAS, rec.PeerAddr) {
				continue
			}
			r.first(rec.LocalAS, rec.LocalAddr, rec.PeerAddr)
			if !r.applies(rec.Header().Time) {
				continue
			}
			r.message(rec)
		}
	}
	return r.finish(), nil
}

func entryTime(originated, record time.Time) time.Time {
	if originated.IsZero() || originated.Unix() == 0 {
		return record
	}
	return originated
}

// baseline clears every selected session the PEER_INDEX_TABLE names: the
// dump that follows is its whole table (ruling R10 5).
func (r *replay) baseline(t mrt.PeerIndexTable) {
	var named []netip.Addr
	for _, p := range t.Peers {
		if r.selected(p.AS, p.Addr) {
			named = append(named, p.Addr)
		}
	}
	if len(named) == 0 || !r.applies(t.Header().Time) {
		return
	}
	for _, a := range named {
		r.session(a).ribBaseline(r.ribGen)
	}
}

// ribBaseline clears s once for RIB baseline gen.
func (s *session) ribBaseline(gen int) {
	if s.ribGen != gen {
		s.clear(true)
		s.down, s.ribGen = false, gen
	}
}

// rib applies a TABLE_DUMP_V2 RIB record's entries for the peer.
func (r *replay) rib(rec mrt.RIB) {
	if !rec.Prefix.IsValid() { // a RIB_GENERIC family without prefixes
		return
	}
	h := rec.Header()
	for e, err := range rec.Entries() {
		if err != nil {
			if r.sel.At.IsZero() || !h.Time.After(r.sel.At) {
				r.info.Skipped++
			}
			continue // Entries ends after an error
		}
		if int(e.PeerIndex) >= len(r.table) {
			if r.sel.At.IsZero() || !h.Time.After(r.sel.At) {
				r.info.Skipped++
			}
			continue
		}
		p := r.table[e.PeerIndex]
		if !r.selected(p.AS, p.Addr) || !r.applies(h.Time) {
			continue
		}
		id := uint32(0)
		if rec.AddPath {
			id = e.PathID
			if h.Subtype == mrt.SubRIBGenericAddPath {
				id = rec.PathID
			}
		}
		r.ribEntry(p.Addr, key{rec.Family, rec.Prefix, id}, e.Attrs, entryTime(e.Originated, h.Time))
	}
}

// ribEntry applies one RIB entry for the peer at addr as an announcement. A
// malformed entry of any kind withdraws its key: it is one route, so there is
// no session to reset.
func (r *replay) ribEntry(addr netip.Addr, k key, attrs bgp.Attrs, t time.Time) {
	s := r.session(addr)
	s.ribBaseline(r.ribGen)
	s.down = false // an entry for the peer: the session holds this route now
	p, d := attrs.Decode()
	if ribMalformed(d) {
		delete(s.routes, k)
		r.info.Malformed++
		return
	}
	r.announce(s, k, Route(k.prefix, &p, true), firstIs(&p, r.sel.Peer), t)
}

// message applies one BGP message X sent.
func (r *replay) message(m mrt.BGP4MPMessage) {
	s := r.session(m.PeerAddr)
	mt, err := m.MessageType()
	if err != nil { // a message header error resets the session (RFC 4271 §6.1)
		r.reset(s)
		return
	}
	if mt != bgp.MessageUpdate {
		return
	}
	u, d1 := bgp.ParseUpdate(m.Message, m.Context())
	p, d2 := u.Attrs.Decode()
	// Internal only when the ASes are equal and real: on a 2-byte subtype both
	// may be AS_TRANS standing for two different 4-byte ASes.
	f := facts{ibgp: m.LocalAS == m.PeerAS && m.PeerAS != bgp.ASTrans}
	f.reachable = len(u.Announced) > 0 || (p.MPReach != nil && (len(p.MPReach.NLRI) > 0 || len(p.MPReach.RawNLRI) > 0))
	for a, err := range u.Attrs.All() {
		if err != nil || a.Code != bgp.AttrMPUnreach {
			f.otherAttrs = true
			break
		}
	}
	f.missingOrigin = f.reachable && !p.HasOrigin
	f.badNextHop = len(u.Announced) > 0 && !hostAddr(p.NextHop)
	disp := classify(d1, d2, f)
	if disp == dispReset {
		r.reset(s)
		return
	}
	s.down = false
	if !s.complete {
		s.mid = true
	}
	v4 := bgp.Family{AFI: bgp.AFIIPv4, SAFI: bgp.SAFIUnicast}
	for _, n := range u.Withdrawn {
		delete(s.routes, key{v4, n.Prefix, n.PathID})
	}
	if mp := p.MPUnreach; mp != nil && mp.Family.HasPrefixes() {
		for _, n := range mp.Withdrawn {
			delete(s.routes, key{mp.Family, n.Prefix, n.PathID})
		}
	}
	type run struct {
		fam  bgp.Family
		nlri []bgp.NLRI
	}
	runs := []run{{v4, u.Announced}}
	if mp := p.MPReach; mp != nil && mp.Family.HasPrefixes() {
		runs = append(runs, run{mp.Family, mp.NLRI})
	}
	if disp == dispWithdraw {
		for _, ru := range runs {
			for _, n := range ru.nlri {
				delete(s.routes, key{ru.fam, n.Prefix, n.PathID})
				r.info.Malformed++
			}
		}
		return
	}
	base := Route(netip.Prefix{}, &p, true)
	ok := firstIs(&p, r.sel.Peer)
	t := m.Header().Time
	for _, ru := range runs {
		for _, n := range ru.nlri {
			rt := base
			rt.Prefix = n.Prefix
			r.announce(s, key{ru.fam, n.Prefix, n.PathID}, rt, ok, t)
		}
	}
}

// reset is RFC 7606's session reset: the router drops everything X sent and
// the session is down until X speaks again (ruling R10 4); X then sends its
// whole table, so the state is complete.
func (r *replay) reset(s *session) {
	s.clear(true)
	s.down = true
	r.info.MalformedResets++
}

// hostAddr reports whether a is usable as an IPv4 NEXT_HOP (RFC 4271 §6.3):
// present, and not unspecified, multicast or the limited broadcast address.
func hostAddr(a netip.Addr) bool {
	return a.Is4() && !a.IsUnspecified() && !a.IsMulticast() && a != netip.AddrFrom4([4]byte{255, 255, 255, 255})
}

// announce sets k's route, or, when the path does not start with X, deletes
// k's earlier route and counts it (ruling R8 b).
func (r *replay) announce(s *session, k key, rt verdict.Route, xFirst bool, t time.Time) {
	if !xFirst {
		delete(s.routes, k)
		r.info.NotFirstAS++
		return
	}
	s.routes[k] = Observation{Route: rt, Evidence: Evidence{Time: t, PeerAddr: s.addr}, Family: k.fam}
}

// firstIs reports whether p's path starts with an AS_SEQUENCE whose first AS
// is x (ruling R8 e: a first segment of another type does not).
func firstIs(p *bgp.Path, x types.ASN) bool {
	segs := p.ASPath.Segments
	return len(segs) > 0 && segs[0].Type == bgp.ASSequence && len(segs[0].ASNs) > 0 &&
		types.ASN(segs[0].ASNs[0]) == x
}

// finish computes the session-wide info and the union of the sessions'
// routes, sorted.
func (r *replay) finish() []Observation {
	r.info.NoRecordsBeforeAt = !r.sel.At.IsZero() && r.before == 0 && r.after > 0
	type entry struct {
		addr netip.Addr
		k    key
		o    Observation
	}
	var all []entry
	down := len(r.sessions) > 0
	for _, s := range r.sessions {
		if s.mid {
			r.info.MidSession = true
		}
		if !s.down {
			down = false
		}
		for k, o := range s.routes {
			all = append(all, entry{s.addr, k, o})
		}
	}
	r.info.DownAtEnd = down
	slices.SortFunc(all, func(a, b entry) int {
		return cmp.Or(
			a.k.prefix.Addr().Compare(b.k.prefix.Addr()),
			cmp.Compare(a.k.prefix.Bits(), b.k.prefix.Bits()),
			cmp.Compare(a.k.fam.AFI, b.k.fam.AFI),
			cmp.Compare(a.k.fam.SAFI, b.k.fam.SAFI),
			cmp.Compare(a.k.id, b.k.id),
			a.addr.Compare(b.addr),
		)
	})
	out := make([]Observation, len(all))
	for i, e := range all {
		out[i] = e.o
	}
	return out
}
