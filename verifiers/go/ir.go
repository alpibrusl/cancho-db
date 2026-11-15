package main

import (
	"bytes"
	"encoding/binary"
	"sort"
)

// Statement IR (ir.md): decoding and effect inference.

func loadStmts(d []byte) (map[string][]effect, *reject) {
	if len(d) < 8 {
		return nil, &reject{"stmts-truncated", -1}
	}
	v2 := string(d[:8]) == "CHODBST2"
	if !v2 && string(d[:8]) != "CHODBST1" {
		return nil, &reject{"stmts-bad-magic", -1}
	}
	out := map[string][]effect{}
	pos := 8
	for i := 0; pos < len(d); i++ {
		if len(d)-pos < 4 {
			return nil, &reject{"stmts-truncated", i}
		}
		n := binary.BigEndian.Uint32(d[pos:])
		pos += 4
		if uint64(len(d)-pos) < uint64(n) {
			return nil, &reject{"stmts-truncated", i}
		}
		enc := d[pos : pos+int(n)]
		pos += int(n)
		es, ok := decodeStmt(enc, v2)
		if !ok {
			return nil, &reject{"stmt-bad-encoding", i}
		}
		out[string(sha([]byte("cancho-db/stmt/v1"), []byte{0}, enc))] = es
	}
	return out, nil
}

type effSet struct {
	m map[string]effect
}

func (s *effSet) add(kind uint8, target []byte) {
	s.m[string(append([]byte{kind}, target...))] = effect{kind, append([]byte(nil), target...)}
}

func (s *effSet) list() []effect {
	var l []effect
	for _, e := range s.m {
		l = append(l, e)
	}
	return l
}

// name reads a table/column Name (no '.', non-empty).
func (r *reader) name(dotOK bool) []byte {
	n := r.b16()
	if r.bad || len(n) == 0 || (!dotOK && bytes.IndexByte(n, '.') >= 0) {
		r.bad = true
		return nil
	}
	return n
}

func joinTC(t, c []byte) []byte { return cat(t, []byte{'.'}, c) }

// expr reads one prefix-order expression using an owed-operand counter.
func (r *reader) expr(s *effSet, allowCol bool) {
	owed := uint64(1)
	for owed > 0 {
		if r.bad || uint64(r.left()) < owed {
			r.bad = true
			return
		}
		var ops uint64
		switch r.u8() {
		case 0:
			t := r.name(false)
			c := r.name(false)
			if r.bad || !allowCol {
				r.bad = true
				return
			}
			s.add(0, joinTC(t, c))
		case 1:
			switch r.u8() {
			case 0:
			case 1:
				r.take(8)
			case 2:
				r.b32()
			default:
				r.bad = true
			}
		case 2:
			r.u32()
		case 3:
			s.add(4, r.name(true))
		case 4:
			fn := r.name(true)
			ops = uint64(r.u32())
			if r.bad {
				return
			}
			s.add(3, fn)
		case 5:
			max := uint8(11)
			if r.v2 {
				max = 17
			}
			if r.u8() > max {
				r.bad = true
			}
			ops = 2
		case 6:
			r.bad = !r.v2 // Star
		case 7:
			if r.u8() > 3 || !r.v2 {
				r.bad = true
			}
			ops = 1
		case 8:
			if r.u8() > 1 || !r.v2 {
				r.bad = true
			}
			n := uint64(r.u32())
			if n == 0 {
				r.bad = true
			}
			ops = 1 + n
		case 9:
			n := uint64(r.u32())
			he := r.u8()
			if n == 0 || he > 1 || !r.v2 {
				r.bad = true
			}
			ops = 2*n + uint64(he)
		case 10:
			r.name(true)
			if !r.v2 {
				r.bad = true
			}
			ops = 1
		default:
			r.bad = true
		}
		if r.bad {
			return
		}
		owed = owed - 1 + ops
	}
}

func (r *reader) opt(s *effSet) {
	switch r.u8() {
	case 0:
	case 1:
		r.expr(s, true)
	default:
		r.bad = true
	}
}

func decodeStmt(b []byte, v2 bool) ([]effect, bool) {
	r := &reader{b: b, v2: v2}
	s := &effSet{m: map[string]effect{}}
	switch r.u8() {
	case 0: // Select
		n := r.count()
		for i := 0; i < n && !r.bad; i++ {
			r.expr(s, true)
		}
		nf := r.count()
		if nf == 0 {
			r.bad = true
		}
		for i := 0; i < nf && !r.bad; i++ {
			if t := r.name(false); t != nil {
				s.add(0, t)
			}
		}
		r.opt(s)
	case 1: // Insert
		t := r.name(false)
		nc := r.count()
		for i := 0; i < nc && !r.bad; i++ {
			r.name(false)
		}
		nr := r.count()
		for i := 0; i < nr && !r.bad; i++ {
			if int(r.u32()) != nc {
				r.bad = true
				break
			}
			for j := 0; j < nc && !r.bad; j++ {
				r.expr(s, false)
			}
		}
		if !r.bad {
			s.add(1, t)
		}
	case 2: // Update
		t := r.name(false)
		n := r.count()
		if n == 0 {
			r.bad = true
		}
		for i := 0; i < n && !r.bad; i++ {
			r.name(false)
			r.expr(s, true)
		}
		r.opt(s)
		if !r.bad {
			s.add(1, t)
		}
	case 3: // Delete
		t := r.name(false)
		r.opt(s)
		if !r.bad {
			s.add(1, t)
		}
	case 4: // Ddl
		if r.u8() > 4 {
			r.bad = true
		}
		if t := r.name(false); t != nil {
			s.add(2, t)
		}
	case 5: // Call
		fn := r.name(true)
		n := r.count()
		for i := 0; i < n && !r.bad; i++ {
			r.expr(s, true)
		}
		if !r.bad {
			s.add(3, fn)
		}
	case 6: // Select2
		if !r.v2 {
			r.bad = true
			break
		}
		if r.u8() > 1 {
			r.bad = true
		}
		n := r.count()
		for i := 0; i < n && !r.bad; i++ {
			r.expr(s, true)
		}
		nf := r.count()
		if nf == 0 {
			r.bad = true
		}
		for i := 0; i < nf && !r.bad; i++ {
			t := r.name(false)
			kind := r.u8()
			if r.bad || kind > 2 {
				r.bad = true
				break
			}
			s.add(0, t)
			if r.left() < 1 {
				r.bad = true
				break
			}
			hasOn := r.b[r.pos] == 1
			if (i == 0 && (kind != 0 || hasOn)) || (kind == 0) == hasOn {
				r.bad = true
				break
			}
			r.opt(s)
		}
		r.opt(s)
		ng := r.count()
		for i := 0; i < ng && !r.bad; i++ {
			r.expr(s, true)
		}
		r.opt(s)
		no := r.count()
		for i := 0; i < no && !r.bad; i++ {
			r.expr(s, true)
			if r.u8() > 1 {
				r.bad = true
			}
			if r.u8() > 2 {
				r.bad = true
			}
		}
		r.opt(s)
		r.opt(s)
	default:
		r.bad = true
	}
	if r.bad || r.left() != 0 {
		return nil, false
	}
	return s.list(), true
}

func sortEffects(l []effect) {
	sort.Slice(l, func(i, j int) bool {
		if l[i].kind != l[j].kind {
			return l[i].kind < l[j].kind
		}
		return bytes.Compare(l[i].target, l[j].target) < 0
	})
}

// sameSet: the inferred effects (any order, repeats allowed) equal the recorded set exactly.
func sameSet(inferred, recorded []effect) bool {
	set := &effSet{m: map[string]effect{}}
	for _, e := range inferred {
		set.add(e.kind, e.target)
	}
	l := set.list()
	if len(l) != len(recorded) {
		return false
	}
	sortEffects(l)
	for i := range l {
		if l[i].kind != recorded[i].kind || !bytes.Equal(l[i].target, recorded[i].target) {
			return false
		}
	}
	return true
}
