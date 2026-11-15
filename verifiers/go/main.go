// Independent verifier for the Cancho DB log format (L1) and tokens (L2),
// written from docs/spec/commit.md and docs/spec/token.md.
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
)

type reject struct {
	rule string
	rec  int
}

// reader is a bounds-checked cursor; any overrun sets bad.
type reader struct {
	b   []byte
	pos int
	bad bool
}

func (r *reader) left() int { return len(r.b) - r.pos }
func (r *reader) take(n int) []byte {
	if r.bad || n < 0 || n > r.left() {
		r.bad = true
		return nil
	}
	s := r.b[r.pos : r.pos+n]
	r.pos += n
	return s
}
func (r *reader) u8() uint8 {
	s := r.take(1)
	if s == nil {
		return 0
	}
	return s[0]
}
func (r *reader) u16() uint16 {
	s := r.take(2)
	if s == nil {
		return 0
	}
	return binary.BigEndian.Uint16(s)
}
func (r *reader) u32() uint32 {
	s := r.take(4)
	if s == nil {
		return 0
	}
	return binary.BigEndian.Uint32(s)
}
func (r *reader) u64() uint64 {
	s := r.take(8)
	if s == nil {
		return 0
	}
	return binary.BigEndian.Uint64(s)
}
func (r *reader) b16() []byte { return r.take(int(r.u16())) }
func (r *reader) b32() []byte {
	n := r.u32()
	if uint64(n) > uint64(r.left()) {
		r.bad = true
		return nil
	}
	return r.take(int(n))
}

// count reads a u32 count of items each at least one byte.
func (r *reader) count() int {
	n := r.u32()
	if r.bad || uint64(n) > uint64(r.left()) {
		r.bad = true
		return 0
	}
	return int(n)
}

type effect struct {
	kind   uint8
	target []byte
}

// readEffects reads [Effect] one element at a time, judging each as it is
// read. It stops at the first out-of-order effect (ordered=false) without
// reading the rest; a malformed element sets r.bad.
func readEffects(r *reader) ([]effect, bool) {
	n := r.count()
	var es []effect
	for i := 0; i < n && !r.bad; i++ {
		k := r.u8()
		t := r.b16()
		if r.bad {
			break
		}
		if k > 4 {
			r.bad = true
			break
		}
		if i > 0 {
			p := es[i-1]
			if p.kind > k || (p.kind == k && bytes.Compare(p.target, t) >= 0) {
				return es, false
			}
		}
		es = append(es, effect{k, t})
	}
	return es, true
}

type commit struct {
	parents   [][]byte
	branch    []byte
	seq       uint64
	stmts     [][]byte
	effects   []effect
	token     []byte
	principal []byte
	time      uint64
}

// decodeCommit returns a rule tag ("" if fine). Checks run in field order.
func decodeCommit(b []byte) (*commit, string) {
	r := &reader{b: b}
	c := &commit{}
	if r.u16() != 1 && !r.bad {
		return nil, "bad-version"
	}
	if r.bad {
		return nil, "bad-encoding"
	}
	np := r.count()
	if r.bad {
		return nil, "bad-encoding"
	}
	// Each parent is 32 bytes; a count that cannot fit is malformed.
	if np*32 > r.left() {
		return nil, "bad-encoding"
	}
	if np > 2 {
		return nil, "parent-count"
	}
	for i := 0; i < np; i++ {
		c.parents = append(c.parents, r.take(32))
	}
	bl := int(r.u16())
	if r.bad {
		return nil, "bad-encoding"
	}
	if bl == 0 {
		return nil, "branch-empty"
	}
	if bl > 255 {
		return nil, "bad-encoding"
	}
	c.branch = r.take(bl)
	c.seq = r.u64()
	r.take(32) // schema
	ns := r.count()
	for i := 0; i < ns && !r.bad; i++ {
		c.stmts = append(c.stmts, r.take(32))
	}
	if r.bad {
		return nil, "bad-encoding"
	}
	es, ordered := readEffects(r)
	if r.bad {
		return nil, "bad-encoding"
	}
	if !ordered {
		return nil, "effects-unordered"
	}
	c.effects = es
	c.token = r.take(32)
	c.principal = r.take(32)
	nc := r.count()
	r.take(nc * 32)
	nn := r.count()
	for i := 0; i < nn && !r.bad; i++ {
		switch r.u8() {
		case 0:
		case 1:
			r.take(8)
		case 2:
			r.b32()
		default:
			r.bad = true
		}
	}
	r.take(32) // changes
	r.take(32) // state
	nk := r.count()
	for i := 0; i < nk && !r.bad; i++ {
		r.b16()
		if ok := r.u8(); ok > 1 {
			r.bad = true
		}
	}
	c.time = r.u64()
	if r.bad || r.left() != 0 {
		return nil, "bad-encoding"
	}
	return c, ""
}

func sha(parts ...[]byte) []byte {
	h := sha256.New()
	for _, p := range parts {
		h.Write(p)
	}
	return h.Sum(nil)
}

func cat(parts ...[]byte) []byte { return bytes.Join(parts, nil) }

// ---- L1 ----

type logInfo struct {
	commits  []*commit
	ids      [][]byte
	branches int
}

func verifyLog(data []byte, expect []byte) (*logInfo, *reject) {
	if len(data) < 8 {
		return nil, &reject{"truncated", -1}
	}
	if string(data[:8]) != "CHODBLG1" {
		return nil, &reject{"bad-magic", -1}
	}
	if len(data) < 40 {
		return nil, &reject{"truncated", -1}
	}
	key := ed25519.PublicKey(data[8:40])
	pos := 40
	info := &logInfo{}
	seen := map[string]bool{}
	last := map[string][]byte{}
	count := map[string]uint64{}
	for i := 0; pos < len(data); i++ {
		if len(data)-pos < 4 {
			return nil, &reject{"truncated", i}
		}
		n := binary.BigEndian.Uint32(data[pos:])
		pos += 4
		if n > 16*1024*1024 {
			return nil, &reject{"record-too-large", i}
		}
		if uint64(len(data)-pos) < uint64(n)+64 {
			return nil, &reject{"truncated", i}
		}
		enc := data[pos : pos+int(n)]
		sig := data[pos+int(n) : pos+int(n)+64]
		pos += int(n) + 64
		c, rule := decodeCommit(enc)
		if rule != "" {
			return nil, &reject{rule, i}
		}
		id := sha([]byte("cancho-db/commit/v1"), []byte{0}, enc)
		if seen[string(id)] {
			return nil, &reject{"duplicate-commit", i}
		}
		if !ed25519.Verify(key, id, sig) {
			return nil, &reject{"bad-signature", i}
		}
		br := string(c.branch)
		if c.seq != count[br] {
			return nil, &reject{"seq-gap", i}
		}
		if c.seq == 0 {
			if len(c.parents) == 2 {
				return nil, &reject{"parent-count", i}
			}
			if len(c.parents) == 1 && !seen[string(c.parents[0])] {
				return nil, &reject{"parent-unknown", i}
			}
		} else {
			if len(c.parents) < 1 || len(c.parents) > 2 {
				return nil, &reject{"parent-count", i}
			}
			if !bytes.Equal(c.parents[0], last[br]) {
				return nil, &reject{"parent-mismatch", i}
			}
			if len(c.parents) == 2 {
				if bytes.Equal(c.parents[0], c.parents[1]) {
					return nil, &reject{"parent-count", i}
				}
				if !seen[string(c.parents[1])] {
					return nil, &reject{"parent-unknown", i}
				}
			}
		}
		if _, ok := count[br]; !ok {
			info.branches++
		}
		count[br]++
		last[br] = id
		seen[string(id)] = true
		info.commits = append(info.commits, c)
		info.ids = append(info.ids, id)
	}
	if expect != nil && !seen[string(expect)] {
		return nil, &reject{"expected-missing", -1}
	}
	return info, nil
}

// ---- L2 ----

type block struct {
	payload   []byte // raw payload bytes
	raw       []byte // whole block bytes
	principal []byte
	branch    []byte
	effects   []effect
	expiry    uint64
	next      []byte
	sig       []byte
}

type token struct {
	blocks []block
	id     []byte
}

func prefixID(blocks []block, k int) []byte {
	k32 := make([]byte, 4)
	binary.BigEndian.PutUint32(k32, uint32(k))
	parts := [][]byte{[]byte("cancho-db/token/v1"), {0}, k32}
	for i := 0; i < k; i++ {
		parts = append(parts, blocks[i].raw)
	}
	return sha(parts...)
}

func decodeToken(b []byte) (*token, bool) {
	r := &reader{b: b}
	n := r.count()
	if r.bad || n == 0 {
		return nil, false
	}
	t := &token{}
	for i := 0; i < n; i++ {
		start := r.pos
		var bl block
		bl.principal = r.take(32)
		bl.branch = r.b16()
		es, ordered := readEffects(r)
		if !ordered {
			return nil, false
		}
		bl.effects = es
		bl.expiry = r.u64()
		pend := r.pos
		bl.next = r.take(32)
		bl.sig = r.take(64)
		if r.bad {
			return nil, false
		}
		bl.payload = b[start:pend]
		bl.raw = b[start:r.pos]
		t.blocks = append(t.blocks, bl)
	}
	if r.left() != 0 {
		return nil, false
	}
	t.id = prefixID(t.blocks, n)
	return t, true
}

func matches(pat, v []byte) bool {
	if len(pat) > 0 && pat[len(pat)-1] == '*' {
		return bytes.HasPrefix(v, pat[:len(pat)-1])
	}
	return bytes.Equal(pat, v)
}

func verifyL2(info *logInfo, root ed25519.PublicKey, tokData, revData []byte, haveRev bool, stmtData []byte, haveStmts bool) *reject {
	if len(tokData) < 8 {
		return &reject{"tokens-truncated", -1}
	}
	if string(tokData[:8]) != "CHODBTK1" {
		return &reject{"tokens-bad-magic", -1}
	}
	tokens := map[string]*token{}
	pos := 8
	for i := 0; pos < len(tokData); i++ {
		if len(tokData)-pos < 4 {
			return &reject{"tokens-truncated", i}
		}
		n := binary.BigEndian.Uint32(tokData[pos:])
		pos += 4
		if uint64(len(tokData)-pos) < uint64(n) {
			return &reject{"tokens-truncated", i}
		}
		t, ok := decodeToken(tokData[pos : pos+int(n)])
		pos += int(n)
		if !ok {
			return &reject{"token-bad-encoding", i}
		}
		tokens[string(t.id)] = t
	}
	revoked := map[string][]uint64{}
	if haveRev {
		if len(revData) < 8 {
			return &reject{"revocations-truncated", -1}
		}
		if string(revData[:8]) != "CHODBRV1" {
			return &reject{"revocations-bad-magic", -1}
		}
		pos := 8
		for i := 0; pos < len(revData); i++ {
			if len(revData)-pos < 104 {
				return &reject{"revocations-truncated", i}
			}
			id := revData[pos : pos+32]
			since := revData[pos+32 : pos+40]
			sig := revData[pos+40 : pos+104]
			pos += 104
			msg := cat([]byte("cancho-db/revoke/v1"), []byte{0}, id, since)
			if !ed25519.Verify(root, msg, sig) {
				return &reject{"revocation-bad-signature", i}
			}
			revoked[string(id)] = append(revoked[string(id)], binary.BigEndian.Uint64(since))
		}
	}
	stmts := map[string][]effect{}
	if haveStmts {
		var rj *reject
		if stmts, rj = loadStmts(stmtData); rj != nil {
			return rj
		}
	}
	for i, c := range info.commits {
		t := tokens[string(c.token)]
		if t == nil {
			return &reject{"token-missing", i}
		}
		key := root
		for _, b := range t.blocks {
			msg := cat([]byte("cancho-db/token-block/v1"), []byte{0}, b.payload, b.next)
			if !ed25519.Verify(key, msg, b.sig) {
				return &reject{"token-bad-signature", i}
			}
			key = ed25519.PublicKey(b.next)
		}
		for k := 1; k <= len(t.blocks); k++ {
			for _, since := range revoked[string(prefixID(t.blocks, k))] {
				if since <= c.time {
					return &reject{"token-revoked", i}
				}
			}
		}
		for _, b := range t.blocks {
			if b.expiry != ^uint64(0) && c.time > b.expiry {
				return &reject{"token-expired", i}
			}
		}
		zero := make([]byte, 32)
		for _, b := range t.blocks {
			if !bytes.Equal(b.principal, zero) && !bytes.Equal(b.principal, c.principal) {
				return &reject{"principal-denied", i}
			}
		}
		for _, b := range t.blocks {
			if !matches(b.branch, c.branch) {
				return &reject{"branch-denied", i}
			}
		}
		if haveStmts {
			var all []effect
			for _, h := range c.stmts {
				es, ok := stmts[string(h)]
				if !ok {
					return &reject{"stmt-missing", i}
				}
				all = append(all, es...)
			}
			if !sameSet(all, c.effects) {
				return &reject{"effects-mismatch", i}
			}
		}
		for _, b := range t.blocks {
			for _, ce := range c.effects {
				ok := false
				for _, be := range b.effects {
					if be.kind == ce.kind && matches(be.target, ce.target) {
						ok = true
						break
					}
				}
				if !ok {
					return &reject{"effect-denied", i}
				}
			}
		}
	}
	return nil
}

func parseHex32(s string) []byte {
	if len(s) != 64 {
		return nil
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil
	}
	return b
}

func usage() {
	os.Exit(2)
}

func main() {
	args := os.Args[1:]
	var path, expectS, rootS, tokPath, revPath, stmtPath string
	var haveExpect, haveRoot, haveTok, haveRev, havePath, haveStmts bool
	for i := 0; i < len(args); i++ {
		a := args[i]
		next := func() string {
			if i+1 >= len(args) {
				usage()
			}
			i++
			return args[i]
		}
		switch a {
		case "--expect":
			if haveExpect {
				usage()
			}
			haveExpect, expectS = true, next()
		case "--root":
			if haveRoot {
				usage()
			}
			haveRoot, rootS = true, next()
		case "--tokens":
			if haveTok {
				usage()
			}
			haveTok, tokPath = true, next()
		case "--revoked":
			if haveRev {
				usage()
			}
			haveRev, revPath = true, next()
		case "--stmts":
			if haveStmts {
				usage()
			}
			haveStmts, stmtPath = true, next()
		default:
			if havePath {
				usage()
			}
			havePath, path = true, a
		}
	}
	if !havePath {
		usage()
	}
	var expect, root []byte
	if haveExpect {
		if expect = parseHex32(expectS); expect == nil {
			usage()
		}
	}
	if haveRoot {
		if root = parseHex32(rootS); root == nil || !haveTok {
			usage()
		}
	} else if haveTok || haveRev || haveStmts {
		usage()
	}
	data, err := os.ReadFile(path)
	if err != nil {
		usage()
	}
	var tokData, revData, stmtData []byte
	if haveRoot {
		if tokData, err = os.ReadFile(tokPath); err != nil {
			usage()
		}
		if haveStmts {
			if stmtData, err = os.ReadFile(stmtPath); err != nil {
				usage()
			}
		}
		if haveRev {
			if revData, err = os.ReadFile(revPath); err != nil {
				usage()
			}
		}
	}
	info, rj := verifyLog(data, expect)
	if rj == nil && haveRoot {
		rj = verifyL2(info, ed25519.PublicKey(root), tokData, revData, haveRev, stmtData, haveStmts)
	}
	if rj != nil {
		fmt.Printf("reject rule=%s record=%d\n", rj.rule, rj.rec)
		os.Exit(1)
	}
	if haveStmts {
		fmt.Printf("ok commits=%d branches=%d level=2+ir\n", len(info.commits), info.branches)
	} else if haveRoot {
		fmt.Printf("ok commits=%d branches=%d level=2\n", len(info.commits), info.branches)
	} else {
		fmt.Printf("ok commits=%d branches=%d\n", len(info.commits), info.branches)
	}
}
