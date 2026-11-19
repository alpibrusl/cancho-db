# A third reading of docs/spec/l3a.md, written by a separate agent session from the spec and the vectors alone (M2f-3, Q9): it never saw tools/l3a.py or src/l3a.cho. Kept as written but for its import and one amendment (marked): it read the files as UTF-8, and a schema name is bytes.
#!/usr/bin/env python3
import hashlib, re, struct, sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "tools"))
import state as S

def sha(*p):
    h = hashlib.sha256()
    for x in p: h.update(x)
    return h.digest()

class Out(Exception):
    def __init__(s, rule, rec): s.rule, s.rec = rule, rec

HEX = re.compile(r'^(?:[0-9a-f]{2})+$')
H64 = re.compile(r'^[0-9a-f]{64}$')
SEQ = re.compile(r'^(0|[1-9][0-9]*)$')

def usage():
    sys.exit(2)

def readf(p):
    try:
        with open(p, 'rb') as f: return f.read()
    except OSError:
        usage()

def lines_of(data, magic):
    text = data.decode('latin-1')   # amended after the vectors: a schema name is bytes (l3a.md section 8), not text
    if not text.endswith('\n'): raise Out('store-malformed', -1)
    ls = text[:-1].split('\n')
    if ls[0] != magic: raise Out('store-malformed', -1)
    return ls[1:]

def hexb(s):
    if not HEX.match(s): raise Out('store-malformed', -1)
    return bytes.fromhex(s)

def parse_deltas(data):
    rows = []
    seen = set()
    for ln in lines_of(data, 'CHODBDL1'):
        f = ln.split('\t')
        if len(f) != 9: raise Out('store-malformed', -1)
        seq, commit, schema, table, key, oh, nh, oi, ni = f
        if not SEQ.match(seq): raise Out('store-malformed', -1)
        seq = int(seq)
        if seq in seen: raise Out('store-malformed', -1)
        seen.add(seq)
        if not H64.match(commit): raise Out('store-malformed', -1)
        if schema == '': raise Out('store-malformed', -1)
        table = hexb(table); key = hexb(key)
        oh = bytes.fromhex(oh) if oh != '' and H64.match(oh) else (None if oh == '' else Out)
        nh = bytes.fromhex(nh) if nh != '' and H64.match(nh) else (None if nh == '' else Out)
        if oh is Out or nh is Out: raise Out('store-malformed', -1)
        oi = None if oi == '' else hexb(oi)
        ni = None if ni == '' else hexb(ni)
        if oh is None and nh is None: raise Out('store-malformed', -1)
        rows.append(dict(seq=seq, commit=commit, schema=schema, table=table, key=key, oh=oh, nh=nh, oi=oi, ni=ni))
    return rows

def parse_base(data):
    m = {}
    for ln in lines_of(data, 'CHODBBS1'):
        f = ln.split('\t')
        if len(f) != 3: raise Out('store-malformed', -1)
        t, k, i = (hexb(x) for x in f)
        if (t, k) in m: raise Out('store-malformed', -1)
        m[(t, k)] = rowhash(i)
    return m

def parse_live(data):
    out = []
    for ln in lines_of(data, 'CHODBLV1'):
        f = ln.split('\t')
        if len(f) != 4 or f[0] == '': raise Out('store-malformed', -1)
        out.append((f[0], hexb(f[1]), hexb(f[2]), rowhash(hexb(f[3]))))
    return out

def rowhash(img): return sha(b'cancho-db/row/v1\x00', img)

def parse_log(data):
    bad = Out('log-malformed', -1)
    if len(data) < 40 or data[:8] != b'CHODBLG1': raise bad
    pos, commits = 40, []
    try:
        while pos < len(data):
            n, = struct.unpack_from('>I', data, pos); pos += 4
            if n > 16777216 or pos + n + 64 > len(data): raise bad
            enc = data[pos:pos + n]; pos += n + 64
            commits.append(parse_commit(enc))
    except (struct.error, IndexError):
        raise bad
    return commits

def parse_commit(enc):
    bad = Out('log-malformed', -1)
    p = [0]
    def take(n):
        if p[0] + n > len(enc): raise bad
        b = enc[p[0]:p[0] + n]; p[0] += n; return b
    def u(fmt):
        return struct.unpack('>' + fmt, take(struct.calcsize('>' + fmt)))[0]
    if u('H') != 1: raise bad
    np_ = u('I')
    if np_ > 2 or np_ * 32 > len(enc): raise bad
    parents = [take(32) for _ in range(np_)]
    branch = take(u('H'))
    if not branch: raise bad
    u('Q'); take(32)
    for _ in range(u('I')): take(32)
    effects = []
    for _ in range(u('I')):
        k = u('B'); effects.append(k); take(u('H'))
    take(32); take(32)
    for _ in range(u('I')): take(32)
    for _ in range(u('I')):
        t = u('B')
        if t == 1: take(8)
        elif t == 2: take(u('I'))
        elif t != 0: raise bad
    changes = take(32); state = take(32)
    for _ in range(u('I')):
        take(u('H')); take(1)
    u('Q')
    if p[0] != len(enc): raise bad
    return dict(id=sha(b'cancho-db/commit/v1\x00', enc), parents=parents, branch=branch, effects=effects, changes=changes, state=state)

def facts_of(rows):
    net = {}
    for r in sorted(rows, key=lambda r: r['seq']):
        k = (r['table'], r['key'])
        if k not in net: net[k] = [r['oh'], r['nh']]
        else: net[k][1] = r['nh']
    out = []
    for (t, k), (o, n) in sorted(net.items()):
        if o == n: continue
        out.append((0 if o is None else (2 if n is None else 1), t, k, o, n))
    return out

def run(logp, deltap, basep, livep, first):
    commits = parse_log(readf(logp))
    rows = parse_deltas(readf(deltap))
    base = parse_base(readf(basep)) if basep else {}
    live = parse_live(readf(livep)) if livep else None
    ids = {c['id']: i for i, c in enumerate(commits)}
    for r in rows:
        if bytes.fromhex(r['commit']) not in ids: raise Out('store-foreign-row', -1)
    byc = {}
    for r in rows: byc.setdefault(bytes.fromhex(r['commit']), []).append(r)
    if first is None and commits: first = commits[0]['branch']
    else: first = first.encode() if first is not None else None
    def schema_of(b): return 'public' if b == first else 'cdb_b_' + b.decode('latin-1')
    maps, last, state_of, nfacts, schemas = {}, {}, {}, 0, set()
    for i, c in enumerate(commits):
        b = c['branch']; sc = schema_of(b); schemas.add(sc)
        mine = byc.get(c['id'], [])
        if any(r['schema'] != sc for r in mine): raise Out('store-foreign-row', i)
        if mine and not any(e in (1, 2, 3) for e in c['effects']): raise Out('store-foreign-row', i)
        for r in mine:
            if (r['oh'] is None) != (r['oi'] is None) or (r['nh'] is None) != (r['ni'] is None): raise Out('facts-image', i)
            if r['oi'] is not None and rowhash(r['oi']) != r['oh']: raise Out('facts-image', i)
            if r['ni'] is not None and rowhash(r['ni']) != r['nh']: raise Out('facts-image', i)
        facts = facts_of(mine)
        if any(len(t) > 255 or len(k) > 65535 for _, t, k, _, _ in facts): raise Out('changes-mismatch', i)
        st, ch = S.changes(facts)
        if st != 'ok' or ch != c['changes']: raise Out('changes-mismatch', i)
        ps = []
        for p in c['parents']:
            if p not in state_of: raise Out('state-mismatch', i)
            ps.append(state_of[p])
        if S.state(ps, c['changes']) != c['state']: raise Out('state-mismatch', i)
        state_of[c['id']] = c['state']
        if b not in maps:
            if not c['parents']:
                m = dict(base) if b == first else {}
            else:
                pb = None
                for bb, lid in last.items():
                    if lid == c['parents'][0] and bb != b: pb = bb
                if pb is None: raise Out('replay-unsupported', i)
                m = dict(maps[pb])
            maps[b] = m
        m = maps[b]
        for kind, t, k, o, n in facts:
            if kind == 0:
                if (t, k) in m: raise Out('replay-precondition', i)
                m[(t, k)] = n
            else:
                if m.get((t, k)) != o: raise Out('replay-precondition', i)
                if kind == 1: m[(t, k)] = n
                else: del m[(t, k)]
        nfacts += len(facts)
        last[b] = c['id']
    if live is not None:
        by = {s: {} for s in schemas}
        for s, t, k, h in live:
            if s not in by or (t, k) in by[s]: raise Out('replay-final', -1)
            by[s][(t, k)] = h
        for b, m in maps.items():
            if by[schema_of(b)] != m: raise Out('replay-final', -1)
    return 'ok commits=%d facts=%d branches=%d%s' % (len(commits), nfacts, len(maps), ' final' if live is not None else '')

def main():
    a = sys.argv[1:]; opts = {}; pos = []; i = 0
    while i < len(a):
        if a[i] in ('--deltas', '--base', '--live-dump', '--first-branch'):
            if a[i] in opts or i + 1 >= len(a): usage()
            opts[a[i]] = a[i + 1]; i += 2
        elif a[i].startswith('--'): usage()
        else: pos.append(a[i]); i += 1
    if len(pos) != 1 or '--deltas' not in opts: usage()
    try:
        print(run(pos[0], opts['--deltas'], opts.get('--base'), opts.get('--live-dump'), opts.get('--first-branch')))
    except Out as e:
        print('reject rule=%s record=%d' % (e.rule, e.rec)); sys.exit(1)

main()
