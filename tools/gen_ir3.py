"""IR v3 vectors (docs/spec/ir.md section 8), added to the registry of gen_vectors.py by `add(g)`.

A v3 store has the magic CHODBST3 and holds records `shape chash payload`: the statement with each constant lifted out into a `Hole`, the salted hash of the constants, and (unless erased) the salt and the constants.
As in gen_ir.py and gen_ir2.py, every effect set a commit records is written out by hand, as a literal list: nothing here calls an inference function.
"""
import hashlib

R, W, D, C, N = 0, 1, 2, 3, 4
NONE = 2**64 - 1
TOKEN_DOMAIN = b"cancho-db/token/v1\x00"
BLOCK_DOMAIN = b"cancho-db/token-block/v1\x00"
STMT3 = b"cancho-db/stmt/v3\x00"
CONSTS = b"cancho-db/consts/v1\x00"


def add(g):
    u32, u64, b16, lst, effect = g.u32, g.u64, g.b16, g.lst, g.effect
    ROOT, ROOT_PK = g.key("root")
    T = 1_700_000_000_000

    def name(b): return b16(b)
    def Col(t, c): return b"\x00" + name(t) + name(c)
    def Const(v): return b"\x01" + v
    def Param(i): return b"\x02" + u32(i)
    def Op(op, a, b): return b"\x05" + bytes([op]) + a + b
    def Hole(vt): return b"\x0b" + bytes([vt])
    EQ = 0
    def opt(e=None): return b"\x00" if e is None else b"\x01" + e
    def Select(items, tables, where=None): return b"\x00" + lst(items) + lst([name(t) for t in tables]) + opt(where)
    def Insert(t, cols, rows): return b"\x01" + name(t) + lst([name(c) for c in cols]) + lst([lst(r) for r in rows])
    def Update(t, sets, where=None): return b"\x02" + name(t) + lst([name(c) + e for c, e in sets]) + opt(where)
    def Delete(t, where=None): return b"\x03" + name(t) + opt(where)

    INT = lambda n: g.value_int(n)
    BYTES = lambda b: g.value_bytes(b)
    NULL = g.value_null()
    SALT = bytes(range(16))

    def chash(salt, values): return hashlib.sha256(CONSTS + salt + u32(len(values)) + b"".join(values)).digest()
    def rec(shape, values, erased=False, salt=SALT):
        """(record body, statement id) for a statement whose constants are `values`, in the order of its holes; `erased` drops the payload and keeps the hash."""
        ch = chash(salt, values)
        if erased:
            body = shape + ch + b"\x00"
        else:
            body = shape + ch + b"\x01" + salt + u32(len(values)) + b"".join(values)
        return body, hashlib.sha256(STMT3 + shape + ch).digest()
    def store(*bodies, magic=b"CHODBST3"): return magic + b"".join(u32(len(x)) + x for x in bodies)

    def mint(label, *specs):
        blocks, signer = [], ROOT
        for i, (branch, effects) in enumerate(specs):
            pl = bytes(32) + b16(branch) + lst([effect(k, t) for k, t in effects]) + u64(NONE)
            nsk, npk = g.key("ir3 token %s %d" % (label, i))
            blocks.append(pl + npk + signer.sign(BLOCK_DOMAIN + pl + npk))
            signer = nsk
        return blocks

    def tid(blocks): return hashlib.sha256(TOKEN_DOMAIN + u32(len(blocks)) + b"".join(blocks)).digest()
    def tokens_store(blocks): return b"CHODBTK1" + u32(4 + sum(len(b) for b in blocks)) + u32(len(blocks)) + b"".join(blocks)

    ALL = mint("all", (b"*", [(k, b"*") for k in range(5)]))
    ARGS = "--root " + ROOT_PK.hex() + " --tokens {dir}/%s.tokens --stmts {dir}/%s.stmts"

    def commits(*specs, token=ALL):
        c = g.Chain()
        for ids, effs in specs:
            assert effs == sorted(set(effs)), "recorded effects must be written in order"
            c.add("main", token=tid(token), time=T, statements=list(ids), effects=[effect(k, t) for k, t in effs])
        return c

    def ir(label, chain_, st, expect, token=ALL):
        g.vec(label, g.log(*[g.record(e) for e in chain_.encs]), expect, ARGS % (label, label), {".tokens": tokens_store(token), ".stmts": st})

    def ok(n): return "ok commits=%d branches=1 level=2+ir" % n
    def no(rule, at): return g.rejects(rule, at)

    ONE = rec(Delete(b"ok"), [])             # a filler record, so that the record under test is the second
    one_body, one_id = ONE
    def second(label, body_or_store, expect_rule, ids=None, effs=None, magic=b"CHODBST3"):
        """A store of the filler and a second record (given as bytes), cited by a commit that cites only the filler (the store is read whole first)."""
        ir(label, commits(([one_id], [(W, b"ok")])), store(one_body, body_or_store, magic=magic), no(expect_rule, 1))

    ins = Insert(b"orders", [b"id", b"note"], [[Hole(1), Hole(2)]])
    ins_vals = [INT(7), BYTES(b"ana@example.org")]
    ins_effs = [(W, b"orders")]

    # ------------------------------------------------------------ valid
    b, i = rec(ins, ins_vals)
    ir("ir3_ok_insert_with_its_constants", commits(([i], ins_effs)), store(b), ok(1))
    b, i = rec(ins, ins_vals, erased=True)
    ir("ir3_ok_insert_erased", commits(([i], ins_effs)), store(b), ok(1))
    b1, i1 = rec(ins, ins_vals)
    b2, i2 = rec(ins, ins_vals, erased=True)
    assert i1 == i2
    ir("ir3_ok_erased_and_whole_have_one_id", commits(([i1], ins_effs)), store(b2), ok(1))
    b, i = rec(Delete(b"orders", Op(EQ, Col(b"orders", b"id"), Hole(1))), [INT(5)])
    ir("ir3_ok_where_hole_reads_a_column_not_a_constant", commits(([i], [(R, b"orders.id"), (W, b"orders")])), store(b), ok(1))
    b, i = rec(Select([Col(b"t", b"a")], [b"t"], Op(EQ, Col(b"t", b"b"), Param(1))), [])
    ir("ir3_ok_no_constants_a_param_stays", commits(([i], [(R, b"t"), (R, b"t.a"), (R, b"t.b")])), store(b), ok(1))
    b, i = rec(Update(b"t", [(b"a", Hole(0))], Op(EQ, Col(b"t", b"k"), Hole(1))), [NULL, INT(1)])
    ir("ir3_ok_null_and_int_holes", commits(([i], [(R, b"t.k"), (W, b"t")])), store(b), ok(1))
    b, i = rec(Insert(b"t", [b"a"], [[Hole(2)], [Hole(2)]]), [BYTES(b""), BYTES(b"\x00\xff")])
    ir("ir3_ok_empty_and_binary_bytes", commits(([i], [(W, b"t")])), store(b), ok(1))
    ir("ir3_ok_two_statements_one_erased", commits(([one_id, i1], [(W, b"ok"), (W, b"orders")])), store(one_body, rec(ins, ins_vals, erased=True)[0]), ok(1))

    # ------------------------------------------------------------ the shape and the record are malformed
    second("ir3_bad_a_const_in_a_v3_shape", rec(Insert(b"t", [b"a"], [[Const(INT(1))]]), [])[0], "stmt-bad-encoding")
    ir("ir3_bad_a_hole_in_a_v2_store", commits(([hashlib.sha256(b"cancho-db/stmt/v1\x00" + Delete(b"ok")).digest()], [(W, b"ok")])),
       store(Delete(b"ok"), Insert(b"t", [b"a"], [[Hole(1)]]), magic=b"CHODBST2"), no("stmt-bad-encoding", 1))
    second("ir3_bad_hole_type_3", rec(Insert(b"t", [b"a"], [[Hole(3)]]), [INT(1)])[0], "stmt-bad-encoding")
    b, _ = rec(ins, ins_vals)
    second("ir3_bad_record_ends_before_the_hash", ins, "stmt-bad-encoding")
    second("ir3_bad_chash_too_short", ins + bytes(31), "stmt-bad-encoding")
    second("ir3_bad_no_payload_tag", ins + chash(SALT, []), "stmt-bad-encoding")
    second("ir3_bad_payload_tag_2", ins + chash(SALT, ins_vals) + b"\x02", "stmt-bad-encoding")
    whole = rec(ins, ins_vals)[0]
    second("ir3_bad_payload_tag_2_over_a_whole_payload", whole[:len(ins) + 32] + b"\x02" + whole[len(ins) + 33:], "stmt-bad-encoding")
    second("ir3_bad_erased_payload_with_trailing_bytes", rec(ins, ins_vals, erased=True)[0] + b"\x00", "stmt-bad-encoding")
    second("ir3_bad_salt_of_15_bytes", ins + chash(SALT, ins_vals) + b"\x01" + SALT[:15] + u32(2) + b"".join(ins_vals), "stmt-bad-encoding")
    second("ir3_bad_payload_with_trailing_bytes", rec(ins, ins_vals)[0] + b"\x00", "stmt-bad-encoding")
    second("ir3_bad_payload_value_cut_short", rec(ins, ins_vals)[0][:-3], "stmt-bad-encoding")
    second("ir3_bad_payload_value_tag_3", ins + chash(SALT, [b"\x03", BYTES(b"x")]) + b"\x01" + SALT + u32(2) + b"\x03" + BYTES(b"x"), "stmt-bad-encoding")

    # ------------------------------------------------------------ the payload is not what the record committed to
    good_body, good_id = rec(ins, ins_vals)
    flipped = bytearray(good_body)
    flipped[len(ins)] ^= 1                                                        # one bit of chash
    second("ir3_consts_hash_flipped", bytes(flipped), "stmt-consts-mismatch")
    other = ins + chash(SALT, ins_vals) + b"\x01" + SALT + u32(2) + INT(8) + BYTES(b"ana@example.org")
    second("ir3_consts_a_value_changed", other, "stmt-consts-mismatch")
    second("ir3_consts_fewer_than_holes", ins + chash(SALT, [INT(7)]) + b"\x01" + SALT + u32(1) + INT(7), "stmt-consts-mismatch")
    second("ir3_consts_more_than_holes", ins + chash(SALT, ins_vals + [NULL]) + b"\x01" + SALT + u32(3) + b"".join(ins_vals) + NULL, "stmt-consts-mismatch")
    second("ir3_consts_type_differs_from_the_hole", ins + chash(SALT, [BYTES(b"7"), BYTES(b"x")]) + b"\x01" + SALT + u32(2) + BYTES(b"7") + BYTES(b"x"), "stmt-consts-mismatch")
    second("ir3_consts_another_salt", ins + chash(SALT, ins_vals) + b"\x01" + bytes(16) + u32(2) + b"".join(ins_vals), "stmt-consts-mismatch")

    # ------------------------------------------------------------ the commit and the store disagree
    # an erased record with another hash has another id: the commit's statement is not in the store
    other_erased = ins + chash(SALT, [INT(8), BYTES(b"x")]) + b"\x00"
    ir("ir3_erased_record_with_another_hash_is_not_the_statement", commits(([good_id], ins_effs)), store(other_erased), no("stmt-missing", 0))
    ir("ir3_effects_recorded_wrongly", commits(([good_id], [(W, b"other")])), store(good_body), no("effects-mismatch", 0))
    ir("ir3_effects_recorded_wrongly_in_an_erased_record", commits(([good_id], [(W, b"other")])), store(rec(ins, ins_vals, erased=True)[0]), no("effects-mismatch", 0))
    ir("ir3_statement_not_in_the_store", commits(([good_id], ins_effs)), store(one_body), no("stmt-missing", 0))
