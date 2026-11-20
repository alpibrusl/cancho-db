"""IR v2 vectors (docs/spec/ir.md section 6), added to the registry of gen_vectors.py by `add(g)`.

As in gen_ir.py, every effect set a commit records is written out by hand from the inference rules, as a literal list: nothing
here calls an inference function. v2 stores have the magic CHODBST2.
"""
import hashlib

R, W, D, C, N = 0, 1, 2, 3, 4
NONE = 2**64 - 1
STMT_DOMAIN = b"cancho-db/stmt/v1\x00"
TOKEN_DOMAIN = b"cancho-db/token/v1\x00"
BLOCK_DOMAIN = b"cancho-db/token-block/v1\x00"


def add(g):
    u32, u64, b16, lst, effect = g.u32, g.u64, g.b16, g.lst, g.effect
    ROOT, ROOT_PK = g.key("root")
    T = 1_700_000_000_000

    # ----------------------------------------------------- encoders (v1 and v2)
    def name(b): return b16(b)
    def Col(t, c): return b"\x00" + name(t) + name(c)
    def Const(v): return b"\x01" + v
    def Param(i): return b"\x02" + u32(i)
    def Nondet(s): return b"\x03" + name(s)
    def Call(f, *args): return b"\x04" + name(f) + u32(len(args)) + b"".join(args)
    def Op(op, a, b): return b"\x05" + bytes([op]) + a + b
    def Star(): return b"\x06"
    def Unary(op, e): return b"\x07" + bytes([op]) + e
    def In(neg, x, *members): return b"\x08" + bytes([neg]) + u32(len(members)) + x + b"".join(members)
    def Case(pairs, els=None):
        body = b"".join(c + r for c, r in pairs) + (els or b"")
        return b"\x09" + u32(len(pairs)) + bytes([1 if els is not None else 0]) + body
    def Cast(t, e): return b"\x0a" + name(t) + e
    EQ, NE, LT, LE, GT, GE, AND, OR, ADD, SUB, MUL, DIV, LIKE, ILIKE, NLIKE, NILIKE, CAT, MOD = range(18)
    NOT, NEG, ISNULL, NOTNULL = range(4)
    ONE, TWO, NULL = g.value_int(1), g.value_int(2), g.value_null()

    def opt(e=None): return b"\x00" if e is None else b"\x01" + e
    def From(t, kind=0, on=None): return name(t) + bytes([kind]) + opt(on)
    def Order(e, d=0, n=0): return e + bytes([d, n])
    def Select2(items, frm, where=None, group=(), having=None, order=(), limit=None, offset=None, distinct=0):
        return (b"\x06" + bytes([distinct]) + lst(list(items)) + lst(list(frm)) + opt(where) + lst(list(group))
                + opt(having) + lst(list(order)) + opt(limit) + opt(offset))
    # v1 statements, valid unchanged in a v2 store
    def Select(items, tables, where=None): return b"\x00" + lst(items) + lst([name(t) for t in tables]) + opt(where)
    def Insert(t, cols, rows): return b"\x01" + name(t) + lst([name(c) for c in cols]) + lst([lst(r) for r in rows])
    def Update(t, sets, where=None): return b"\x02" + name(t) + lst([name(c) + e for c, e in sets]) + opt(where)
    def Delete(t, where=None): return b"\x03" + name(t) + opt(where)

    def sid(stmt): return hashlib.sha256(STMT_DOMAIN + stmt).digest()
    def stmts_store(*stmts, magic=b"CHODBST2"): return magic + b"".join(u32(len(x)) + x for x in stmts)

    def mint(label, *specs):
        blocks, signer = [], ROOT
        for i, (branch, effects) in enumerate(specs):
            pl = bytes(32) + b16(branch) + lst([effect(k, t) for k, t in effects]) + u64(NONE)
            nsk, npk = g.key("ir2 token %s %d" % (label, i))
            blocks.append(pl + npk + signer.sign(BLOCK_DOMAIN + pl + npk))
            signer = nsk
        return blocks

    def tid(blocks): return hashlib.sha256(TOKEN_DOMAIN + u32(len(blocks)) + b"".join(blocks)).digest()
    def tokens_store(blocks): return b"CHODBTK1" + u32(4 + sum(len(b) for b in blocks)) + u32(len(blocks)) + b"".join(blocks)

    ALL = mint("all", (b"*", [(k, b"*") for k in range(5)]))
    ARGS = "--root " + ROOT_PK.hex() + " --tokens {dir}/%s.tokens --stmts {dir}/%s.stmts"

    def commits(*specs, token=ALL):
        c = g.Chain()
        for stmts, effs in specs:
            assert effs == sorted(set(effs)), "recorded effects must be written in order"
            c.add("main", token=tid(token), time=T, statements=[sid(x) for x in stmts],
                  effects=[effect(k, t) for k, t in effs])
        return c

    def ir(label, chain_, store, expect, token=ALL):
        g.vec(label, g.log(*[g.record(e) for e in chain_.encs]), expect, ARGS % (label, label),
              {".tokens": tokens_store(token), ".stmts": store})

    def ok(n): return "ok commits=%d branches=1 level=2+ir" % n
    def no(rule, at): return g.rejects(rule, at)

    def good(label, stmt, effs):
        ir(label, commits(([stmt], effs)), stmts_store(stmt), ok(1))

    def malformed(label, stmt, magic=b"CHODBST2"):
        one = Delete(b"ok")
        ir(label, commits(([one], [(W, b"ok")])), stmts_store(one, stmt, magic=magic), no("stmt-bad-encoding", 1))

    a = lambda c: Col(b"t", c)

    # ------------------------------------------------------------ valid
    good("ir2_ok_everything_at_once",
         Select2([a(b"a")], [From(b"t")], where=Op(GT, a(b"b"), Const(ONE)), order=[Order(a(b"a"), 1)], limit=Const(TWO),
                 offset=Const(ONE), distinct=1),
         [(R, b"t"), (R, b"t.a"), (R, b"t.b")])
    good("ir2_ok_group_by_and_having",
         Select2([a(b"a"), Call(b"count", Star())], [From(b"t")], group=[a(b"a")],
                 having=Op(GT, Call(b"count", Star()), Const(ONE)), order=[Order(a(b"a"))]),
         [(R, b"t"), (R, b"t.a"), (C, b"count")])
    good("ir2_ok_order_by_a_column_not_selected",
         Select2([a(b"a")], [From(b"t")], order=[Order(a(b"b"))]), [(R, b"t"), (R, b"t.a"), (R, b"t.b")])
    good("ir2_ok_group_by_column_alone",
         Select2([Call(b"count", Star())], [From(b"t")], group=[a(b"g")]), [(R, b"t"), (R, b"t.g"), (C, b"count")])
    good("ir2_ok_having_reads_another_column",
         Select2([Call(b"count", Star())], [From(b"t")], group=[a(b"g")], having=Op(GT, Call(b"sum", a(b"x")), Const(ONE))),
         [(R, b"t"), (R, b"t.g"), (R, b"t.x"), (C, b"count"), (C, b"sum")])
    good("ir2_ok_count_star_alone", Select2([Call(b"count", Star())], [From(b"t")]), [(R, b"t"), (C, b"count")])
    good("ir2_ok_star_reads_no_column", Select2([Star()], [From(b"t")]), [(R, b"t")])
    good("ir2_ok_no_optional_parts_is_a_select", Select2([a(b"a")], [From(b"t")]), [(R, b"t"), (R, b"t.a")])
    good("ir2_ok_distinct_only", Select2([a(b"a")], [From(b"t")], distinct=1), [(R, b"t"), (R, b"t.a")])
    good("ir2_ok_order_directions_and_nulls",
         Select2([Const(ONE)], [From(b"t")], order=[Order(a(b"a"), 0, 0), Order(a(b"b"), 1, 1), Order(a(b"c"), 0, 2)]),
         [(R, b"t"), (R, b"t.a"), (R, b"t.b"), (R, b"t.c")])
    good("ir2_ok_limit_and_offset_may_read_columns",
         Select2([Const(ONE)], [From(b"t")], limit=a(b"n"), offset=a(b"m")), [(R, b"t"), (R, b"t.m"), (R, b"t.n")])

    good("ir2_ok_inner_join",
         Select2([Col(b"a", b"x")], [From(b"a"), From(b"b", 1, Op(EQ, Col(b"a", b"id"), Col(b"b", b"aid")))]),
         [(R, b"a"), (R, b"a.id"), (R, b"a.x"), (R, b"b"), (R, b"b.aid")])
    good("ir2_ok_left_join_with_where",
         Select2([Col(b"a", b"x"), Col(b"b", b"y")],
                 [From(b"a"), From(b"b", 2, Op(EQ, Col(b"a", b"id"), Col(b"b", b"aid")))],
                 where=Unary(NOTNULL, Col(b"b", b"y"))),
         [(R, b"a"), (R, b"a.id"), (R, b"a.x"), (R, b"b"), (R, b"b.aid"), (R, b"b.y")])
    good("ir2_ok_three_tables_comma_and_joins",
         Select2([Const(ONE)], [From(b"a"), From(b"b"), From(b"c", 2, Op(EQ, Col(b"b", b"k"), Col(b"c", b"k")))],
                 where=Op(EQ, Col(b"a", b"k"), Col(b"b", b"k"))),
         [(R, b"a"), (R, b"a.k"), (R, b"b"), (R, b"b.k"), (R, b"c"), (R, b"c.k")])
    good("ir2_ok_join_condition_with_a_function",
         Select2([Const(ONE)], [From(b"a"), From(b"b", 1, Op(EQ, Call(b"lower", Col(b"a", b"n")), Col(b"b", b"n")))]),
         [(R, b"a"), (R, b"a.n"), (R, b"b"), (R, b"b.n"), (C, b"lower")])

    good("ir2_ok_not_and_is_null",
         Select2([a(b"a")], [From(b"t")], where=Unary(NOT, Unary(ISNULL, a(b"b")))), [(R, b"t"), (R, b"t.a"), (R, b"t.b")])
    good("ir2_ok_negation", Select2([Unary(NEG, a(b"a"))], [From(b"t")]), [(R, b"t"), (R, b"t.a")])
    good("ir2_ok_in_list",
         Select2([a(b"a")], [From(b"t")], where=In(0, a(b"a"), Const(ONE), Const(TWO), a(b"b"))),
         [(R, b"t"), (R, b"t.a"), (R, b"t.b")])
    good("ir2_ok_not_in", Select2([a(b"a")], [From(b"t")], where=In(1, a(b"a"), Const(ONE))), [(R, b"t"), (R, b"t.a")])
    good("ir2_ok_like_family",
         Select2([a(b"a")], [From(b"t")],
                 where=Op(AND, Op(LIKE, a(b"n"), Const(g.value_bytes(b"x%"))),
                          Op(OR, Op(ILIKE, a(b"n"), Const(g.value_bytes(b"y%"))),
                             Op(OR, Op(NLIKE, a(b"m"), Const(g.value_bytes(b"z"))),
                                Op(NILIKE, a(b"m"), Const(g.value_bytes(b"w"))))))),
         [(R, b"t"), (R, b"t.a"), (R, b"t.m"), (R, b"t.n")])
    good("ir2_ok_concatenation_and_modulo",
         Select2([Op(CAT, a(b"a"), Const(g.value_bytes(b"!"))), Op(MOD, a(b"b"), Const(TWO))], [From(b"t")]),
         [(R, b"t"), (R, b"t.a"), (R, b"t.b")])
    good("ir2_ok_case_with_else",
         Select2([Case([(Op(GT, a(b"a"), Const(ONE)), a(b"b"))], a(b"c"))], [From(b"t")]),
         [(R, b"t"), (R, b"t.a"), (R, b"t.b"), (R, b"t.c")])
    good("ir2_ok_case_without_else_two_pairs",
         Select2([Case([(Unary(ISNULL, a(b"a")), Const(ONE)), (Unary(NOTNULL, a(b"b")), Const(TWO))])], [From(b"t")]),
         [(R, b"t"), (R, b"t.a"), (R, b"t.b")])
    good("ir2_ok_cast_is_not_a_call", Select2([Cast(b"int4", a(b"a"))], [From(b"t")]), [(R, b"t"), (R, b"t.a")])
    good("ir2_ok_cast_to_a_qualified_type_name",
         Select2([Cast(b"pg_catalog.text", Cast(b"int8", a(b"a")))], [From(b"t")]), [(R, b"t"), (R, b"t.a")])
    good("ir2_ok_nested_everything",
         Select2([Case([(In(0, a(b"a"), Const(ONE)), Cast(b"text", Unary(NEG, a(b"b"))))], Call(b"coalesce", a(b"c"), Const(NULL)))],
                 [From(b"t")]),
         [(R, b"t"), (R, b"t.a"), (R, b"t.b"), (R, b"t.c"), (C, b"coalesce")])

    # v2 expressions inside the v1 statement kinds
    good("ir2_ok_update_with_case_and_in",
         Update(b"t", [(b"a", Case([(In(0, a(b"b"), Const(ONE)), Const(TWO))], a(b"a")))], Unary(NOTNULL, a(b"c"))),
         [(R, b"t.a"), (R, b"t.b"), (R, b"t.c"), (W, b"t")])
    good("ir2_ok_delete_with_like", Delete(b"t", Op(LIKE, a(b"n"), Const(g.value_bytes(b"x%")))),
         [(R, b"t.n"), (W, b"t")])
    good("ir2_ok_insert_with_cast_and_negation",
         Insert(b"t", [b"a", b"b"], [[Cast(b"int4", Const(ONE)), Unary(NEG, Const(TWO))]]), [(W, b"t")])
    good("ir2_ok_call_statement_with_case", b"\x05" + name(b"f") + lst([Case([(Const(ONE), Const(TWO))])]), [(C, b"f")])

    # v1 statements are valid in a v2 store, with the same ids
    good("ir2_ok_a_v1_select_in_a_v2_store",
         Select([a(b"a")], [b"t"], Op(GT, a(b"b"), Const(ONE))), [(R, b"t"), (R, b"t.a"), (R, b"t.b")])
    v1 = Select([a(b"a")], [b"t"])
    mixed = Select2([a(b"a")], [From(b"t")])
    ir("ir2_ok_v1_and_v2_statements_in_one_commit", commits(([v1, mixed], [(R, b"t"), (R, b"t.a")])),
       stmts_store(v1, mixed), ok(1))

    # ----------------------------------------- v2 constructs are refused in a v1 store
    def v1store_refuses(label, stmt):
        one = Delete(b"ok")
        ir(label, commits(([one], [(W, b"ok")])), stmts_store(one, stmt, magic=b"CHODBST1"), no("stmt-bad-encoding", 1))

    v1store_refuses("ir2_v1_store_refuses_select2", Select2([a(b"a")], [From(b"t")]))
    v1store_refuses("ir2_v1_store_refuses_star", Select([Star()], [b"t"]))
    v1store_refuses("ir2_v1_store_refuses_unary", Select([Unary(NOT, a(b"a"))], [b"t"]))
    v1store_refuses("ir2_v1_store_refuses_in", Select([In(0, a(b"a"), Const(ONE))], [b"t"]))
    v1store_refuses("ir2_v1_store_refuses_case", Select([Case([(Const(ONE), Const(TWO))])], [b"t"]))
    v1store_refuses("ir2_v1_store_refuses_cast", Select([Cast(b"int4", a(b"a"))], [b"t"]))
    v1store_refuses("ir2_v1_store_refuses_like", Select([Op(LIKE, a(b"a"), Const(ONE))], [b"t"]))
    v1store_refuses("ir2_v1_store_refuses_concat", Select([Op(CAT, a(b"a"), Const(ONE))], [b"t"]))
    v1store_refuses("ir2_v1_store_refuses_modulo", Select([Op(MOD, a(b"a"), Const(ONE))], [b"t"]))
    ir("ir2_a_store_with_another_magic_is_refused", commits(([v1], [(R, b"t"), (R, b"t.a")])),
       stmts_store(v1, magic=b"CHODBST4"), no("stmts-bad-magic", -1))

    # ------------------------------------------------------- malformed v2 statements
    malformed("ir2_bad_distinct_2", b"\x06\x02" + lst([a(b"a")]) + lst([From(b"t")]) + opt() + lst([]) + opt() + lst([]) + opt() + opt())
    malformed("ir2_bad_no_from", Select2([a(b"a")], []))
    malformed("ir2_bad_first_from_is_a_join", Select2([a(b"a")], [From(b"t", 1, Const(ONE))]))
    malformed("ir2_bad_first_from_has_on", b"\x06\x00" + lst([]) + lst([name(b"t") + b"\x00" + opt(Const(ONE))]) + opt() + lst([]) + opt() + lst([]) + opt() + opt())
    malformed("ir2_bad_join_without_on", Select2([a(b"a")], [From(b"t"), From(b"u", 1)]))
    malformed("ir2_bad_left_join_without_on", Select2([a(b"a")], [From(b"t"), From(b"u", 2)]))
    malformed("ir2_bad_comma_with_on", Select2([a(b"a")], [From(b"t"), From(b"u", 0, Const(ONE))]))
    malformed("ir2_bad_join_kind_3", Select2([a(b"a")], [From(b"t"), From(b"u", 3, Const(ONE))]))
    malformed("ir2_bad_join_kind_3_without_on", Select2([a(b"a")], [From(b"t"), From(b"u", 3)]))
    malformed("ir2_bad_on_flag_2", b"\x06\x00" + lst([]) + lst([From(b"t"), name(b"u") + b"\x01\x02"]) + opt() + lst([]) + opt() + lst([]) + opt() + opt())
    malformed("ir2_bad_order_direction_2", Select2([a(b"a")], [From(b"t")], order=[Order(a(b"a"), 2, 0)]))
    malformed("ir2_bad_order_nulls_3", Select2([a(b"a")], [From(b"t")], order=[Order(a(b"a"), 0, 3)]))
    malformed("ir2_bad_unary_op_4", Select2([Unary(4, a(b"a"))], [From(b"t")]))
    malformed("ir2_bad_in_negated_2", Select2([In(2, a(b"a"), Const(ONE))], [From(b"t")]))
    malformed("ir2_bad_in_no_members", Select2([b"\x08\x00" + u32(0) + a(b"a")], [From(b"t")]))
    malformed("ir2_bad_in_members_overrun", Select2([b"\x08\x00" + u32(5) + a(b"a") + Const(ONE)], [From(b"t")]))
    malformed("ir2_bad_in_count_huge", Select2([b"\x08\x00" + u32(0xFFFFFFFF) + a(b"a")], [From(b"t")]))
    malformed("ir2_bad_case_no_pairs", Select2([b"\x09" + u32(0) + b"\x00"], [From(b"t")]))
    # has_else 2 owes 2n + 2 operands: give them, so only the flag itself is wrong
    malformed("ir2_bad_case_else_flag_2", Select2([b"\x09" + u32(1) + b"\x02" + Const(ONE) + Const(TWO) + Const(ONE) + Const(TWO)], [From(b"t")]))
    malformed("ir2_bad_case_pair_missing_result", Select2([b"\x09" + u32(1) + b"\x00" + Const(ONE)], [From(b"t")]))
    malformed("ir2_bad_case_says_else_has_none", Select2([b"\x09" + u32(1) + b"\x01" + Const(ONE) + Const(TWO)], [From(b"t")]))
    malformed("ir2_bad_case_count_huge", Select2([b"\x09" + u32(0xFFFFFFFF) + b"\x00"], [From(b"t")]))
    malformed("ir2_bad_cast_empty_type", Select2([b"\x0a" + name(b"") + a(b"a")], [From(b"t")]))
    malformed("ir2_bad_cast_missing_operand", Select2([b"\x0a" + name(b"int4")], [From(b"t")]))
    malformed("ir2_bad_operator_18", Select2([Op(18, Const(ONE), Const(ONE))], [From(b"t")]))
    malformed("ir2_bad_expression_tag_11", Select2([b"\x0b"], [From(b"t")]))
    malformed("ir2_bad_select2_trailing_byte", Select2([a(b"a")], [From(b"t")]) + b"\x00")
    malformed("ir2_bad_select2_truncated", Select2([a(b"a")], [From(b"t")], limit=Const(ONE))[:-3])
    malformed("ir2_bad_table_name_with_dot_in_from", Select2([a(b"a")], [From(b"a.b")]))
    malformed("ir2_bad_group_count_huge", b"\x06\x00" + lst([]) + lst([From(b"t")]) + opt() + u32(0xFFFFFFFF))

    # ------------------------------------------------------------- effects-mismatch
    def mismatch(label, stmt, recorded):
        ir(label, commits(([stmt], recorded)), stmts_store(stmt), no("effects-mismatch", 0))

    sel = Select2([a(b"a")], [From(b"t")], order=[Order(a(b"b"))], group=[a(b"g")],
                  having=Op(GT, a(b"h"), Const(ONE)), limit=a(b"l"))
    full = [(R, b"t"), (R, b"t.a"), (R, b"t.b"), (R, b"t.g"), (R, b"t.h"), (R, b"t.l")]
    ir("ir2_ok_every_clause_reads", commits(([sel], full)), stmts_store(sel), ok(1))
    mismatch("ir2_mismatch_order_by_unrecorded", sel, [e for e in full if e[1] != b"t.b"])
    mismatch("ir2_mismatch_group_by_unrecorded", sel, [e for e in full if e[1] != b"t.g"])
    mismatch("ir2_mismatch_having_unrecorded", sel, [e for e in full if e[1] != b"t.h"])
    mismatch("ir2_mismatch_limit_unrecorded", sel, [e for e in full if e[1] != b"t.l"])
    mismatch("ir2_mismatch_join_condition_unrecorded",
             Select2([Const(ONE)], [From(b"a"), From(b"b", 1, Op(EQ, Col(b"a", b"id"), Col(b"b", b"aid")))]),
             [(R, b"a"), (R, b"a.id"), (R, b"b")])
    mismatch("ir2_mismatch_joined_table_unrecorded",
             Select2([Const(ONE)], [From(b"a"), From(b"b", 2, Const(ONE))]), [(R, b"a")])
    mismatch("ir2_mismatch_cast_recorded_as_a_call", Select2([Cast(b"int4", a(b"a"))], [From(b"t")]),
             [(R, b"t"), (R, b"t.a"), (C, b"int4")])
    mismatch("ir2_mismatch_aggregate_unrecorded", Select2([Call(b"count", Star())], [From(b"t")]), [(R, b"t")])
    mismatch("ir2_mismatch_column_in_case_unrecorded",
             Select2([Case([(Const(ONE), a(b"a"))], a(b"b"))], [From(b"t")]), [(R, b"t"), (R, b"t.a")])
    mismatch("ir2_mismatch_column_in_in_list_unrecorded",
             Select2([In(0, a(b"a"), a(b"b"))], [From(b"t")]), [(R, b"t"), (R, b"t.a")])
    mismatch("ir2_mismatch_column_under_not_unrecorded",
             Select2([Unary(NOT, a(b"a"))], [From(b"t")]), [(R, b"t")])
    mismatch("ir2_mismatch_distinct_adds_nothing_recorded_extra",
             Select2([a(b"a")], [From(b"t")], distinct=1), [(R, b"t"), (R, b"t.a"), (W, b"t")])
    mismatch("ir2_mismatch_delete_like_column_unrecorded", Delete(b"t", Op(LIKE, a(b"n"), Const(ONE))), [(W, b"t")])

    # ----------------------------------------------------- the order of rules still holds
    ir("ir2_effect_denied_on_an_order_by_column",
       commits(([Select2([a(b"a")], [From(b"t")], order=[Order(a(b"secret"))])],
                [(R, b"t"), (R, b"t.a"), (R, b"t.secret")]), token=mint("narrow", (b"*", [(R, b"t"), (R, b"t.a")]))),
       stmts_store(Select2([a(b"a")], [From(b"t")], order=[Order(a(b"secret"))])), no("effect-denied", 0),
       token=mint("narrow", (b"*", [(R, b"t"), (R, b"t.a")])))

    # ----------------------------------------------------- history reads (docs/spec/ir.md section 6.1, docs/m2-branches.md D29): a table's Name may end in `@<64 hex digits>`
    HEX = hashlib.sha256(b"a commit").hexdigest().encode()
    HEX2 = hashlib.sha256(b"another commit").hexdigest().encode()
    hist, hist2 = b"orders@" + HEX, b"orders@" + HEX2
    sel_h = Select2([Col(hist, b"id")], [From(hist)])
    good("ir2_history_name_is_read_as_written", sel_h, [(R, hist), (R, hist + b".id")])
    mismatch("ir2_history_suffix_dropped_from_the_recorded_effects", sel_h, [(R, b"orders"), (R, b"orders.id")])
    mismatch("ir2_history_another_commit_recorded", sel_h, [(R, hist2), (R, hist2 + b".id")])
    plain = mint("plain", (b"*", [(R, b"orders"), (R, b"orders.*")]))
    ir("ir2_history_effect_denied_for_a_token_of_the_plain_table", commits(([sel_h], [(R, hist), (R, hist + b".id")]), token=plain), stmts_store(sel_h), no("effect-denied", 0), token=plain)
    hist_tok = mint("history", (b"*", [(R, b"orders@*")]))
    ir("ir2_history_effect_allowed_by_a_history_token", commits(([sel_h], [(R, hist), (R, hist + b".id")]), token=hist_tok), stmts_store(sel_h), ok(1), token=hist_tok)
    prefix_tok = mint("prefix", (b"*", [(R, b"orders*")]))
    ir("ir2_history_effect_allowed_by_a_prefix_pattern", commits(([sel_h], [(R, hist), (R, hist + b".id")]), token=prefix_tok), stmts_store(sel_h), ok(1), token=prefix_tok)
    cur = Select2([Col(b"orders", b"id")], [From(b"orders")])
    ir("ir2_history_token_does_not_allow_the_current_table", commits(([cur], [(R, b"orders"), (R, b"orders.id")]), token=hist_tok), stmts_store(cur), no("effect-denied", 0), token=hist_tok)
    join_h = Select2([Col(hist, b"id"), Col(b"orders", b"id")], [From(hist), From(b"orders", 1, Op(EQ, Col(hist, b"id"), Col(b"orders", b"id")))])
    good("ir2_history_joined_to_the_current_table", join_h, [(R, b"orders"), (R, b"orders.id"), (R, hist), (R, hist + b".id")])
