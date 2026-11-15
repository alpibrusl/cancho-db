"""IR vectors (docs/spec/ir.md), added to the registry of gen_vectors.py by `add(g)`.

Every effect set a commit records here is written out by hand from the inference rules of ir.md section 3, as a literal
list. Nothing calls an inference function: a vector that computed its own expected answer would test the code against itself.
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

    # ----------------------------------------------------- IR encoders
    def name(b): return b16(b)
    def Col(t, c): return b"\x00" + name(t) + name(c)
    def Const(v): return b"\x01" + v
    def Param(i): return b"\x02" + u32(i)
    def Nondet(s): return b"\x03" + name(s)
    def Call(f, *args): return b"\x04" + name(f) + u32(len(args)) + b"".join(args)
    def Op(op, a, b): return b"\x05" + bytes([op]) + a + b
    EQ, NE, LT, LE, GT, GE, AND, OR, ADD, SUB, MUL, DIV = range(12)
    NULL, ONE, TWO = g.value_null(), g.value_int(1), g.value_int(2)

    def opt(e=None): return b"\x00" if e is None else b"\x01" + e
    def Select(items, tables, where=None): return b"\x00" + lst(items) + lst([name(t) for t in tables]) + opt(where)
    def Insert(t, cols, rows): return b"\x01" + name(t) + lst([name(c) for c in cols]) + lst([lst(r) for r in rows])
    def Update(t, sets, where=None): return b"\x02" + name(t) + lst([name(c) + e for c, e in sets]) + opt(where)
    def Delete(t, where=None): return b"\x03" + name(t) + opt(where)
    def Ddl(kind, t): return b"\x04" + bytes([kind]) + name(t)
    def CallStmt(f, args): return b"\x05" + name(f) + lst(args)

    def sid(stmt): return hashlib.sha256(STMT_DOMAIN + stmt).digest()
    def stmts_store(*stmts, magic=b"CHODBST1"): return magic + b"".join(u32(len(s)) + s for s in stmts)

    # a token that allows everything (so that only the IR checks can refuse), and one that allows reads only
    def mint(label, *specs):
        blocks, signer = [], ROOT
        for i, (branch, effects) in enumerate(specs):
            pl = bytes(32) + b16(branch) + lst([effect(k, t) for k, t in effects]) + u64(NONE)
            nsk, npk = g.key("ir token %s %d" % (label, i))
            blocks.append(pl + npk + signer.sign(BLOCK_DOMAIN + pl + npk))
            signer = nsk
        return blocks

    def tid(blocks): return hashlib.sha256(TOKEN_DOMAIN + u32(len(blocks)) + b"".join(blocks)).digest()
    def tokens_store(blocks): return b"CHODBTK1" + u32(4 + sum(len(b) for b in blocks)) + u32(len(blocks)) + b"".join(blocks)

    ALL = mint("all", (b"*", [(k, b"*") for k in range(5)]))
    READ_ONLY = mint("read only", (b"*", [(R, b"*")]))
    ARGS = "--root " + ROOT_PK.hex() + " --tokens {dir}/%s.tokens --stmts {dir}/%s.stmts"

    def commits(*specs, token=ALL, branch="main"):
        """specs: (statements [bytes], recorded effects [(kind, target)]) -> the chain. Effects are listed in the
        order given: write them already in (kind, target) order."""
        c = g.Chain()
        for stmts, effs in specs:
            assert effs == sorted(set(effs)), "recorded effects must be written in order"
            c.add(branch, token=tid(token), time=T, statements=[sid(s) for s in stmts],
                  effects=[effect(k, t) for k, t in effs])
        return c

    def ir(label, chain_, store, expect, token=ALL, args=None, log_bytes=None, tokens=None):
        log = log_bytes if log_bytes is not None else g.log(*[g.record(e) for e in chain_.encs])
        g.vec(label, log, expect, args or (ARGS % (label, label)),
              {".tokens": tokens if tokens is not None else tokens_store(token), ".stmts": store})

    def ok(n, branches=1): return "ok commits=%d branches=%d level=2+ir" % (n, branches)
    def no(rule, at): return g.rejects(rule, at)

    def one(label, stmt, effs, token=ALL):
        ir(label, commits(([stmt], effs), token=token), stmts_store(stmt), ok(1), token)

    # ------------------------------------------------------------- valid
    sel = Select([Col(b"orders", b"id"), Col(b"orders", b"total")], [b"orders"],
                 Op(GT, Col(b"orders", b"total"), Param(1)))
    sel_effs = [(R, b"orders"), (R, b"orders.id"), (R, b"orders.total")]
    one("ir_ok_select", sel, sel_effs)
    one("ir_ok_select_constant_still_reads_the_table", Select([Const(ONE)], [b"orders"]), [(R, b"orders")])
    one("ir_ok_select_no_where", Select([Col(b"orders", b"id")], [b"orders"]), [(R, b"orders"), (R, b"orders.id")])
    one("ir_ok_select_where_only_column", Select([Const(ONE)], [b"t"], Col(b"t", b"c")), [(R, b"t"), (R, b"t.c")])
    one("ir_ok_select_same_column_twice", Select([Col(b"t", b"c"), Col(b"t", b"c")], [b"t"], Col(b"t", b"c")),
        [(R, b"t"), (R, b"t.c")])
    one("ir_ok_select_no_items", Select([], [b"t"]), [(R, b"t")])
    join = Select([Col(b"orders", b"id"), Col(b"users", b"name")], [b"orders", b"users"],
                  Op(EQ, Col(b"orders", b"uid"), Col(b"users", b"id")))
    one("ir_ok_select_join", join, [(R, b"orders"), (R, b"orders.id"), (R, b"orders.uid"), (R, b"users"),
                                    (R, b"users.id"), (R, b"users.name")])
    one("ir_ok_select_functions", Select([Call(b"lower", Col(b"users", b"name")), Nondet(b"now")], [b"users"]),
        [(R, b"users"), (R, b"users.name"), (C, b"lower"), (N, b"now")])
    one("ir_ok_select_const_kinds", Select([Const(NULL), Const(ONE), Const(g.value_bytes(b"x"))], [b"t"]), [(R, b"t")])
    one("ir_ok_select_zero_arg_call", Select([Call(b"pi")], [b"t"]), [(R, b"t"), (C, b"pi")])
    one("ir_ok_select_names_with_dots_in_functions", Select([Call(b"pg.round", Nondet(b"seq.orders_id"))], [b"t"]),
        [(R, b"t"), (C, b"pg.round"), (N, b"seq.orders_id")])
    deep = Op(AND, Op(EQ, Col(b"a", b"x"), Const(ONE)),
              Op(OR, Op(LT, Col(b"a", b"y"), Param(2)), Op(GT, Col(b"a", b"z"), Const(TWO))))
    one("ir_ok_select_deep_expression", Select([Const(ONE)], [b"a"], deep),
        [(R, b"a"), (R, b"a.x"), (R, b"a.y"), (R, b"a.z")])
    nested = Call(b"f", Call(b"g", Call(b"h", Op(ADD, Col(b"t", b"c"), Param(0))), Const(ONE)), Param(1))
    one("ir_ok_select_nested_calls", Select([nested], [b"t"]), [(R, b"t"), (R, b"t.c"), (C, b"f"), (C, b"g"), (C, b"h")])

    one("ir_ok_insert", Insert(b"orders", [b"id", b"total"], [[Const(ONE), Param(1)], [Const(TWO), Const(NULL)]]),
        [(W, b"orders")])
    one("ir_ok_insert_nondet", Insert(b"orders", [b"created"], [[Nondet(b"now")]]), [(W, b"orders"), (N, b"now")])
    one("ir_ok_insert_no_rows", Insert(b"orders", [b"id"], []), [(W, b"orders")])
    one("ir_ok_insert_function", Insert(b"orders", [b"id"], [[Call(b"gen_id")]]), [(W, b"orders"), (C, b"gen_id")])

    one("ir_ok_update", Update(b"orders", [(b"total", Op(ADD, Col(b"orders", b"total"), Const(ONE)))],
                               Op(EQ, Col(b"orders", b"id"), Param(1))),
        [(R, b"orders.id"), (R, b"orders.total"), (W, b"orders")])
    one("ir_ok_update_constant", Update(b"orders", [(b"total", Const(g.value_int(0)))]), [(W, b"orders")])
    one("ir_ok_update_two_sets", Update(b"o", [(b"a", Col(b"o", b"b")), (b"b", Col(b"o", b"a"))]),
        [(R, b"o.a"), (R, b"o.b"), (W, b"o")])
    one("ir_ok_delete", Delete(b"orders", Op(EQ, Col(b"orders", b"id"), Param(1))),
        [(R, b"orders.id"), (W, b"orders")])
    one("ir_ok_delete_all", Delete(b"orders"), [(W, b"orders")])

    c = commits(*[([Ddl(k, b"orders")], [(D, b"orders")]) for k in range(5)])
    ir("ir_ok_ddl_all_kinds", c, stmts_store(*[Ddl(k, b"orders") for k in range(5)]), ok(5))

    one("ir_ok_call_statement", CallStmt(b"refund", [Param(1)]), [(C, b"refund")])
    one("ir_ok_call_statement_nested", CallStmt(b"refund", [Call(b"round", Op(ADD, Const(ONE), Nondet(b"random")))]),
        [(C, b"refund"), (C, b"round"), (N, b"random")])
    one("ir_ok_call_statement_no_args", CallStmt(b"vacuum", []), [(C, b"vacuum")])

    upd = Update(b"orders", [(b"total", Col(b"orders", b"total"))])
    # a commit of two statements records the union, without repeats
    ir("ir_ok_two_statements_union", commits(([sel, upd], [(R, b"orders"), (R, b"orders.id"), (R, b"orders.total"),
                                                           (W, b"orders")])),
       stmts_store(sel, upd), ok(1))
    ir("ir_ok_same_statement_twice", commits(([sel, sel], sel_effs)), stmts_store(sel), ok(1))
    ir("ir_ok_statement_order_is_irrelevant", commits(([upd, sel], [(R, b"orders"), (R, b"orders.id"),
                                                                       (R, b"orders.total"), (W, b"orders")])),
       stmts_store(sel, upd), ok(1))
    ir("ir_ok_no_statements", commits(([], [])), stmts_store(), ok(1))
    ins = Insert(b"t", [b"c"], [[Call(b"f")]])
    ir("ir_ok_every_kind_in_one_commit",
       commits(([Select([Col(b"s", b"x")], [b"s"]), ins, Ddl(1, b"d"), CallStmt(b"g", [Nondet(b"now")])],
                [(R, b"s"), (R, b"s.x"), (W, b"t"), (D, b"d"), (C, b"f"), (C, b"g"), (N, b"now")])),
       stmts_store(Select([Col(b"s", b"x")], [b"s"]), ins, Ddl(1, b"d"), CallStmt(b"g", [Nondet(b"now")])), ok(1))
    ir("ir_ok_two_commits", commits(([sel], sel_effs), ([upd], [(R, b"orders.total"), (W, b"orders")])),
       stmts_store(sel, upd), ok(2))
    ir("ir_ok_unused_statement_in_store", commits(([sel], sel_effs)), stmts_store(upd, sel, Delete(b"x")), ok(1))
    ir("ir_ok_statement_listed_twice_in_store", commits(([sel], sel_effs)), stmts_store(sel, sel), ok(1))

    # ------------------------------------------------------ stmt-missing
    other = Delete(b"elsewhere")
    ir("ir_stmt_missing", commits(([sel], sel_effs)), stmts_store(other), no("stmt-missing", 0))
    ir("ir_stmt_missing_empty_store", commits(([sel], sel_effs)), stmts_store(), no("stmt-missing", 0))
    ir("ir_stmt_missing_second_of_two", commits(([sel, upd], [(R, b"orders"), (R, b"orders.id"),
                                                               (R, b"orders.total"), (W, b"orders")])),
       stmts_store(sel), no("stmt-missing", 0))
    ir("ir_stmt_missing_second_commit", commits(([sel], sel_effs), ([upd], [(W, b"orders")])), stmts_store(sel),
       no("stmt-missing", 1))

    # -------------------------------------------------- effects-mismatch
    def mismatch(label, stmt_list, recorded, store=None):
        ir(label, commits((stmt_list, recorded)), store or stmts_store(*stmt_list), no("effects-mismatch", 0))

    mismatch("ir_mismatch_missing_column_read", [sel], [(R, b"orders"), (R, b"orders.id")])
    mismatch("ir_mismatch_missing_table_read", [sel], [(R, b"orders.id"), (R, b"orders.total")])
    mismatch("ir_mismatch_extra_effect", [sel], sel_effs + [(W, b"orders")])
    mismatch("ir_mismatch_extra_column", [sel], sel_effs + [(R, b"orders.zzz")])
    mismatch("ir_mismatch_extra_table", [sel], sel_effs + [(R, b"users")])
    mismatch("ir_mismatch_nothing_recorded", [sel], [])
    mismatch("ir_mismatch_wrong_column", [sel], [(R, b"orders"), (R, b"orders.id"), (R, b"orders.uid")])
    mismatch("ir_mismatch_wrong_kind", [sel], [(R, b"orders.id"), (R, b"orders.total"), (W, b"orders")])
    mismatch("ir_mismatch_insert_unrecorded", [Insert(b"t", [b"c"], [[Const(ONE)]])], [])
    mismatch("ir_mismatch_insert_recorded_as_read", [Insert(b"t", [b"c"], [[Const(ONE)]])], [(R, b"t")])
    mismatch("ir_mismatch_insert_nondet_unrecorded", [Insert(b"t", [b"c"], [[Nondet(b"now")]])], [(W, b"t")])
    mismatch("ir_mismatch_update_write_unrecorded", [upd], [(R, b"orders.total")])
    mismatch("ir_mismatch_update_where_unrecorded", [Update(b"o", [(b"a", Const(ONE))], Col(b"o", b"k"))], [(W, b"o")])
    mismatch("ir_mismatch_delete_where_unrecorded", [Delete(b"o", Col(b"o", b"k"))], [(W, b"o")])
    mismatch("ir_mismatch_ddl_unrecorded", [Ddl(2, b"o")], [])
    mismatch("ir_mismatch_ddl_recorded_as_write", [Ddl(2, b"o")], [(W, b"o")])
    mismatch("ir_mismatch_call_unrecorded", [CallStmt(b"f", [])], [])
    mismatch("ir_mismatch_call_argument_unrecorded", [CallStmt(b"f", [Call(b"g")])], [(C, b"f")])
    mismatch("ir_mismatch_nondet_unrecorded", [Select([Nondet(b"now")], [b"t"])], [(R, b"t")])
    mismatch("ir_mismatch_second_statement_unrecorded", [sel, upd], sel_effs)
    mismatch("ir_mismatch_effects_without_statements", [], [(R, b"orders")])
    mismatch("ir_mismatch_call_target_is_not_a_prefix", [CallStmt(b"fn.refund", [])], [(C, b"fn.refund_all")])
    ir("ir_mismatch_second_commit", commits(([sel], sel_effs), ([sel], [])), stmts_store(sel),
       no("effects-mismatch", 1))

    # the gap this closes: a server that records less than it ran passes L2 alone and is refused with the statements
    ins_t = Insert(b"orders", [b"id"], [[Const(ONE)]])
    lying = commits(([ins_t], []), token=READ_ONLY)
    g.vec("ir_gap_hidden_write_passes_l2_alone", g.log(*[g.record(e) for e in lying.encs]), "ok commits=1 branches=1 level=2",
          "--root " + ROOT_PK.hex() + " --tokens {dir}/ir_gap_hidden_write_passes_l2_alone.tokens",
          {".tokens": tokens_store(READ_ONLY)})
    ir("ir_gap_hidden_write_is_refused_with_statements", lying, stmts_store(ins_t), no("effects-mismatch", 0),
       token=READ_ONLY)
    truthful = commits(([ins_t], [(W, b"orders")]), token=READ_ONLY)
    ir("ir_effect_denied_on_the_true_effects", truthful, stmts_store(ins_t), no("effect-denied", 0), token=READ_ONLY)
    r_only_stmt = Select([Col(b"orders", b"id")], [b"orders"])
    ir("ir_ok_read_only_token_reads", commits(([r_only_stmt], [(R, b"orders"), (R, b"orders.id")]), token=READ_ONLY),
       stmts_store(r_only_stmt), ok(1), token=READ_ONLY)
    # a select needs `read orders` as well as its columns: `orders.*` alone does not match `orders`
    cols_only = mint("cols only", (b"*", [(R, b"orders.*")]))
    ir("ir_effect_denied_select_needs_the_table", commits(([r_only_stmt], [(R, b"orders"), (R, b"orders.id")]),
                                                           token=cols_only),
       stmts_store(r_only_stmt), no("effect-denied", 0), token=cols_only)

    # ---------------------------------------------------------- the order
    c1 = commits(([sel], [(R, b"orders")]))  # recorded set is wrong AND the statement is not in the store
    ir("ir_order_missing_before_mismatch", c1, stmts_store(other), no("stmt-missing", 0))
    ir("ir_order_mismatch_before_denied", commits(([sel], [(W, b"orders")]), token=READ_ONLY), stmts_store(sel),
       no("effects-mismatch", 0), token=READ_ONLY)
    narrow = mint("narrow", (b"main", [(R, b"*")]))
    c2 = g.Chain()
    c2.add("other", token=tid(narrow), time=T, statements=[g.h("nowhere")], effects=[])
    ir("ir_order_branch_before_statements", c2, stmts_store(), no("branch-denied", 0), token=narrow)

    # ----------------------------------------------- store failures
    one_commit = commits(([sel], sel_effs))
    good = stmts_store(sel)
    ir("ir_stmts_bad_magic", one_commit, b"CHODBST3" + good[8:], no("stmts-bad-magic", -1))
    ir("ir_stmts_empty_file", one_commit, b"", no("stmts-truncated", -1))
    ir("ir_stmts_short_header", one_commit, b"CHODB", no("stmts-truncated", -1))
    ir("ir_stmts_truncated_length", one_commit, good + b"\x00\x00", no("stmts-truncated", 1))
    ir("ir_stmts_truncated_body", one_commit, good[:-1], no("stmts-truncated", 0))
    ir("ir_stmts_length_lies", one_commit, good + u32(0xFFFFFFFF) + b"x", no("stmts-truncated", 1))

    def bad(label, raw):
        ir(label, one_commit, stmts_store(sel, raw), no("stmt-bad-encoding", 1))

    bad("ir_bad_empty_record", b"")
    bad("ir_bad_unknown_statement_tag", b"\x06")
    bad("ir_bad_select_without_from", Select([], []))
    bad("ir_bad_select_from_name_empty", Select([], [b""]))
    bad("ir_bad_select_from_name_with_dot", Select([], [b"a.b"]))
    bad("ir_bad_column_name_with_dot", Select([Col(b"t", b"a.b")], [b"t"]))
    bad("ir_bad_column_table_with_dot", Select([Col(b"t.x", b"c")], [b"t"]))
    bad("ir_bad_column_name_empty", Select([Col(b"t", b"")], [b"t"]))
    bad("ir_bad_insert_table_with_dot", Insert(b"a.b", [b"c"], []))
    bad("ir_bad_insert_column_with_dot", Insert(b"t", [b"a.b"], []))
    bad("ir_bad_insert_row_too_short", Insert(b"t", [b"a", b"b"], [[Const(ONE)]]))
    bad("ir_bad_insert_row_too_long", Insert(b"t", [b"a"], [[Const(ONE), Const(ONE)]]))
    # the row's own count must equal the number of columns even when the bytes happen to line up
    two_cols = b"\x01" + name(b"t") + lst([name(b"a"), name(b"b")]) + u32(1)
    bad("ir_bad_insert_row_count_larger_than_its_expressions", two_cols + u32(3) + Const(ONE) + Const(ONE))
    bad("ir_bad_insert_row_count_smaller_than_its_expressions", two_cols + u32(1) + Const(ONE) + Const(ONE))
    bad("ir_bad_insert_column_reference_in_values", Insert(b"t", [b"a"], [[Col(b"t", b"b")]]))
    bad("ir_bad_update_without_sets", Update(b"t", []))
    bad("ir_bad_update_set_column_with_dot", Update(b"t", [(b"a.b", Const(ONE))]))
    bad("ir_bad_ddl_kind_5", Ddl(5, b"t"))
    bad("ir_bad_ddl_table_with_dot", Ddl(0, b"t.x"))
    bad("ir_bad_optional_flag_2", b"\x03" + name(b"t") + b"\x02")
    bad("ir_bad_unknown_expression_tag", Select([b"\x06"], [b"t"]))
    bad("ir_bad_operator_12", Select([Op(12, Const(ONE), Const(ONE))], [b"t"]))
    bad("ir_bad_value_tag_3", Select([Const(b"\x03")], [b"t"]))
    bad("ir_bad_value_int_short", Select([Const(b"\x01\x00\x00")], [b"t"]))
    bad("ir_bad_value_bytes_overrun", Select([Const(b"\x02" + u32(99) + b"ab")], [b"t"]))
    bad("ir_bad_operator_missing_operand", Select([Op(EQ, Const(ONE), b"")], [b"t"]))
    bad("ir_bad_operator_missing_both_operands", b"\x03" + name(b"t") + b"\x01" + b"\x05\x00")
    bad("ir_bad_extra_operand", b"\x03" + name(b"t") + b"\x01" + Op(EQ, Const(ONE), Const(ONE)) + Const(ONE))
    bad("ir_bad_call_argc_exceeds_arguments", b"\x03" + name(b"t") + b"\x01" + b"\x04" + name(b"f") + u32(3) + Const(ONE))
    bad("ir_bad_call_argc_huge", b"\x03" + name(b"t") + b"\x01" + b"\x04" + name(b"f") + u32(0xFFFFFFFF))
    bad("ir_bad_call_name_empty", Select([b"\x04" + name(b"") + u32(0)], [b"t"]))
    bad("ir_bad_nondet_name_empty", Select([Nondet(b"")], [b"t"]))
    bad("ir_bad_call_statement_name_empty", CallStmt(b"", []))
    bad("ir_bad_items_count_huge", b"\x00" + u32(0xFFFFFFFF))
    bad("ir_bad_rows_count_huge", b"\x01" + name(b"t") + u32(0) + u32(0xFFFFFFFF))
    bad("ir_bad_trailing_byte", Delete(b"t") + b"\x00")
    bad("ir_bad_cut_in_name", b"\x03" + u16_overrun())
    bad("ir_bad_only_a_tag", b"\x00")
    # entries are judged one at a time: an earlier malformed statement beats a later truncated entry
    ir("ir_bad_entry_before_truncated_entry", one_commit, stmts_store(sel, b"\x07") + u32(0xFFFFFFFF),
       no("stmt-bad-encoding", 1))

    # a bad entry is an error even if nothing uses it
    ir("ir_bad_entry_unused_is_still_an_error", one_commit, stmts_store(sel, b"\x07", Delete(b"x")),
       no("stmt-bad-encoding", 1))
    # a name that is only a dot-free long run is fine (no length limit but u16)
    long_name = b"n" * 1000
    one("ir_ok_long_names", Select([Col(long_name, long_name)], [long_name]),
        [(R, long_name), (R, long_name + b"." + long_name)])

    # ----------------------------------------------- store order
    tk = tokens_store(ALL)
    ir("ir_order_tokens_before_stmts", one_commit, b"CHODBST3", no("tokens-bad-magic", -1), tokens=b"CHODBTK2")
    rev_bad = b"CHODBRV2"
    g.vec("ir_order_revoked_before_stmts", g.log(*[g.record(e) for e in one_commit.encs]),
          no("revocations-bad-magic", -1),
          "--root " + ROOT_PK.hex() + " --tokens {dir}/ir_order_revoked_before_stmts.tokens --revoked "
          "{dir}/ir_order_revoked_before_stmts.revoked --stmts {dir}/ir_order_revoked_before_stmts.stmts",
          {".tokens": tk, ".revoked": rev_bad, ".stmts": b"CHODBST3"})
    ir("ir_order_stmts_before_commits", commits(([sel], sel_effs), ([sel], sel_effs)), b"CHODBST3",
       no("stmts-bad-magic", -1))
    bad_log = g.log(g.record(one_commit.encs[0]), g.record(one_commit.encs[0]))
    ir("ir_order_l1_before_stmts", one_commit, b"CHODBST3", no("duplicate-commit", 1), log_bytes=bad_log)
    ir("ir_empty_log", commits(), good, ok(0, 0))
    ir("ir_empty_log_bad_stmts", commits(), b"CHODBST3", no("stmts-bad-magic", -1))


def u16_overrun():
    """A name that claims 60000 bytes and has none."""
    return b"\xea\x60"
