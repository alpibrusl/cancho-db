"""L2 vectors (docs/spec/token.md), added to the registry of gen_vectors.py by `add(g)`.

As there, the expected line of every vector is written by hand from the spec, and the keys are fixed so the output is
reproducible. `{dir}` in an args line is the vectors directory (tests/run_vectors.py fills it in).
"""
import hashlib
import struct

NONE = 2**64 - 1
TOKEN_DOMAIN = b"cancho-db/token/v1\x00"
BLOCK_DOMAIN = b"cancho-db/token-block/v1\x00"
REVOKE_DOMAIN = b"cancho-db/revoke/v1\x00"
ZERO = bytes(32)


def add(g):
    u32, u64, b16, lst, effect = g.u32, g.u64, g.b16, g.lst, g.effect
    ROOT, ROOT_PK = g.key("root")
    FOREIGN, FOREIGN_PK = g.key("foreign root")
    _, P1 = g.key("agent 1")
    _, P2 = g.key("agent 2")
    T = 1_700_000_000_000
    ROOT_ARG = "--root " + ROOT_PK.hex()

    # ------------------------------------------------------------ builders
    def payload(principal=ZERO, branch=b"*", effects=(), expiry=NONE, raw=False):
        effects = list(effects)
        if not raw:
            assert effects == sorted(set(effects)), "token effects must be strictly ascending"
        return principal + b16(branch) + lst([effect(k, t) for k, t in effects]) + u64(expiry)

    def block(pl, next_pk, signer):
        return pl + next_pk + signer.sign(BLOCK_DOMAIN + pl + next_pk)

    def mint(label, *specs, root=ROOT):
        """A valid token: blocks signed in order, each by the key the previous one names. -> list of block bytes."""
        blocks, signer = [], root
        for i, spec in enumerate(specs):
            nsk, npk = g.key("token %s block %d" % (label, i))
            blocks.append(block(payload(**spec), npk, signer))
            signer = nsk
        return blocks

    def enc(blocks):
        return u32(len(blocks)) + b"".join(blocks)

    def tid(blocks, k=None):
        k = len(blocks) if k is None else k
        return hashlib.sha256(TOKEN_DOMAIN + u32(k) + b"".join(blocks[:k])).digest()

    def store(*encodings, magic=b"CHODBTK1"):
        return magic + b"".join(u32(len(e)) + e for e in encodings)

    def revocation(ident, since, signer=ROOT):
        return ident + u64(since) + signer.sign(REVOKE_DOMAIN + ident + u64(since))

    def revoked(*entries, magic=b"CHODBRV1"):
        return magic + b"".join(entries)

    def chain(*commits):
        """commits: dicts of commit() arguments plus `branch`. -> (encodings, tip ids)"""
        c = g.Chain()
        for kw in commits:
            kw = dict(kw)
            c.add(kw.pop("branch", "main"), **kw)
        return c

    def l2(name, c, tokens, expect, rev=None, args_extra="", log_bytes=None):
        files = {".tokens": tokens}
        args = ROOT_ARG + " --tokens {dir}/%s.tokens" % name
        if rev is not None:
            files[".revoked"] = rev
            args += " --revoked {dir}/%s.revoked" % name
        g.vec(name, log_bytes if log_bytes is not None else g.log(*[g.record(e) for e in c.encs]), expect,
              (args + " " + args_extra).strip(), files)

    def ok(commits, branches=1): return "ok commits=%d branches=%d level=2" % (commits, branches)
    def no(rule, at): return g.rejects(rule, at)

    ORDERS = dict(branch=b"main", effects=[(0, b"orders.*"), (1, b"orders")])
    basic = mint("basic", ORDERS)
    use = dict(token=tid(basic), effects=[effect(0, b"orders.total"), effect(1, b"orders")], time=T)
    one = chain(use)

    # ------------------------------------------------------------- valid
    c = chain(use, use, use)
    l2("l2_ok_basic", c, store(enc(basic)), ok(3))

    nothing = mint("nothing", dict(branch=b"main"))
    l2("l2_ok_no_effects", chain(dict(token=tid(nothing), time=T)), store(enc(nothing)), ok(1))

    wide = mint("wide", dict(branch=b"agent-7/*", effects=[(0, b"*"), (1, b"*"), (2, b"*"), (3, b"fn.*"), (4, b"*")]))
    c = chain(dict(branch="agent-7/a", token=tid(wide), time=T,
                   effects=[effect(0, b"x.y"), effect(1, b"t"), effect(2, b"t"), effect(3, b"fn.refund"),
                            effect(4, b"")]),
              dict(branch="agent-7/", token=tid(wide), time=T))
    l2("l2_ok_wildcards", c, store(enc(wide)), ok(2, 2))

    att = mint("att",
               dict(branch=b"*", effects=[(0, b"*"), (1, b"*")]),
               dict(branch=b"agent/*", effects=[(0, b"orders.*"), (1, b"orders")], expiry=T + 10),
               dict(principal=P1, branch=b"agent/a", effects=[(0, b"orders.total")]))
    c = chain(dict(branch="agent/a", token=tid(att), principal=P1, time=T, effects=[effect(0, b"orders.total")]))
    l2("l2_ok_attenuated", c, store(enc(att)), ok(1))

    bound = mint("bound", dict(principal=P1, branch=b"*"))
    bearer = mint("bearer", dict(branch=b"*"))
    c = chain(dict(token=tid(bound), principal=P1, time=T), dict(token=tid(bearer), principal=P2, time=T))
    l2("l2_ok_principal_bound_and_bearer", c, store(enc(bound), enc(bearer)), ok(2))

    exp_eq = mint("exp eq", dict(branch=b"*", expiry=T))
    c = chain(dict(token=tid(exp_eq), time=T), dict(token=tid(bearer), time=NONE))
    l2("l2_ok_expiry_boundary_and_none", c, store(enc(exp_eq), enc(bearer)), ok(2))

    hi = mint("hi", dict(branch=b"*", expiry=2**63 + 5))
    l2("l2_ok_expiry_high_bit", chain(dict(token=tid(hi), time=2**63 + 5)), store(enc(hi)), ok(1))

    junk = mint("junk", dict(branch=b"*"), root=FOREIGN)  # a valid encoding, signed by the wrong root, never used
    l2("l2_ok_unused_bad_token_in_store", one, store(enc(junk), enc(basic)), ok(1))
    l2("l2_ok_duplicate_token_in_store", one, store(enc(basic), enc(basic)), ok(1))

    l2("l2_ok_revoked_later", one, store(enc(basic)), ok(1), revoked(revocation(tid(basic), T + 1)))
    l2("l2_ok_revoked_other_token", one, store(enc(basic)), ok(1), revoked(revocation(g.h("some other token"), 0)))
    l2("l2_ok_no_revocations", one, store(enc(basic)), ok(1), revoked())
    l2("l2_ok_revoked_since_above_signed_range", chain(dict(token=tid(basic), time=2**63)), store(enc(basic)), ok(1),
       revoked(revocation(tid(basic), NONE)))

    # revoking an attenuation does not revoke what it was attenuated from
    child = mint("basic", ORDERS, dict(branch=b"main", effects=[(0, b"orders.total")]))
    assert child[0] == basic[0]
    c = chain(dict(token=tid(basic), time=T))
    l2("l2_ok_revoking_child_leaves_parent", c, store(enc(basic), enc(child)), ok(1),
       revoked(revocation(tid(child), 0)))

    # A prefix of a token is itself a valid token (and a wider one): the chain cannot tell it was cut. That is why
    # presenting a token needs a proof of the last key (token.md §1), which a log cannot check.
    c = chain(dict(token=tid(child, 1), time=T, effects=[effect(0, b"orders.id")]))
    l2("l2_ok_token_prefix_is_a_token", c, store(enc(child[:1])), ok(1))

    emp = mint("emp", dict(branch=b"*", effects=[(4, b"")]))
    c = chain(dict(token=tid(emp), time=T, effects=[effect(4, b"")]))
    l2("l2_ok_empty_pattern_matches_empty_target", c, store(enc(emp)), ok(1))

    sharp = mint("sharp", dict(branch=b"*", effects=[(0, b"o*")]))
    c = chain(dict(token=tid(sharp), time=T, effects=[effect(0, b"orders")]))
    l2("l2_ok_star_is_a_prefix_sharp_edge", c, store(enc(sharp)), ok(1))

    # ------------------------------------------------- token missing / chain
    l2("l2_token_missing_empty_store", one, store(), no("token-missing", 0))
    l2("l2_token_missing_other_token", one, store(enc(bearer)), no("token-missing", 0))
    c = chain(use, dict(use, token=g.h("nobody")))
    l2("l2_token_missing_second_commit", c, store(enc(basic)), no("token-missing", 1))

    def tampered(blocks, edit):
        """-> (token encoding, id) of a token whose bytes were edited after signing."""
        e = edit(blocks)
        return e, tid(e)

    def flip(b, at):
        x = bytearray(b)
        x[at] ^= 1
        return bytes(x)

    def with_token(label, blocks, extra_commit_kw=None, rule="token-bad-signature", args_store=None):
        kw = dict(token=tid(blocks), time=T, **(extra_commit_kw or {}))
        l2(label, chain(kw), args_store or store(enc(blocks)), no(rule, 0))

    with_token("l2_sig_wrong_root", mint("basic", ORDERS, root=FOREIGN))
    with_token("l2_sig_payload_flipped", [flip(basic[0], 35)])      # inside the branch pattern: "main" -> "mbin"
    with_token("l2_sig_next_key_flipped", [flip(basic[0], len(basic[0]) - 64 - 1)])
    with_token("l2_sig_signature_flipped", [flip(basic[0], len(basic[0]) - 1)])
    with_token("l2_sig_zeroed", [basic[0][:-64] + bytes(64)])
    with_token("l2_sig_second_block_flipped", [child[0], flip(child[1], len(child[1]) - 1)])

    three = mint("three", dict(branch=b"*"), dict(branch=b"*"), dict(branch=b"*"))
    with_token("l2_blocks_reordered", [three[0], three[2], three[1]])
    with_token("l2_block_dropped_from_middle", [three[0], three[2]])
    with_token("l2_blocks_swapped_first_two", [three[1], three[0], three[2]])
    wrong_sk, wrong_pk = g.key("not the chain's key")
    with_token("l2_second_block_signed_by_stranger",
               [three[0], block(payload(branch=b"*"), wrong_pk, wrong_sk)])
    with_token("l2_block_appended_by_stranger", three + [block(payload(branch=b"*"), wrong_pk, wrong_sk)])
    with_token("l2_first_block_signed_by_stranger", [block(payload(branch=b"*"), wrong_pk, wrong_sk)])

    # a key that is not a point: no signature verifies under it, and that is a verdict, not a crash
    junk_key = bytes([0xFF]) * 32
    chain_bad = [block(payload(branch=b"*"), junk_key, ROOT), block(payload(branch=b"*"), wrong_pk, wrong_sk)]
    with_token("l2_next_key_is_not_a_point", chain_bad)

    # ---------------------------------------------------------- revocation
    l2("l2_revoked_equal_time", one, store(enc(basic)), no("token-revoked", 0), revoked(revocation(tid(basic), T)))
    l2("l2_revoked_since_earlier", one, store(enc(basic)), no("token-revoked", 0),
       revoked(revocation(tid(basic), 0)))
    c = chain(dict(use, time=100), dict(use, time=200))
    l2("l2_revoked_second_commit_only", c, store(enc(basic)), no("token-revoked", 1),
       revoked(revocation(tid(basic), 150)))
    c = chain(dict(token=tid(child), time=T))
    l2("l2_revoked_parent_prefix", c, store(enc(child)), no("token-revoked", 0),
       revoked(revocation(tid(child, 1), 0)))
    l2("l2_revoked_whole_child", c, store(enc(child)), no("token-revoked", 0), revoked(revocation(tid(child), 0)))
    c = chain(dict(token=tid(basic), time=NONE))
    l2("l2_revoked_time_above_signed_range", c, store(enc(basic)), no("token-revoked", 0),
       revoked(revocation(tid(basic), 2**63)))
    l2("l2_revoked_among_many", one, store(enc(basic)), no("token-revoked", 0),
       revoked(revocation(g.h("a"), 0), revocation(tid(basic), 0), revocation(g.h("b"), 0)))
    l2("l2_revoked_twice_earliest_wins_later_first", one, store(enc(basic)), no("token-revoked", 0),
       revoked(revocation(tid(basic), T - 100), revocation(tid(basic), T + 100)))
    l2("l2_revoked_twice_earliest_wins", one, store(enc(basic)), no("token-revoked", 0),
       revoked(revocation(tid(basic), T + 100), revocation(tid(basic), T - 100)))

    # -------------------------------------------------------------- expiry
    ex = mint("ex", dict(branch=b"*", expiry=T - 1))
    l2("l2_expired", chain(dict(token=tid(ex), time=T)), store(enc(ex)), no("token-expired", 0))
    ex2 = mint("ex2", dict(branch=b"*"), dict(branch=b"*", expiry=T - 1))
    l2("l2_expired_by_attenuation", chain(dict(token=tid(ex2), time=T)), store(enc(ex2)), no("token-expired", 0))
    ex3 = mint("ex3", dict(branch=b"*", expiry=T - 1), dict(branch=b"*", expiry=NONE))
    l2("l2_expired_attenuation_cannot_extend", chain(dict(token=tid(ex3), time=T)), store(enc(ex3)),
       no("token-expired", 0))
    l2("l2_expired_high_bit", chain(dict(token=tid(hi), time=2**63 + 6)), store(enc(hi)), no("token-expired", 0))
    ex4 = mint("ex4", dict(branch=b"*", expiry=2**63))
    l2("l2_expired_time_max", chain(dict(token=tid(ex4), time=NONE - 1)), store(enc(ex4)), no("token-expired", 0))

    # u64 times compared across the 32-bit boundary: a verifier that looked at one half would get these backwards
    lo_max, carry = 2**32 - 1, 2**32
    e1 = mint("carry1", dict(branch=b"*", expiry=lo_max))
    l2("l2_expired_across_32_bit_carry", chain(dict(token=tid(e1), time=carry)), store(enc(e1)),
       no("token-expired", 0))
    e2 = mint("carry2", dict(branch=b"*", expiry=carry))
    l2("l2_ok_expiry_across_32_bit_carry", chain(dict(token=tid(e2), time=lo_max)), store(enc(e2)), ok(1))
    l2("l2_revoked_across_32_bit_carry", chain(dict(token=tid(basic), time=carry)), store(enc(basic)),
       no("token-revoked", 0), revoked(revocation(tid(basic), lo_max)))
    l2("l2_ok_revoked_since_across_32_bit_carry", chain(dict(token=tid(basic), time=lo_max)), store(enc(basic)),
       ok(1), revoked(revocation(tid(basic), carry)))
    l2("l2_revoked_twice_across_32_bit_carry", chain(dict(token=tid(basic), time=carry)), store(enc(basic)),
       no("token-revoked", 0), revoked(revocation(tid(basic), carry), revocation(tid(basic), lo_max)))
    l2("l2_ok_revoked_twice_earliest_is_later", chain(dict(token=tid(basic), time=lo_max)), store(enc(basic)), ok(1),
       revoked(revocation(tid(basic), lo_max + 2), revocation(tid(basic), carry)))

    # ----------------------------------------------------------- principal
    l2("l2_principal_denied", chain(dict(token=tid(bound), principal=P2, time=T)), store(enc(bound)),
       no("principal-denied", 0))
    pa = mint("pa", dict(branch=b"*"), dict(principal=P1, branch=b"*"))
    l2("l2_principal_denied_by_attenuation", chain(dict(token=tid(pa), principal=P2, time=T)), store(enc(pa)),
       no("principal-denied", 0))
    pw = mint("pw", dict(principal=P1, branch=b"*"), dict(branch=b"*"))
    l2("l2_principal_cannot_be_widened", chain(dict(token=tid(pw), principal=P2, time=T)), store(enc(pw)),
       no("principal-denied", 0))
    pz = mint("pz", dict(principal=P1, branch=b"*"))
    l2("l2_principal_zero_commit_is_not_wildcard", chain(dict(token=tid(pz), principal=ZERO, time=T)),
       store(enc(pz)), no("principal-denied", 0))

    # -------------------------------------------------------------- branch
    def denied_branch(name, spec_list, branch):
        t = mint(name, *spec_list)
        l2("l2_branch_denied_" + name, chain(dict(branch=branch, token=tid(t), time=T)), store(enc(t)),
           no("branch-denied", 0))
        return t

    denied_branch("exact", [dict(branch=b"main")], "mainx")
    denied_branch("exact_shorter", [dict(branch=b"main")], "mai")
    denied_branch("prefix", [dict(branch=b"agent-7/*")], "agent-70")
    denied_branch("attenuated", [dict(branch=b"*"), dict(branch=b"agent/*")], "main")
    denied_branch("cannot_be_widened", [dict(branch=b"main"), dict(branch=b"*")], "other")
    denied_branch("empty_pattern", [dict(branch=b"")], "main")
    denied_branch("pattern_longer_than_name", [dict(branch=b"agent-7/*")], "agent-7")

    # -------------------------------------------------------------- effects
    def denied_effect(name, spec_list, effects):
        t = mint(name, *spec_list)
        l2("l2_effect_denied_" + name, chain(dict(token=tid(t), time=T, effects=[effect(k, x) for k, x in effects])),
           store(enc(t)), no("effect-denied", 0))

    denied_effect("kind", [dict(branch=b"*", effects=[(0, b"orders")])], [(1, b"orders")])
    denied_effect("target", [dict(branch=b"*", effects=[(1, b"orders")])], [(1, b"secrets")])
    denied_effect("prefix_is_not_exact", [dict(branch=b"*", effects=[(0, b"orders.*")])], [(0, b"orders")])
    denied_effect("cannot_be_widened", [dict(branch=b"*", effects=[(0, b"orders.total")]),
                                         dict(branch=b"*", effects=[(0, b"*")])], [(0, b"orders.id")])
    denied_effect("one_of_many", [dict(branch=b"*", effects=[(1, b"orders")])],
                  [(0, b"orders.total"), (1, b"orders")])
    # the first effect is permitted and the second is not: every effect is checked, not only the first
    denied_effect("second_effect", [dict(branch=b"*", effects=[(0, b"orders.*")])],
                  [(0, b"orders.total"), (1, b"orders")])
    # an empty pattern matches only the empty value, never everything
    denied_effect("empty_pattern", [dict(branch=b"*", effects=[(0, b"")])], [(0, b"orders")])
    denied_effect("ddl", [dict(branch=b"*", effects=[(0, b"*"), (1, b"*")])], [(2, b"orders")])
    denied_effect("empty_grant", [dict(branch=b"*")], [(4, b"")])
    denied_effect("narrower_in_second_block", [dict(branch=b"*", effects=[(0, b"*"), (1, b"*")]),
                                                dict(branch=b"*", effects=[(0, b"orders.*")])], [(1, b"orders")])
    denied_effect("call_target_prefix", [dict(branch=b"*", effects=[(3, b"fn.refund")])], [(3, b"fn.refund_all")])

    # ------------------------------------------------- the order of the rules
    both = [dict(branch=b"main", effects=[(0, b"a")], expiry=T - 1)]
    t_exp = mint("o", *both)
    t_bad = mint("o", *both, root=FOREIGN)
    c = chain(dict(token=tid(t_bad), time=T, principal=P2, branch="x", effects=[effect(1, b"z")]))
    l2("l2_order_signature_before_revoked", c, store(enc(t_bad)), no("token-bad-signature", 0),
       revoked(revocation(tid(t_bad), 0)))
    c = chain(dict(token=tid(t_exp), time=T, principal=P2, branch="x", effects=[effect(1, b"z")]))
    l2("l2_order_revoked_before_expired", c, store(enc(t_exp)), no("token-revoked", 0),
       revoked(revocation(tid(t_exp), 0)))
    t = mint("o2", dict(principal=P1, branch=b"main", effects=[(0, b"a")], expiry=T - 1))
    c = chain(dict(token=tid(t), time=T, principal=P2, branch="x", effects=[effect(1, b"z")]))
    l2("l2_order_expired_before_principal", c, store(enc(t)), no("token-expired", 0))
    t = mint("o3", dict(principal=P1, branch=b"main", effects=[(0, b"a")]))
    c = chain(dict(token=tid(t), time=T, principal=P2, branch="x", effects=[effect(1, b"z")]))
    l2("l2_order_principal_before_branch", c, store(enc(t)), no("principal-denied", 0))
    t = mint("o4", dict(branch=b"main", effects=[(0, b"a")]))
    c = chain(dict(token=tid(t), time=T, branch="x", effects=[effect(1, b"z")]))
    l2("l2_order_branch_before_effect", c, store(enc(t)), no("branch-denied", 0))
    c = chain(use, dict(use, effects=[effect(1, b"secrets")]), dict(use, token=g.h("nobody")))
    l2("l2_first_failing_commit_wins", c, store(enc(basic)), no("effect-denied", 1))

    # ------------------------------------------------------- store failures
    good = store(enc(basic))
    l2("l2_tokens_bad_magic", one, b"CHODBTK2" + good[8:], no("tokens-bad-magic", -1))
    l2("l2_tokens_empty_file", one, b"", no("tokens-truncated", -1))
    l2("l2_tokens_short_header", one, b"CHODB", no("tokens-truncated", -1))
    l2("l2_tokens_truncated_length", one, good + b"\x00\x00", no("tokens-truncated", 1))
    l2("l2_tokens_truncated_body", one, good[:-1], no("tokens-truncated", 0))
    l2("l2_tokens_length_lies", one, good + u32(0xFFFFFFFF) + b"x", no("tokens-truncated", 1))
    l2("l2_token_zero_blocks", one, store(u32(0)), no("token-bad-encoding", 0))
    l2("l2_token_empty_record", one, store(b""), no("token-bad-encoding", 0))
    l2("l2_token_count_overrun", one, store(u32(2) + basic[0]), no("token-bad-encoding", 0))
    l2("l2_token_count_huge", one, store(u32(0xFFFFFFFF) + basic[0]), no("token-bad-encoding", 0))
    l2("l2_token_trailing_bytes", one, store(enc(basic) + b"\x00"), no("token-bad-encoding", 0))
    l2("l2_token_cut_inside_block", one, store(enc(basic)[:-3]), no("token-bad-encoding", 0))
    unordered = block(payload(branch=b"*", effects=[(1, b"a"), (0, b"a")], raw=True), ROOT_PK, ROOT)
    l2("l2_token_effects_unordered", one, store(enc([unordered])), no("token-bad-encoding", 0))
    dup = block(payload(branch=b"*", effects=[(0, b"a"), (0, b"a")], raw=True), ROOT_PK, ROOT)
    l2("l2_token_effects_duplicate", one, store(enc([dup])), no("token-bad-encoding", 0))
    kind5 = block(payload(branch=b"*", effects=[(5, b"a")], raw=True), ROOT_PK, ROOT)
    l2("l2_token_effect_kind_5", one, store(enc([kind5])), no("token-bad-encoding", 0))
    l2("l2_token_bad_entry_unused_is_still_an_error", one, store(enc(basic), b"\x00\x01"),
       no("token-bad-encoding", 1))

    rgood = revoked(revocation(g.h("x"), 5))
    l2("l2_revoked_bad_magic", one, good, no("revocations-bad-magic", -1), b"CHODBRV2" + rgood[8:])
    l2("l2_revoked_empty_file", one, good, no("revocations-truncated", -1), b"")
    l2("l2_revoked_short_header", one, good, no("revocations-truncated", -1), b"CHODB")
    l2("l2_revoked_truncated_entry", one, good, no("revocations-truncated", 1), rgood + b"x" * 50)
    l2("l2_revoked_truncated_last_byte", one, good, no("revocations-truncated", 0), rgood[:-1])
    l2("l2_revoked_bad_signature", one, good, no("revocation-bad-signature", 1),
       revoked(revocation(g.h("x"), 5), revocation(g.h("y"), 6, signer=FOREIGN)))
    l2("l2_revoked_signature_flipped", one, good, no("revocation-bad-signature", 0),
       revoked(flip(revocation(g.h("x"), 5), 103)))
    l2("l2_revoked_since_flipped", one, good, no("revocation-bad-signature", 0),
       revoked(flip(revocation(g.h("x"), 5), 39)))
    l2("l2_revoked_id_flipped", one, good, no("revocation-bad-signature", 0),
       revoked(flip(revocation(g.h("x"), 5), 0)))
    l2("l2_revoked_signed_without_domain", one, good, no("revocation-bad-signature", 0),
       revoked(g.h("x") + u64(5) + ROOT.sign(g.h("x") + u64(5))))

    # the order of the stores, and of the stores against the commits
    l2("l2_tokens_checked_before_revoked", one, b"CHODBTK2", no("tokens-bad-magic", -1), b"CHODBRV2")
    l2("l2_stores_checked_before_commits", chain(dict(token=g.h("nobody"))), b"CHODBTK2",
       no("tokens-bad-magic", -1))
    l2("l2_revoked_store_checked_before_commits", chain(dict(token=g.h("nobody"))), good,
       no("revocations-bad-magic", -1), b"CHODBRV2")

    # L1 comes first, and the expected id is part of L1
    bad_log = g.log(g.record(one.encs[0]), g.record(one.encs[0]))
    l2("l2_l1_failure_first", one, good, no("duplicate-commit", 1), log_bytes=bad_log)
    l2("l2_l1_failure_before_store_failure", one, b"CHODBTK2", no("duplicate-commit", 1), log_bytes=bad_log)
    l2("l2_expect_missing_is_l1", one, good, no("expected-missing", -1), args_extra="--expect " + "00" * 32)
    l2("l2_expect_present", one, good, ok(1), args_extra="--expect " + g.cid(one.encs[0]).hex())

    # a log with no commits: L2 has nothing to check, and the stores are still read
    l2("l2_ok_empty_log", chain(), good, ok(0, 0))
    l2("l2_empty_log_bad_store", chain(), b"CHODBTK2", no("tokens-bad-magic", -1))

    # the root key that is given is the one trusted
    g.vec("l2_wrong_root_given", g.log(*[g.record(e) for e in one.encs]), no("token-bad-signature", 0),
          "--root " + FOREIGN_PK.hex() + " --tokens {dir}/l2_wrong_root_given.tokens", {".tokens": good})
    g.vec("l2_root_not_a_point", g.log(*[g.record(e) for e in one.encs]), no("token-bad-signature", 0),
          "--root " + ("ff" * 32) + " --tokens {dir}/l2_root_not_a_point.tokens", {".tokens": good})
    g.vec("l2_root_not_a_point_revocations", g.log(*[g.record(e) for e in one.encs]),
          no("revocation-bad-signature", 0),
          "--root " + ("ff" * 32) + " --tokens {dir}/l2_root_not_a_point_revocations.tokens --revoked "
          "{dir}/l2_root_not_a_point_revocations.revoked", {".tokens": good, ".revoked": rgood})
