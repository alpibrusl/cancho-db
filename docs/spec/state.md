# Cancho DB: facts, `changes` and `state` (v1)

This defines what the commit's two hash fields, `changes` and `state` ([`commit.md`](commit.md) section 2, fields 12 and 13), contain. Until M2 a server
wrote 32 zero bytes in both. The commit format itself does not change (`version` stays 1): a verifier that checks L1 and L2 reads these fields as opaque
hashes, exactly as before. What this document adds is how a **producer** computes them and how an **L3 verifier** checks them. The design is
[`../m2-branches.md`](../m2-branches.md) (D6 and D7); the open questions it lists (Q1: what `state` is) are answered here as that document recommends,
and a different answer is a new `version`, not an edit of this one.

## 1. Notation

As in `commit.md`: integers are big-endian and fixed width; `Hash` is 32 bytes (SHA-256); `bytes16` is a `u16` length and that many bytes, `bytes32` a
`u32` length and that many bytes; neither is interpreted. `||` is concatenation. Every value has exactly one byte representation.

## 2. A fact

A fact is one row of one table that a commit changed, **net**: if a transaction changed the same row more than once, the fact is from the row as the
commit began to the row as it ended (an insert then an update is an insert of the last image; an insert then a delete is no fact; an update then a
delete is a delete of the first image). Producing the net fact is the producer's duty; a verifier checks the encoding and the order, and L3 replay
(section 5) checks the facts against the data.

| Field | Encoding | Constraint |
|---|---|---|
| `kind` | `u8` | `0` insert, `1` update, `2` delete; any other value is `fact-kind` |
| `table` | `bytes16` | length 1 to 255, else `fact-table` |
| `pk` | `bytes32` | length 1 to 65535, else `fact-pk`; the table's primary key in a canonical encoding the producer defines (M2b) |
| `old` | `Hash` or absent | the hash of the row image before: absent for an insert, present otherwise |
| `new` | `Hash` or absent | the hash of the row image after: absent for a delete, present otherwise |

A violation of the "absent / present" column, a present hash that is not 32 bytes, or a present hash of 32 zero bytes, is `fact-image`. The **encoding** of a fact is
`table || pk || kind || old || new` where an absent hash is written as 32 zero bytes (the zero hash is therefore never a real image, which is why it is refused above).

The **leaf** of a fact is

```
leaf = SHA-256( "cancho-db/fact/v1" || 0x00 || encoding(fact) )
```

(`cancho-db/fact/v1` is 17 ASCII bytes, then one `0x00`.) How a row image is hashed is the producer's definition and is not part of this version; this document
fixes only that a hash stands for one image.

## 3. `changes`

The facts of a commit MUST be **strictly ascending** by `(table, pk)`, each compared as an unsigned lexicographic byte string with a prefix sorting first, `table` before `pk`;
an equal or smaller successor is `facts-unordered` (so a commit has at most one fact for a row). With the leaves `l_0 ... l_{n-1}` in that order:

```
node(a, b) = SHA-256( "cancho-db/node/v1" || 0x00 || a || b )
root       = the one hash left by repeating: pair neighbours from the left into node(a, b); an unpaired last hash is carried up unchanged
changes    = SHA-256( "cancho-db/changes/v1" || 0x00 || u32(n) || root )     // root is 32 zero bytes when n = 0
```

`n` is in the hash so that a list of facts and the same root reached through a different count are different; the three prefixes keep a leaf, a node and a root from being
confused for each other. A commit that changed no row (a read) has **n = 0**, and its `changes` is a single fixed value (section 6).

## 4. `state`

```
state(commit) = SHA-256( "cancho-db/state/v1" || 0x00 || u8(p) || state(parent_0) || ... || state(parent_{p-1}) || changes(commit) )
```

where `p` is the number of the commit's `parents` (0 for the root of a log, 1 for a normal commit or a fork point, 2 for a merge) and `state(parent_i)` is the `state` field of
the parent commit, in the order the commit lists them. `state` is therefore a function of the **history of changes**: two commits with the same `state` have the same ancestry of
changes. **It is not a digest of the table contents**, and a verifier MUST NOT describe it as one: that the tables hold what the facts say is what L3 replay checks (section 5), and a
content-addressed root is left to the signed snapshots of M3.

## 5. What a verifier checks

* **L1 and L2** ignore the two fields (they are opaque hashes) and are unchanged.
* **L3a, delta replay** (M2f): for each commit, the stored facts must be well formed (section 2) and ordered (section 3); `changes` must equal section 3 over them; `state` must equal section 4 over the
  parents' states and that `changes`; and applying the facts in log order to a scratch database must leave tables whose row images hash to the `new` hashes. Every `changes` or `state` that is
  not what the facts give is `changes-mismatch` or `state-mismatch`, in that order of checking.

## 6. Golden values

The empty `changes` (n = 0) is `SHA-256("cancho-db/changes/v1" || 0x00 || 00 00 00 00 || 32 zero bytes)`, which is

```
changes(∅) = c068815f658b62c1cc6ebe55e18dc1306c029787ffdef0076eaf1ec5467af9ea   (checked against `openssl dgst` by tests/state_check.py)
```

`tests/state_cases.txt` holds the cases, one per line as `COMMAND => RESULT`, written by `tools/state.py --vectors` and never edited by hand. The two commands:

```
C FACT FACT ...        FACT = kind:table:pk:old:new, every field hex, an absent hash written -;     RESULT: ok HEX(changes) | error RULE
S P PARENT... CHANGES  P parent states then the changes, all hex;                                      RESULT: ok HEX(state)
```
