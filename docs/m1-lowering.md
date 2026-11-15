# M1, P1: from SQL to the IR, and what is sent upstream

> **Status: design, written before the code.** Companion to [`m1-proxy.md`](m1-proxy.md) (D4, section 7). The decisions here
> are not yet measured against a parser; the gate in section 6 is how they get measured, and a claim that turns out false is
> corrected in place.

P1 gives the proxy eyes: it reads each `Query` message, lowers its statements to the IR of [`spec/ir.md`](spec/ir.md),
infers their effects, checks them against the token, and only then lets anything reach PostgreSQL.

## 1. The decision everything else follows from: forward what was checked

A proxy that **parses the client's SQL and then forwards the client's bytes** is only as sound as its parser is equal to
PostgreSQL's. Any difference is an authority bypass: the proxy checks the statement it understood, PostgreSQL runs the one it
parsed. This class of bug is old and well known (comments, quoting, `E''` strings, `standard_conforming_strings`, dollar
quoting, `;` inside a string, nested comments, `U&''` escapes, unicode normalisation of identifiers), and a hand-written parser
for a language as large as SQL will have some of it.

**So the proxy never forwards the client's bytes.** It forwards **SQL rendered from the same parse it checked**:

```
client text ──lex/parse──► AST ──lower──► IR ──infer──► effects ──check(token)──► allowed?
                            │
                            └──render──► canonical SQL ──► PostgreSQL
```

What executes is derived from what was checked, in a grammar so small and so regular (every identifier double-quoted, every
string a plain `'...'` literal, every compound expression fully parenthesised, `CAST(x AS t)` for casts) that the proxy's
reading and PostgreSQL's cannot differ about *which tables and columns appear*. A parser mistake can still make the proxy
**run something other than what the client meant** (a precedence bug turns `a OR b AND c` into the wrong thing), but it
cannot make it run something other than what it **checked**, which is the property the log and the tokens rest on.

*Chosen over* forwarding the original and trusting the parser (the bypass above), and over a differential check on every
statement against PostgreSQL's own parse (PostgreSQL does not expose its parse tree to a client, and `EXPLAIN` is not a
substitute at run time). *Costs:* the renderer must be exact (quoting rules, number forms, type names), statements are not
byte-identical upstream (so server-side logs show the canonical text, not the client's), and **anything the renderer cannot
reproduce faithfully is refused**, not approximated.

The renderer is what makes the gate of section 6 possible: the original and its rendering can both be run, and compared.

## 2. The accepted SQL: a subset, stated, with every refusal tagged

Accepted, to the extent IR v2 can say it:

- `SELECT [DISTINCT] items FROM t [, t] [[LEFT|INNER] JOIN t ON cond]... [WHERE] [GROUP BY] [HAVING] [ORDER BY] [LIMIT] [OFFSET]`
- `INSERT INTO t [(cols)] VALUES (...), (...)`; `UPDATE t SET c = e, ... [WHERE]`; `DELETE FROM t [WHERE]`
- `CREATE TABLE t (...)`, `DROP TABLE t`, `ALTER TABLE t ADD COLUMN ...`, `CREATE INDEX`, `DROP INDEX`: **a small, closed grammar**
  for each (column name, a type from a short list, `NOT NULL`, `PRIMARY KEY`, `DEFAULT literal`), because the renderer must
  reproduce a DDL statement completely and IR's `Ddl` carries only the table.
- Expressions: literals (integers, decimals, single-quoted strings, `TRUE`/`FALSE`/`NULL`), column references (`c`, `t.c`),
  `+ - * / % ||`, comparisons, `AND OR NOT`, `IS [NOT] NULL`, `[NOT] IN (list)`, `[NOT] LIKE`/`ILIKE`, `BETWEEN`, `CASE`,
  `CAST(x AS type)` and `x::type`, function calls including `count(*)`, `now()`.
- Transaction control the proxy tracks itself (`BEGIN`, `COMMIT`, `ROLLBACK`) is P2's.

Refused, **before anything reaches PostgreSQL**, with `0A000` and a rule tag in the message, one tag per class so a log or a
test can count them: `unsupported-sql: subquery`, `cte`, `set-operation`, `window`, `returning`, `on-conflict`,
`insert-select`, `copy`, `temp-table`, `listen`, `set`, `catalog` (a reference to `pg_catalog` or `information_schema`),
`dollar-quote`, `escape-string`, `unicode-escape`, `nested-too-deep`, `nondeterministic` (`random()`, `clock_timestamp()`,
`nextval`, `gen_random_uuid()`), `unknown-construct`. And `42703` `unknown-column` / `42702` `ambiguous-column` /
`42P01` `unknown-table` where the schema snapshot shows PostgreSQL would refuse too; refusing here is the same answer sooner.

Anything the lexer meets that it does not fully understand is `unknown-construct`: **the default is refusal.** There is no
"pass it through" path.

## 3. Lexing, and what makes it safe to be small

- **Exactly PostgreSQL's rules for what is accepted, and refusal for what is not.** Whitespace; `--` comments; **nested**
  `/* */` comments (PostgreSQL nests them: a non-nesting lexer reads `/* /* */ */` differently); identifiers (unquoted fold to
  lower case, ASCII letters, digits, `_`, `$` not first; `"quoted"` with `""` for a quote); `'string'` with `''` for a quote and
  **no backslash escapes**, which is only true if `standard_conforming_strings` is on, so the proxy sets it **in the upstream
  startup** (it is a per-session setting a client could `SET`, and `SET` is refused); numbers; operators; punctuation.
- **Refused outright**, because their lexing depends on server state or on rarely-correct code: `E'...'`, `U&'...'`,
  `$tag$...$tag$`, `B'..'`/`X'..'`, non-ASCII identifiers (normalisation rules), a NUL anywhere, `;` anywhere but between
  statements, a comment-opener inside a token.
- **Statements are split by the lexer**, never by searching for `;` in the text: a `;` in a string or comment is not a
  separator. A `Query` message with several statements is lowered as a unit (`m1-proxy.md` D6).
- **Lengths are bounded** (statement bytes, tokens, nesting depth) with the same style of refusal; nothing recurses on input.
  Expressions are parsed by operator-precedence climbing with an explicit stack and an arena of nodes, and emitted in the IR's
  prefix order with a second explicit stack, so a deep expression is a refusal, not a stack overflow.

### 3.1 Measured, and what the differential found

- **PostgreSQL truncates an identifier longer than 63 bytes with only a `NOTICE`**, and two different long names that share a
  63-byte prefix become one: `create table t(<70 a's>, <63 a's>bbbbbbb)` fails with `column "<63 a's>" specified more than
  once`. The lexer refuses an identifier over 63 bytes (`identifier-too-long`), quoted or not, counting a doubled quote as one.
- **PostgreSQL ends an operator by a rule that is easy to get wrong**: a multi-character operator may end in `+` or `-` only if
  it also contains one of `~ ! @ # % ^ & | ` ?`; otherwise the trailing signs are trimmed and lexed on (`1<-2` is `1 < -2`).
  Checked from PostgreSQL's own error messages (`select null::xml OP null::xml` fails naming the operator token it read) over
  3,000 random operator strings (2,809 that PostgreSQL reads as one operator, 191 that it trims into several): 0 disagreements. `!=` is rewritten to `<>` by PostgreSQL's
  scanner and `=>` is its own token; both are accounted for, not hidden.
- **The statement count is compared with PostgreSQL's.** `tests/lex_diff.py` builds SQL from a grammar of valid statement lists
  with hostile lexical content (`;` in strings, comments, quoted identifiers; nested comments; backslashes; doubled quotes) and
  from a fuzzer over an alphabet of dangerous fragments, sends each to a real server, and counts the `CommandComplete`
  messages. In a run of 12,000 strings, 6,247 were comparable (the lexer accepted, PostgreSQL ran it without error), 4,505 with
  two or more statements: **0 disagreements**. The lexer refused 4,882 (the safe direction) and PostgreSQL rejected 871.
- **Its teeth, shown:** a lexer whose block comments do not nest is caught at once (20 disagreements in 3,000 strings). A lexer
  that lets a doubled quote end a string is **not** caught by the statement count (quote parity is preserved, so boundaries do
  not move); the unit cases kill it. The two checks cover different things, and the claim is made for each separately.
- The first version of the differential reported 145 "disagreements" that were its own generator's bad fragment, and then 15 that
  were its own misreading of what a successful `select 1 - 2` shows. Both were caught by checks in the test itself.

### 3.2 The expression parser, and what the differential found

`src/parse.cho` reads the expression subset of section 2 and renders it back with **every operator parenthesised, every name
folded and double-quoted, and keywords in lower case**: that rendering, not the client's text, is what the proxy will send. The
parser is operator-precedence climbing with an explicit operator stack (brackets of calls, `IN` lists, `CASE` and `CAST` sit on
it as frames) and a value stack; the tree is built into caller arrays; the renderer walks it with a third stack. Nothing
recurses; every stack and arena has a limit that is a tagged refusal (`nested-too-deep`, `too-big`).

- **The check is PostgreSQL's own plan.** `tests/parse_diff.py` sends `EXPLAIN (VERBOSE, COSTS OFF) SELECT <expr> FROM t` for the
  original and for the rendering to a real server. Its `Output:` line is the expression as PostgreSQL parsed it, parenthesised,
  so a precedence or associativity error in this parser shows as a different line. Over 12,000 cases (three seeds; a typed grammar
  written with and without redundant parentheses, with random spacing, case and comments; chains of operands and operators with
  no parentheses at all; and a fuzzer over a token vocabulary): **0 disagreements**. About 2,000 of 4,000 cases per seed are valid
  expressions that plan identically; about 500 more are expressions that PostgreSQL refuses for a type error, both before and after
  rendering, with the same SQLSTATE.
- **It also checks the other direction**: an expression the parser accepts must not be a *syntax* error (`42601`) to PostgreSQL,
  or the proxy would run a statement nobody could have run. None is.
- **What the differential found (a real bug).** `a IN (1) - b` was parsed as `a IN ((1) - b)`: the `IN` operator waited for its
  right operand like any infix operator, so the `-` that followed bound to the list. PostgreSQL reads `(a IN (1)) - b`: a list
  is closed on the right. The generator did not intend this case; a chain of random operators did. It is now reduced when its
  `)` arrives, a hand case pins it, and the mutant that restores the wait is killed.
- **A second bug, found by a limit case.** The renderer wrote at index -1 when the output buffer was already full, a trap: caught
  by the case "output of 3 bytes for `1 + 2`", not by anything that ran the proxy's way.
- **A deliberate narrowing.** `a BETWEEN 1 = 1 AND 2` is valid in PostgreSQL (the bound is `1 = 1`) and refused here: the
  `AND` that closes a `BETWEEN` is recognised only after operators tighter than `BETWEEN` have been reduced. A refusal is the safe
  direction, and the case is in the corpus so a change of mind is visible. The mutant that would accept it behaves like
  PostgreSQL, so it is not listed as a mutant to kill.
- **Names.** PostgreSQL's reserved, type-or-function-name and column-name keywords (156 words, from `pg_get_keywords()` on 16)
  are refused as bare names, so `user` is not quietly rendered as `"user"` and run, where PostgreSQL would have refused it.
  Types come from a closed list (`smallint integer bigint text boolean numeric varchar date timestamp timestamptz real`, with `int`,
  `bool` and `decimal` as spellings); anything else is `unknown-type`, since a type can be user-defined.

### 3.3 SELECT

`src/stmt.cho` reads a `SELECT` over the expression parser and the same arrays, and `parse.render` renders it
(`select distinct "a" as "x", ... from "t" as "u" inner join "v" on (...) where ... group by ... having ... order by "a" desc
limit 5 offset 2`). Joins are left-deep and rendered without parentheses, which is exact, and re-parses to the same tree.

- **Checked the same way**: `tests/stmt_diff.py` compares PostgreSQL's `EXPLAIN (VERBOSE, COSTS OFF)` for the original and for
  the rendering over a grammar of statements (one to three tables, the joins read, every clause present or absent, expressions
  from the generator of `tests/pgdiff.py` inside) and a fuzzer over clause words: 12,000 cases over three seeds, **0
  disagreements**; about 1,650 per 4,000 are valid statements that plan identically, about 1,000 more are errors with one
  SQLSTATE on both sides (ambiguous columns, type errors). Its teeth: seven deliberate breakages (a left join rendered as inner,
  `where` as `having`, `asc` and `desc` swapped, DISTINCT dropped, joins' operands swapped, LIMIT and OFFSET exchanged) are each
  caught (54 to 687 disagreements in 2,500 cases); dropping an alias is caught only twice, because aliases hardly show in a plan,
  and the hand cases are what pin them.
- **What the differential found**: PostgreSQL refuses `select nulls first` (it reads `nulls` followed by `first` as one
  lookahead token, never a name), and a bare select-list label may not be one of eleven non-reserved words (`day hour minute month
  second year filter over varying within without`), which continue an expression instead (`1 day`). Both were accepted at first
  and are refused now; the word list is from `pg_get_keywords()` (`barelabel` false). A first failure of the check itself: it
  counted `42601` as a syntax error, but PostgreSQL also uses it for "non-integer constant in ORDER BY"; the test now looks at the
  message.
- **Another**: `GROUP BY ROLLUP (a)` and `CUBE (a)` are grouping sets in PostgreSQL, and were parsed as calls; refused.
- **Refused with a tag**: set operations (`set-operation`), `RIGHT/FULL/CROSS/NATURAL` joins and `USING` (`unsupported-join`),
  schema-qualified or function tables and `(t)` (`unknown-construct`), sub-selects (`subquery`), `NULLS FIRST/LAST`, `OFFSET`
  before `LIMIT`, `FOR UPDATE`, `FETCH`, `WINDOW`, `DISTINCT ON`; a statement that is not a `SELECT` is
  `unsupported-statement` (P1b-2b).

## 4. Lowering

- **Aliases** (`FROM orders o`) are resolved to base tables: the IR names `orders`, never `o`.
- **Unqualified columns** are resolved against the **schema snapshot** (`m1-proxy.md` D5): one table has the column, or the
  statement is `ambiguous-column` / `unknown-column`. `SELECT *` and `t.*` are expanded to the snapshot's columns, in order;
  the IR and the rendering both carry the explicit list, so what runs is what the snapshot said even if a column is added
  between the snapshot and the execution (a DDL through the proxy invalidates the snapshot; one that bypasses the proxy is out of
  scope, as `m1-proxy.md` section 6 says).
- **Lowering that the IR cannot express is refused**, not approximated; lowering never *adds* an effect the SQL does not have
  nor drops one it has. The IR's effect rules (`ir.md` section 3, 6) are the whole of the inference: there is no second
  implementation of "which columns does this statement read" in the lowering.
- **Function names are recorded as written** (`call lower`), not resolved through `search_path`. A user function that shadows a
  builtin is a known gap (`m1-proxy.md` section 8); qualifying calls is future work.

## 5. Where it goes in the proxy

A new `Query` branch in the message loop (P0's `step` forwards untouched today): the whole message is lexed and lowered; if any
statement is refused the **whole message** is refused (PostgreSQL would run them as one implicit transaction, so a partial run
would be a different transaction); otherwise the **rendered** statements are sent upstream. Everything that is not `Query`,
`Terminate`, `Sync`/`Flush`-free simple-protocol traffic is refused as the extended protocol (`m1-proxy.md` D3). Responses
flow back untouched. The token is checked against the inferred effects before the first byte is sent upstream, so **a refused
statement never appears in PostgreSQL's log** (measured at the gate).

## 6. The gate, and why it can fail

A corpus `tests/sql/corpus.sql` of statements, each annotated by hand with: accepted or the refusal tag, and (if accepted) the
effect set it must infer. It is run three ways:

1. **Lowering** (`cancho test`, no server): lex, parse and lower each statement; the IR's id and inferred effects must equal the
   annotation, and a refused one must carry exactly its tag. Mutants of the lexer, parser and lowering must each be caught.
2. **Differential, accepted statements** (needs PostgreSQL): for each, run the **original** directly and the **rendering**
   through the proxy; the result sets (and command tags) must be identical. For a `SELECT`/DML, additionally
   `EXPLAIN (VERBOSE, COSTS OFF)` of the original and of the rendering must be identical, which is what catches a precedence or
   associativity error in the parser: the renderer parenthesises everything, so a wrong parse shows as a different plan.
3. **Refusals** (needs PostgreSQL with `log_statement=all`): after every refused statement the server's log must contain
   nothing for it.

Plus **fuzzing the lexer** against the property that matters: for generated strings that mix quotes, comments, semicolons and
the refused forms, either the proxy refuses or the statement it would send, split the way PostgreSQL splits it (checked by sending
it to PostgreSQL and counting the commands it reports), has the same number of statements as the proxy found.

## 7. Slices

| Slice | Delivers | Gate |
|---|---|---|
| IR v2 | `ir.md` section 6, three verifiers | built; 428 vectors agree |
| **P1a** | the lexer and statement splitter, with the refusals of section 3 | **built** (`src/lex.cho`): 167 hand-written cases (54 refusals), 35 mutants killed, and a differential against PostgreSQL itself (section 3.1) |
| **P1b-1** | **the expression parser and the renderer** (`src/parse.cho`): precedence climbing over explicit stacks, a tree in caller arrays, and the parenthesised rendering | **built**: 265 hand-written cases (123 refusals), each accepted one a fixed point of parse-then-render; PostgreSQL's plan for the original equal to its plan for the rendering over 12,000 generated expressions (section 3.2); 56 mutants killed |
| **P1b-2a** | **SELECT** (`src/stmt.cho`): items and aliases, `FROM` with comma lists and `[INNER|LEFT [OUTER]] JOIN ... ON`, `WHERE`, `GROUP BY`, `HAVING`, `ORDER BY [ASC|DESC]`, `LIMIT`, `OFFSET` | **built**: 146 hand-written cases (83 refusals, each accepted one a fixed point), 34 mutants killed, PostgreSQL's plans for the original and the rendering equal over 12,000 generated statements (section 3.3) |
| **P1b-2b** | INSERT, UPDATE, DELETE and the closed DDL | the same checks |
| **P1c** | lowering, the schema snapshot, the effect check | lowering gate (1); refusals (3) |
| **P1d** | the `Query` branch in the proxy | end to end with psql: differential (2) and the server log (3) |

## 8. Risks

- **The renderer is the new trusted component.** It must be exact; its tests are the EXPLAIN differential and the fixed-point
  property, and a mistake there is a different statement run, not a bypass (section 1).
- **A SQL parser is the largest code in the project so far.** The corpus measures progress; if it proves far larger than the
  rest, the answer is a smaller subset, not a looser check (`m1-proxy.md` section 8).
- **Type names and DDL** need a closed list; the first list will be too short for real use, and extending it is a decision each
  time (a type can be a user-defined type with side effects).
- **`search_path` and unqualified names** (tables as well as functions): the IR records names as written, and PostgreSQL
  resolves them by `search_path`, which a client could set. `SET` is refused and the upstream session's `search_path` is fixed
  in the startup, so within M1 the name means one thing; a deployment with several schemas needs qualified names in the IR.
