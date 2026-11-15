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

- **INSERT, UPDATE, DELETE** are read the same way: `INSERT INTO t [AS a] [(c, ...)] VALUES (e, ...), ...`, `UPDATE t [[AS] a] SET c = e, ... [WHERE e]`,
  `DELETE FROM t [[AS] a] [WHERE e]`. `EXPLAIN` plans them without running them, so the same differential applies (30% of the
  generated statements are DML: random column subsets, typed values, one to three rows, aliases). Found: PostgreSQL requires `AS` for an
  INSERT alias (`insert into t x ...` is a syntax error there, and was accepted here), and `SET` must never be taken as the alias in
  `UPDATE t SET`. Refused with their own tags: `insert-select`, `returning`, `on-conflict`; `DEFAULT`, `DEFAULT VALUES`, `UPDATE ... FROM`,
  `DELETE ... USING`, `ONLY`, row-valued `SET (a, b) = ...` and schema-qualified names fall out as `reserved-word`, `syntax` or
  `unknown-construct`.

### 3.4 The closed DDL

DDL has no plan, so the check is behavioural: `tests/ddl_diff.py` runs the original and the rendering, each in a transaction rolled
back after the same prelude, and compares what is left in the catalog (every column's name, type with modifiers, NOT NULL and
default expression; every constraint through `pg_get_constraintdef`; every index through `pg_indexes.indexdef`), or the SQLSTATE
if both fail. 5,000 cases over two seeds (a grammar of column definitions with the constraints in random order, plus a fuzzer
over DDL words): **0 disagreements**, about 1,500 of them statements that run and leave an identical catalog. Its teeth: a
rendering that loses `PRIMARY KEY`, a unique index written plain, a lost numeric scale, and a swapped NOT NULL bit are caught
(13 to 48 disagreements in 1,500 cases).

- **The grammar is closed**: `CREATE TABLE t (name type [NOT NULL] [PRIMARY KEY] [UNIQUE] [DEFAULT literal], ...)`, the
  constraints in any order and each once, written back in one order; the type from the closed list of section 3.2; a default
  only a number (optionally negated), a string, `NULL`, `TRUE` or `FALSE`. No table constraints, `REFERENCES`, `CHECK`,
  identity columns, `IF [NOT] EXISTS`, `CASCADE`, `TEMP`, partial, expression or `USING` indexes, and no schema-qualified names:
  each is refused (`syntax`, `reserved-word`, `unknown-construct`, `unsupported-statement`), because the IR's `Ddl` carries only
  the table and the renderer must reproduce what it accepts completely.
- **A side effect on the expression parser**: `x NOT NULL` is not an expression, so a `NOT` that is not `NOT IN/LIKE/ILIKE/BETWEEN`
  now ends an expression (the caller sees the leftover token and refuses) instead of being a parse error there.

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

### 4.1 P1c, decided before it is built

The parser's tree (section 3) is lowered to IR v2 bytes (`ir.md` section 6) by `src/lower.cho`, given a **schema snapshot**. What
follows is written before the code; a claim that proves false is corrected here.

- **The snapshot** is plain text, one table a line, lower-case names: `orders: id customer total`, and for DROP INDEX one line
  `index i1 on orders`. The proxy will build it from `information_schema` (P1d); the tests write it by hand. A statement naming a
  table the snapshot lacks is `unknown-table` (`42P01`), a column it lacks `unknown-column` (`42703`), a bare column two scope
  tables have `ambiguous-column` (`42702`): PostgreSQL would refuse all three, so this is the same answer sooner and never a
  refusal of something valid. `CREATE TABLE` of a table that exists is left to PostgreSQL.
- **Scope**: the tables of a statement's `FROM` (or its single target), by alias if it has one; a name qualified by a table that
  is not in scope is `unknown-table`. Names fold as the renderer folds them (unquoted to lower case, quoted as written).
- **`*` and `t.*`** become the snapshot's columns in order, as `Col` items; a `SELECT` with no `FROM` has no scope.
- **`ORDER BY`** takes an output name first, as PostgreSQL does: a bare name equal to a select item's alias is that item's
  expression (lowered again, so its reads are recorded once more, harmlessly); any other name is an input column. `GROUP BY` and
  `HAVING` read input columns only (an output alias there is `unknown-column`: refused where PostgreSQL would accept, the safe
  direction). An ordinal (`ORDER BY 2`) is a constant.
- **Constants**: an integer literal that fits an `i64` is `Const int`; everything else (decimals, exponents, strings, `TRUE`,
  `FALSE`) is `Const bytes` of its value: a string's content with `''` undoubled, a number's text, `true` or `false`. The IR's id is
  therefore not a function of the rendering; it never needs to be (lowering is not specified, `ir.md` section 5).
- **Operators**: `or and = <> < <= > >= + - * / % || like ilike` and their `NOT` forms map to the `Op` codes of `ir.md` section 6;
  `x BETWEEN a AND b` is `(x >= a) AND (x <= b)`, `NOT BETWEEN` the negation of that, a simple `CASE x WHEN a THEN ...` has
  `x = a` conditions: all write `x` more than once, which adds no effect (`ir.md` section 6). `!=` is `<>` (the renderer already
  says so).
- **Calls**: `count(*)` is `Call count (Star)`; any other call is `Call name args` with the name as written, lower-cased. **`now()`
  is `Nondet now`** (recorded in the commit's `nondet` list, `m1-proxy.md` D8). `random`, `clock_timestamp`, `nextval`,
  `gen_random_uuid`, `setseed`, `txid_current` and `timeofday` are `nondeterministic` refusals, never a `Call`: their value would
  not be in the log.
- **Statements**: `Select2` for every `SELECT` (the v1 `Select` is never written); `Insert` with the column list (the snapshot's
  columns if none was given, a row of the wrong length refused as `syntax`); `Update`, `Delete`, and `Ddl` with the kind of
  `ir.md` section 2 and the table (for `DROP INDEX`, the table the snapshot says the index is on).
- **No second inference.** The effect check calls `ir.infer` on the lowered bytes, the code the verifier already runs; the
  lowering has no rule of its own for which columns a statement reads. The gate (section 6, 1) therefore compares **two hand
  writings**: the IR bytes a case expects, built by an encoder in the test generator, and the effect set it expects, each written
  from the statement by hand; the code under test must reproduce the first byte for byte and `ir.infer` must give the second.
- **Slices**: P1c-1 the lowering of expressions and the four DML statements; P1c-2 DDL, the refusals by name, and the effect
  check against a token; the plan differential cannot see the IR, so what covers the lowering against PostgreSQL is that every
  name it resolves was resolved the way the server's own error messages say it would be (an unknown or ambiguous column is
  compared with PostgreSQL's `42703` and `42702` in the same differential run).

### 4.2 What the lowering gate found

- **The two hand writings agree with the code, and the verifier is the oracle for the second.** For each case the test builds the
  IR from the statement by hand with its own encoder, and writes the effect set by hand from `ir.md` section 3. The bytes
  must be identical to what `lowercheck` prints; then the real verifier (`build/verify --stmts`) is given a commit that records
  that hand-written set over the lowered statement and must say `ok ... level=2+ir`, and the same commit with one effect removed
  and with one added must be refused `effects-mismatch`: the check can fail, so passing it means something.
- **Bugs this found in the first run (both mine)**: a call with arguments visited its first argument twice (an off-by-one in the walk's
  steps), and `DROP INDEX` was written with the kind of `CREATE TABLE`.
- **Name resolution against PostgreSQL** (`tests/lower_diff.py`): the generator of `tests/stmt_diff.py`'s statements, a snapshot
  written to match the temporary tables, and PostgreSQL's own `42P01`, `42703` and `42702`. A lowering that refuses a name
  must not be refused for a different reason by PostgreSQL or accepted by it, and one that accepts must not draw a name error. 20,000
  statements, 0 disagreements after one fix: `ORDER BY` takes an **output name first** and refuses one that two **different**
  outputs have (`SELECT (a)::int::boolean, t.* ... ORDER BY a` is ambiguous in PostgreSQL, and was lowered as `a` the
  input column); two plain references to the same column (`SELECT t.*, * ... ORDER BY b`) are not different, and were refused
  at first for it. Both are cases the generator reached by chance.
- **Limits, stated**: a `SELECT` with no `FROM` (`select 1`, `select now()`) is refused `cannot-lower` because the IR requires a table;
  an expression's implicit output name is only known for column references and casts of them, so `ORDER BY` of any other
  implicit name (`ORDER BY count`) is looked up as an input column and refused if it is none (the safe direction); a scope
  of more than 10 tables or 16 `FROM` entries is refused. The lowering does not type-check, and an `ON` condition may name
  a table that appears later in the `FROM`, which PostgreSQL refuses: the IR then over-reports, never under-reports.

## 5. Where it goes in the proxy

A new `Query` branch in the message loop (P0's `step` forwards untouched today): the whole message is lexed and lowered; if any
statement is refused the **whole message** is refused (PostgreSQL would run them as one implicit transaction, so a partial run
would be a different transaction); otherwise the **rendered** statements are sent upstream. Everything that is not `Query`,
`Terminate`, `Sync`/`Flush`-free simple-protocol traffic is refused as the extended protocol (`m1-proxy.md` D3). Responses
flow back untouched. The token is checked against the inferred effects before the first byte is sent upstream, so **a refused
statement never appears in PostgreSQL's log** (measured at the gate).

### 5.1 The guard

`guard.check` is the whole decision in one function, with no sockets: the text of one `Query` message, the schema snapshot, and
the token in; the text to send upstream, or a refusal, out. Each statement is parsed, lowered, and its effects inferred by
`ir.infer` and checked one by one with `token.effect_denied`, the functions the verifier runs on the log. **If any statement is
refused the whole message is**, and what is sent is only ever the renderings, joined with `; `: a comment, an unusual spelling or
a trailing statement hidden in a string cannot reach PostgreSQL, because none of the client's bytes does.

- A refusal is answered with a SQLSTATE: PostgreSQL's own (`42P01`, `42703`, `42702`) for a name it would refuse, `42501`
  (insufficient privilege) for an effect the token does not allow, `0A000` for everything outside the subset, with the tag in the
  message.
- **Checked by hand-written verdicts** (`tests/guard_check.py`, tokens minted by the test's own code): every place a column can
  be read (`SELECT`, `WHERE`, `ORDER BY`, `GROUP BY`, `HAVING`, `ON`, `LIMIT`, `DISTINCT`'s items, `*`), writes, DDL, calls,
  `now()`; a second statement that is denied refuses the first's message too; a statement hidden in a comment or a string is not a
  statement; refusals of the lexer, the parser and the lowering with the right SQLSTATE. 13 mutants (an effect not checked, only
  the first checked, the effect's encoding off by one, the `; ` lost, v1 inference) are each caught.
- Transaction control (`BEGIN`, `COMMIT`, `ROLLBACK`) is `unsupported-statement` until P2, which tracks it itself.

### 5.2 P1d-2, decided before it is built

How the guard gets into the event loop (`proxy/proxy.cho`), written before the code:

- **Framing, client to server only.** A paired client's bytes are no longer copied in chunks: they are collected per connection
  until a whole frontend message is there (a type byte and a 4-byte length). The server's answers still flow back untouched.
  A message longer than 64 KiB is refused and the connection closed (a bound, like every other in the proxy).
- **What each message does.** `Q` (simple query): the guard (section 5.1); on success the proxy sends a **new** `Q` whose text is the
  guard's rendering (the client's message is dropped); on refusal it answers the client itself, with an `ErrorResponse`
  (severity `ERROR`, the guard's SQLSTATE, the tag in the message) and `ReadyForQuery('I')`, and sends nothing upstream. `X`
  (terminate): forwarded. Everything else (`P`, `B`, `E`, `D`, `S`, `H`, `F`, `C` and the copy messages, which are the extended
  protocol and `COPY`) is refused the same way with `0A000` `unsupported-sql: extended-protocol`, the connection staying
  open: `psql` and every driver in simple mode use only `Q`. A message type that is not in the protocol closes the connection.
- **The token** the client logged in with is kept for its connection (the login already decodes it) and is what the guard
  checks; it is dropped with the connection.
- **The schema snapshot is read fresh for each `Q`**, from the catalog, over one dedicated upstream connection the proxy keeps
  for the purpose (`information_schema.columns` and `pg_indexes` for the public schema, in one simple query, bounded by the
  same `login_ms()` wait as the login). Fresh means a DDL that went through the proxy, or around it, is visible to the next
  statement, with no invalidation to get wrong; the price is one local round trip a query, stated as P1d's cost and measured at the
  gate. If the catalog connection fails the query is refused (`catalog-unavailable`, `08006`): the guard cannot resolve names without
  it, and a guess would not be a check.
- **Transaction control** (`BEGIN`, `COMMIT`, `ROLLBACK`) is still `unsupported-statement`: P2 owns it.
- **Gate** (section 6, 3): `psql` through the proxy against a server with `log_statement=all`: an allowed query appears in the server's
  log **as the rendering, not as typed** (a comment or an unusual case is not in it); a refused one **does not appear at all**; the
  results of allowed queries through the proxy equal the results direct, as a diff, for the accepted corpus; an extended-protocol
  client (`psycopg`'s prepared statements, `psql`'s `\bind`) gets the refusal and a working connection.

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
| **P1b-2a** | **SELECT** (`src/stmt.cho`): items and aliases, `FROM` with comma lists and `[INNER|LEFT [OUTER]] JOIN ... ON`, `WHERE`, `GROUP BY`, `HAVING`, `ORDER BY [ASC|DESC]`, `LIMIT`, `OFFSET` | **built**: 146 hand-written cases (83 refusals, each accepted one a fixed point), 34 mutants killed (now part of the 226 and 60 of P1b-2b), PostgreSQL's plans for the original and the rendering equal over 12,000 generated statements (section 3.3) |
| **P1b-2b** | **INSERT, UPDATE, DELETE** (`src/stmt.cho`, `stmt.statement` dispatches on the first word) | **built**: 226 hand-written cases in all (143 refusals), 60 mutants killed, the PostgreSQL plan comparison over INSERT, UPDATE and DELETE as well (section 3.3) |
| **P1b-2c** | **the closed DDL** (`CREATE TABLE`, `DROP TABLE`, `ALTER TABLE ... ADD [COLUMN]`, `CREATE [UNIQUE] INDEX`, `DROP INDEX`) | **built**: 320 hand-written cases in all (211 refusals), 84 statement mutants killed, and `tests/ddl_diff.py`: the original and the rendering are each run in a rolled-back transaction and must leave the same catalog (section 3.4) |
| **P1c** | **lowering** (`src/lower.cho`) to IR v2 bytes from the tree and a schema snapshot, for SELECT, INSERT, UPDATE, DELETE and the closed DDL | **built**: 73 hand-written cases (42 IR byte for byte, 42 effect sets accepted by the verifier, 31 refusals), name resolution compared with PostgreSQL's SQLSTATEs over 8,000 statements, 27 mutants killed (section 4.2); the effect check against a token is P1d |
| **P1d-1** | **the query guard** (`src/guard.cho`), sans-io: lex, parse, lower, infer and check every statement of a `Query` message against the token, and answer the text to send instead, or a refusal | **built**: 51 hand-written verdicts over tokens minted outside `src/`, 13 mutants killed (section 5.1) |
| **P1d-2** | the `Query` branch in the proxy: the schema snapshot read from the upstream database at login, the guard on every `Query`, the rendered text sent, refusals answered as `ErrorResponse` plus `ReadyForQuery`, the extended protocol refused | end to end with psql: differential (2) and the server log (3) |

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
