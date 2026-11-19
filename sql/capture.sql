-- Row-delta capture (docs/m2-branches.md D5 and D6; the producer's definitions docs/spec/state.md leaves open): installed by the proxy, never by a client.
-- Idempotent: it can be run again at every start.
--
--   cdb.delta       one row per fact a statement changed: the row image before and after, and their hashes
--   cdb.capture()   the trigger function (statement level, transition tables): INSERT, UPDATE and DELETE each write their facts
--   cdb.track(t)    install the three triggers on a table (it needs a primary key; without one the call raises)
--   cdb.track_all() track every table of the schema `public`
--   cdb.untrackable()  the tables of `public` the capture cannot track (no primary key, or partitioned), as text: empty when there are none
--   cdb.on_ddl()    an event trigger function: a table made or altered in `public` is tracked in the same transaction, so its first write is captured; a keyless
--                   or partitioned one raises and the statement fails
--   cdb.on_drop()   an event trigger function: a dropped table's salts (cdb.cur) are dropped with it
--   cdb.facts(x)    the NET facts of transaction x as the text `C` takes in tools/state.py: `kind:table:pk:old:new`, hex, `-` for none, in (table, pk) order
--
-- Version 2 (docs/m2g-erasure.md, docs/spec/l3a.md section 9). A row image is the jsonb text of the row; each version of a row has a random 16-byte salt and its hash is
-- SHA-256("cancho-db/row/v2" || 0x00 || salt || that text). A primary key is the jsonb text of the array of its column values, in index order ("the plain key"); the fact's
-- `pk` is a commitment to it, SHA-256("cancho-db/key/v1" || 0x00 || key_salt || plain key), the salt being the key's own, made when the row is inserted. Both texts are PostgreSQL's
-- own canonical jsonb text, which does not depend on the client or on the session. The salts of the rows as they stand are in `cdb.cur`, the old and new salt of every fact in
-- `cdb.delta`. Nothing but the hashes and the commitments is in the log; erasing a row means destroying its images, salts and plain keys (docs/m2g-erasure.md).

create schema if not exists cdb;

create table if not exists cdb.delta (
    seq bigserial primary key,
    xid bigint not null default txid_current(),
    commit_id bytea,
    tbl text not null,
    pk bytea,
    sch text not null default 'public',
    old_hash bytea,
    new_hash bytea,
    old_row jsonb,
    new_row jsonb
);
alter table cdb.delta add column if not exists sch text not null default 'public';
alter table cdb.delta alter column pk drop not null;
-- version 2: the commitment to the key (what a fact's `pk` is), the key's and the row versions' salts. `pk` is the plain key and the images and salts are the payloads: null once erased.
alter table cdb.delta add column if not exists kc bytea;
alter table cdb.delta add column if not exists key_salt bytea;
alter table cdb.delta add column if not exists old_salt bytea;
alter table cdb.delta add column if not exists new_salt bytea;
alter table cdb.delta add column if not exists ord bigint;
create index if not exists delta_ord on cdb.delta (sch, tbl, ord) where ord is not null;

-- One row for each commit that wrote (a write, DDL or a call: the commits that are prepared), inserted in the same transaction as the stamp of its delta rows: the commit's id, the schema of its branch and
-- its place in the log (`ord`, the index of the commit in the log, from 0). `AS OF` names a commit by its id and finds its place here (docs/m2-branches.md D30).
create table if not exists cdb.mark (
    commit_id bytea primary key,
    sch text not null,
    ord bigint not null
);
create index if not exists mark_sch on cdb.mark (sch, ord);
create index if not exists delta_xid on cdb.delta (xid);
create index if not exists delta_commit on cdb.delta (commit_id) where commit_id is not null;

-- The salts of the rows as they stand (the rows of every tracked table, keyed by the plain key): the key's salt, the salt of the current version, and the commitment.
create table if not exists cdb.cur (
    sch text not null,
    tbl text not null,
    pk bytea not null,
    key_salt bytea not null,
    salt bytea not null,
    kc bytea not null,
    primary key (sch, tbl, pk)
);

-- Refuses a database that holds deltas of version 1 (unsalted): its history cannot be made erasable, and the two versions are not mixed in one delta store (docs/m2g-erasure.md Q13).
do $$
begin
    if exists (select 1 from cdb.delta where kc is null) then
        raise exception 'cdb: this database holds delta rows of version 1 (unsalted); the capture is version 2' using errcode = '55000';
    end if;
end $$;

create or replace function cdb.rnd() returns bytea language sql volatile as $$
    select decode(replace(gen_random_uuid()::text, '-', ''), 'hex')
$$;

-- The hash of a row image with its salt (a version 2 row hash); a null salt is a row the capture knows nothing of, and raises rather than hash it unsalted.
create or replace function cdb.row_hash2(salt bytea, r jsonb) returns bytea language plpgsql immutable as $$
begin
    if salt is null then
        raise exception 'cdb: a row without a salt (it was not written through a tracked table)' using errcode = '55000';
    end if;
    return sha256(convert_to('cancho-db/row/v2', 'UTF8') || '\x00'::bytea || salt || convert_to(r::text, 'UTF8'));
end $$;

create or replace function cdb.key_commit(salt bytea, plain bytea) returns bytea language sql immutable as $$
    select sha256(convert_to('cancho-db/key/v1', 'UTF8') || '\x00'::bytea || salt || plain)
$$;

-- A name for a row alias that no column of `rel` has: `to_jsonb(n)` is the COLUMN n if the table has one and not the row, so the aliases of the capture (and of cdb.merge) are made not to be a column's name.
create or replace function cdb.free_alias(rel regclass, base text) returns text language plpgsql stable as $$
declare
    a text := base;
begin
    while exists (select 1 from pg_attribute where attrelid = rel and attname = a and attnum > 0 and not attisdropped) loop
        a := a || '_';
    end loop;
    return a;
end $$;

create or replace function cdb.capture() returns trigger language plpgsql as $$
declare
    pkcols text[] := string_to_array(TG_ARGV[0], ',');
    ao text := TG_ARGV[1];
    an text := TG_ARGV[2];
    onclause text;
    pkexpr text;
    t text := TG_TABLE_NAME;
    sc text := TG_TABLE_SCHEMA;
begin
    -- key columns are never null, so plain equality is the join (and is what a full join needs to be hash- or merge-joinable)
    select string_agg(format('%1$s.%3$I = %2$s.%3$I', ao, an, c), ' and ') into onclause from unnest(pkcols) c;
    select format('convert_to(jsonb_build_array(%s)::text, ''UTF8'')', string_agg(format('%%1$s.%I', c), ', ')) into pkexpr from unnest(pkcols) c;
    if TG_OP = 'INSERT' then
        -- a new row: its key's salt and its first version's salt are made here, remembered in cdb.cur, and written beside the fact
        execute format($q$with j as materialized (select %1$s as pk, to_jsonb(%2$I) as r, cdb.rnd() as ks, cdb.rnd() as s from new_rows %2$I),
                               c as (insert into cdb.cur (sch, tbl, pk, key_salt, salt, kc) select %3$L, %4$L, j.pk, j.ks, j.s, cdb.key_commit(j.ks, j.pk) from j)
                          insert into cdb.delta (sch, tbl, pk, kc, key_salt, new_hash, new_salt, new_row)
                          select %3$L, %4$L, j.pk, cdb.key_commit(j.ks, j.pk), j.ks, cdb.row_hash2(j.s, j.r), j.s, j.r from j$q$,
                       format(pkexpr, an), an, sc, t);
    elsif TG_OP = 'DELETE' then
        execute format($q$with j as materialized (select %1$s as pk, to_jsonb(%2$I) as r from old_rows %2$I),
                               k as materialized (select j.pk, j.r, c.salt as os, c.key_salt as cks, c.kc as ckc from j left join cdb.cur c on c.sch = %3$L and c.tbl = %4$L and c.pk = j.pk),
                               d as (delete from cdb.cur c using k where c.sch = %3$L and c.tbl = %4$L and c.pk = k.pk)
                          insert into cdb.delta (sch, tbl, pk, kc, key_salt, old_hash, old_salt, old_row)
                          select %3$L, %4$L, k.pk, k.ckc, k.cks, cdb.row_hash2(k.os, k.r), k.os, k.r from k$q$,
                       format(pkexpr, ao), ao, sc, t);
    else
        -- matched by primary key: an update; a row only in the old image is a delete of its key, only in the new one an insert (a changed key). A row of the new side
        -- with no old row has a null first key column in the old alias, which is how the two sides are told apart (key columns are never null). An update keeps the key's
        -- salt and commitment and gives the row a new salt (the old one again if the image did not change, so that a write that changes nothing is no fact); an insert gets both; a delete drops the row's entry in cdb.cur
        execute format($q$with j as materialized (select case when %1$I.%5$I is null then null else %6$s end as opk, case when %2$I.%5$I is null then null else %7$s end as npk,
                                                         to_jsonb(%1$I) as o, to_jsonb(%2$I) as n, cdb.rnd() as ks
                                                    from old_rows %1$I full join new_rows %2$I on %8$s),
                               k as materialized (select j.opk, j.npk, j.o, j.n, j.ks, c.salt as os, c.key_salt as cks, c.kc as ckc, case when j.o = j.n then c.salt else cdb.rnd() end as s
                                                    from j left join cdb.cur c on c.sch = %3$L and c.tbl = %4$L and c.pk = j.opk),
                               u as (update cdb.cur c set salt = k.s from k where k.opk is not null and k.npk is not null and c.sch = %3$L and c.tbl = %4$L and c.pk = k.opk),
                               d as (delete from cdb.cur c using k where k.opk is not null and k.npk is null and c.sch = %3$L and c.tbl = %4$L and c.pk = k.opk),
                               i as (insert into cdb.cur (sch, tbl, pk, key_salt, salt, kc) select %3$L, %4$L, k.npk, k.ks, k.s, cdb.key_commit(k.ks, k.npk) from k where k.opk is null)
                          insert into cdb.delta (sch, tbl, pk, kc, key_salt, old_hash, new_hash, old_salt, new_salt, old_row, new_row)
                          select %3$L, %4$L, coalesce(k.opk, k.npk), case when k.opk is null then cdb.key_commit(k.ks, k.npk) else k.ckc end, case when k.opk is null then k.ks else k.cks end,
                                 case when k.opk is null then null else cdb.row_hash2(k.os, k.o) end, case when k.npk is null then null else cdb.row_hash2(k.s, k.n) end,
                                 case when k.opk is null then null else k.os end, case when k.npk is null then null else k.s end,
                                 case when k.opk is null then null else k.o end, case when k.npk is null then null else k.n end
                            from k$q$,
                       ao, an, sc, t, pkcols[1], format(pkexpr, ao), format(pkexpr, an), onclause);
    end if;
    return null;
end $$;

create or replace function cdb.track(tbl regclass) returns void language plpgsql as $$
declare
    cols text;
    ao text;
    an text;
begin
    select string_agg(a.attname, ',' order by array_position(i.indkey::int2[], a.attnum)) into cols
      from pg_index i join pg_attribute a on a.attrelid = i.indrelid and a.attnum = any (i.indkey)
     where i.indrelid = tbl and i.indisprimary;
    if cols is null then
        raise exception 'cdb.track: table % has no primary key', tbl using errcode = '55000';
    end if;
    execute format('drop trigger if exists cdb_ins on %s', tbl);
    execute format('drop trigger if exists cdb_upd on %s', tbl);
    execute format('drop trigger if exists cdb_del on %s', tbl);
    ao := cdb.free_alias(tbl, 'cdb_o');
    an := cdb.free_alias(tbl, 'cdb_n');
    -- rows that are already in the table (a base: written before the capture, or copied by a fork, whose entries in cdb.cur were copied first) get a salt each
    execute format('insert into cdb.cur (sch, tbl, pk, key_salt, salt, kc) select %L, %L, x.pk, x.ks, cdb.rnd(), cdb.key_commit(x.ks, x.pk) from (select convert_to(jsonb_build_array(%s)::text, ''UTF8'') as pk, cdb.rnd() as ks from %s) x on conflict do nothing',
                   (select n.nspname from pg_class c join pg_namespace n on n.oid = c.relnamespace where c.oid = tbl), (select c.relname from pg_class c where c.oid = tbl),
                   (select string_agg(format('%I', c), ', ') from unnest(string_to_array(cols, ',')) c), tbl);
    execute format('create trigger cdb_ins after insert on %s referencing new table as new_rows for each statement execute function cdb.capture(%L, %L, %L)', tbl, cols, ao, an);
    execute format('create trigger cdb_upd after update on %s referencing old table as old_rows new table as new_rows for each statement execute function cdb.capture(%L, %L, %L)', tbl, cols, ao, an);
    execute format('create trigger cdb_del after delete on %s referencing old table as old_rows for each statement execute function cdb.capture(%L, %L, %L)', tbl, cols, ao, an);
end $$;

create or replace function cdb.track_all() returns int language plpgsql as $$
declare
    r record;
    n int := 0;
begin
    for r in select c.oid::regclass as t from pg_class c join pg_namespace s on s.oid = c.relnamespace where (s.nspname = 'public' or s.nspname like 'cdb\_b\_%') and c.relkind = 'r' loop
        perform cdb.track(r.t);
        n := n + 1;
    end loop;
    return n;
end $$;

-- The net facts of transaction x: per (table, key) the image before the first change and the image after the last; a row inserted and deleted in the same
-- transaction, or changed and changed back, is no fact. Sorted as docs/spec/state.md section 3 sorts (unsigned bytes, a prefix first).
create or replace function cdb.facts(x bigint) returns text language sql stable as $$
    select coalesce(string_agg(k.kind::text || ':' || encode(convert_to(c.tbl, 'UTF8'), 'hex') || ':' || encode(c.kc, 'hex') || ':' || coalesce(encode(c.oh, 'hex'), '-') || ':' || coalesce(encode(c.nh, 'hex'), '-'),
                                ' ' order by convert_to(c.tbl, 'UTF8'), c.kc), '')
      from (select tbl, kc, (array_agg(old_hash order by seq))[1] as oh, (array_agg(new_hash order by seq desc))[1] as nh from cdb.delta where xid = x group by tbl, kc) c
      cross join lateral (select case when c.oh is null then 0 when c.nh is null then 2 else 1 end as kind) k
     where not (c.oh is null and c.nh is null) and c.oh is distinct from c.nh
$$;

-- The tables of `public` that cannot be tracked: a partitioned table (and its partitions) would record one row under two names, by the path it was written through, and a table
-- without a primary key has no key for a fact. The proxy refuses to start while there are any (docs/m2-branches.md D15).
create or replace function cdb.untrackable() returns text language sql stable as $$
    select coalesce(string_agg(case when n.nspname = 'public' then '' else n.nspname || '.' end || c.relname || case when c.relkind = 'p' or c.relispartition then ' (partitioned)' else ' (no primary key)' end, ', ' order by c.relname), '')
      from pg_class c join pg_namespace n on n.oid = c.relnamespace
     where (n.nspname = 'public' or n.nspname like 'cdb\_b\_%') and c.relkind in ('r', 'p')
       and (c.relkind = 'p' or c.relispartition or not exists (select 1 from pg_index i where i.indrelid = c.oid and i.indisprimary))
$$;

-- A fork (docs/m2-branches.md D2, D24): schema `dst` gets a copy of every table of schema `src` (columns, defaults, constraints and indexes by `like ... including all`, then
-- the foreign keys between the copies, and identity counters set past the copied rows), and the copies are tracked afterwards, so that the copying is a base and records no
-- facts. Returns the number of tables. Views, functions and types are not copied; a column default that calls a sequence goes on using the source's sequence.
create or replace function cdb.fork(src text, dst text) returns int language plpgsql as $$
declare
    r record;
    n int := 0;
    old_path text := current_setting('search_path');
    cols text;
    fks text[];
    stmt text;
begin
    perform set_config('cdb.forking', 'on', true);
    perform set_config('client_min_messages', 'warning', true);
    execute format('create schema %I', dst);
    for r in select c.relname from pg_class c join pg_namespace s on s.oid = c.relnamespace where s.nspname = src and c.relkind = 'r' order by c.relname loop
        execute format('create table %I.%I (like %I.%I including all)', dst, r.relname, src, r.relname);
        select string_agg(quote_ident(a.attname), ', ' order by a.attnum) into cols
          from pg_attribute a where a.attrelid = format('%I.%I', src, r.relname)::regclass and a.attnum > 0 and not a.attisdropped and a.attgenerated = '';
        if cols is not null then
            execute format('insert into %I.%I (%s) overriding system value select %s from %I.%I', dst, r.relname, cols, cols, src, r.relname);
        end if;
        for cols in select a.attname from pg_attribute a where a.attrelid = format('%I.%I', src, r.relname)::regclass and a.attidentity <> '' loop
            execute format('select setval(%L, coalesce((select max(%I) from %I.%I), 0) + 1, false)', pg_get_serial_sequence(format('%I.%I', dst, r.relname), cols), cols, dst, r.relname);
        end loop;
        n := n + 1;
    end loop;
    -- foreign keys: written as the source prints them with its own schema on the path, then run with the copy's on it
    perform set_config('search_path', quote_ident(src), true);
    select coalesce(array_agg(format('alter table %s add constraint %I %s', c.conrelid::regclass::text, c.conname, pg_get_constraintdef(c.oid)) order by c.conrelid::regclass::text, c.conname), '{}') into fks
      from pg_constraint c join pg_class t on t.oid = c.conrelid join pg_namespace s on s.oid = t.relnamespace where s.nspname = src and c.contype = 'f';
    perform set_config('search_path', quote_ident(dst), true);
    foreach stmt in array fks loop
        execute stmt;
    end loop;
    perform set_config('search_path', old_path, true);
    -- the copies keep the salts of the rows they were copied from (the fork commit has no facts: the branch starts from the source's hashes), then are tracked
    insert into cdb.cur (sch, tbl, pk, key_salt, salt, kc) select dst, c.tbl, c.pk, c.key_salt, c.salt, c.kc from cdb.cur c where c.sch = src;
    for r in select c.oid::regclass as t from pg_class c join pg_namespace s on s.oid = c.relnamespace where s.nspname = dst and c.relkind = 'r' loop
        perform cdb.track(r.t);
    end loop;
    perform set_config('cdb.forking', 'off', true);
    return n;
end $$;

-- `AS OF` (docs/m2-branches.md D30, D31). `cdb.ord('<64 hex digits>')` is the place in the log of that commit of the connection's branch (the schema first on the search path): 22023 `as-of-unknown-commit` if
-- the branch has no such commit that wrote, 55000 `as-of-unavailable` if some delta rows of the branch were stamped before `ord` existed (their place is not known).
create or replace function cdb.ord(h text) returns bigint language plpgsql stable as $$
declare
    sc text := current_schema();
    o bigint;
begin
    select m.ord into o from cdb.mark m where m.commit_id = decode(h, 'hex') and m.sch = sc;
    if o is null then
        raise exception 'as-of-unknown-commit: the branch has no commit that wrote with that id' using errcode = '22023';
    end if;
    if exists (select 1 from cdb.delta d where d.sch = sc and d.commit_id is not null and d.ord is null) then
        raise exception 'as-of-unavailable: some of the history of this branch was recorded before it could be ordered' using errcode = '55000';
    end if;
    return o;
end $$;

-- The table of type `t` (a table's row type: `null::t`) as it was after the commit at place `n`: the current rows whose key no later delta touched, and the old image of the earliest later delta of every key that
-- one touched, unless that delta is an insert. The deltas of the transaction asking, not yet stamped, are later than every commit: its own writes are not in the past. Schema changes since are not reflected (the old image is the old row read into today's type); a table made since reads as empty.
create or replace function cdb.asof(t anyelement, n bigint) returns setof anyelement language plpgsql stable as $$
declare
    rel oid;
    sc text;
    tb text;
    pkexpr text;
begin
    select c.oid, s.nspname, c.relname into rel, sc, tb from pg_class c join pg_namespace s on s.oid = c.relnamespace where c.reltype = pg_typeof(t)::oid;
    select string_agg(format('x.%I', a.attname), ', ' order by array_position(i.indkey::int2[], a.attnum)) into pkexpr
      from pg_index i join pg_attribute a on a.attrelid = i.indrelid and a.attnum = any (i.indkey) where i.indrelid = rel and i.indisprimary;
    return query execute format($f$
        select x.* from %1$s x
         where not exists (select 1 from cdb.delta d where d.sch = %2$L and d.tbl = %3$L and (d.ord > %4$s or d.ord is null and d.xid = txid_current()) and d.pk = convert_to(jsonb_build_array(%5$s)::text, 'UTF8'))
        union all
        select (jsonb_populate_record(null::%1$s, e.old_row)).*
          from (select distinct on (d.pk) d.old_row from cdb.delta d where d.sch = %2$L and d.tbl = %3$L and (d.ord > %4$s or d.ord is null and d.xid = txid_current()) order by d.pk, coalesce(d.ord, 9223372036854775807), d.seq) e
         where e.old_row is not null
    $f$, rel::regclass, sc, tb, n, pkexpr);
end $$;

-- A merge (docs/m2-branches.md D34 to D37): the three-way merge of the tables of schema `ssch` (the source) into those of `tsch` (the target), key by key and by state, the base being the tables of `bsch` `AS OF`
-- place `bord` (cdb.asof). Source unchanged from the base: the target's row stays; target unchanged, source changed: the source's version is applied; both changed to one image: nothing; both changed to
-- different images, or one deleted and the other changed: a conflict. All tables are looked at before anything is applied, and a conflict anywhere raises 'merge-conflict' (the keys, ten at most) so that the
-- transaction rolls back; so does a source row PostgreSQL refuses ('merge-constraint') and a table the two sides do not both have, with the same columns ('merge-schema-differs'). Deletes are applied children first,
-- then updates and inserts parents first. The applying is by ordinary statements, so the capture records it as the net facts of the transaction. Nothing here makes a temporary table: a transaction that did
-- cannot be prepared. Returns the number of rows applied.
create or replace function cdb.merge(tsch text, ssch text, bsch text, bord bigint) returns int language plpgsql as $$
declare
    tabs text[];
    ordered text[] := '{}';
    t text;
    n int;
    pk text;
    cols text;
    pkq text;
    q text;
    conflicts text[] := '{}';
    nconf int := 0;
    one text[];
    dels jsonb[] := '{}';
    upds jsonb[] := '{}';
    inss jsonb[] := '{}';
    i int;
    applied int := 0;
    rc int;
    rcols text;
    ra text;
    progress boolean;
begin
    select coalesce(array_agg(c.relname::text order by c.relname), '{}') into tabs from pg_class c join pg_namespace s on s.oid = c.relnamespace where s.nspname = tsch and c.relkind = 'r';
    if tabs is distinct from (select coalesce(array_agg(c.relname::text order by c.relname), '{}') from pg_class c join pg_namespace s on s.oid = c.relnamespace where s.nspname = ssch and c.relkind = 'r') then
        raise exception 'merge-schema-differs: the two branches do not have the same tables' using errcode = '55000';
    end if;
    foreach t in array tabs loop
        if (select array_agg(a.attname || ':' || a.atttypid order by a.attnum) from pg_attribute a where a.attrelid = format('%I.%I', tsch, t)::regclass and a.attnum > 0 and not a.attisdropped)
           is distinct from (select array_agg(a.attname || ':' || a.atttypid order by a.attnum) from pg_attribute a where a.attrelid = format('%I.%I', ssch, t)::regclass and a.attnum > 0 and not a.attisdropped) then
            raise exception 'merge-schema-differs: table % has other columns on the two branches', t using errcode = '55000';
        end if;
        if to_regclass(format('%I.%I', bsch, t)) is null then
            raise exception 'merge-schema-differs: table % did not exist at the merge base', t using errcode = '55000';
        end if;
    end loop;
    -- parents before children, by the foreign keys among the tables
    loop
        progress := false;
        foreach t in array tabs loop
            if not (t = any (ordered)) and not exists (
                select 1 from pg_constraint c join pg_class r on r.oid = c.confrelid join pg_namespace rs on rs.oid = r.relnamespace
                 where c.contype = 'f' and c.conrelid = format('%I.%I', tsch, t)::regclass and rs.nspname = tsch and r.relname::text <> t and r.relname::text = any (tabs) and not (r.relname::text = any (ordered))) then
                ordered := ordered || t;
                progress := true;
            end if;
        end loop;
        exit when not progress;
    end loop;
    foreach t in array tabs loop
        if not (t = any (ordered)) then
            ordered := ordered || t;
        end if;
    end loop;
    n := coalesce(array_length(ordered, 1), 0);
    -- every table: the classification of every key, in one pass
    for i in 1 .. n loop
        t := ordered[i];
        ra := cdb.free_alias(format('%I.%I', tsch, t)::regclass, 'cdb_r');
        select string_agg(format('%I.%I', ra, a.attname), ', ' order by array_position(ix.indkey::int2[], a.attnum)) into pk
          from pg_index ix join pg_attribute a on a.attrelid = ix.indrelid and a.attnum = any (ix.indkey) where ix.indrelid = format('%I.%I', tsch, t)::regclass and ix.indisprimary;
        q := format($f$
            with m as materialized (
                select coalesce(t.k, s.k, b.k) as k, b.j as bj, t.j as tj, s.j as sj
                  from (select jsonb_build_array(%1$s) as k, to_jsonb(%7$I) as j from cdb.asof(null::%2$I.%3$I, %4$s) %7$I) b
                  full join (select jsonb_build_array(%1$s) as k, to_jsonb(%7$I) as j from %5$I.%3$I %7$I) t on t.k = b.k
                  full join (select jsonb_build_array(%1$s) as k, to_jsonb(%7$I) as j from %6$I.%3$I %7$I) s on s.k = coalesce(t.k, b.k))
            select (select coalesce(array_agg(%3$L || ' ' || k::text order by k::text), '{}') from (select k from m where tj is distinct from bj and sj is distinct from bj and tj is distinct from sj order by k::text limit 10) c),
                   (select count(*) from m where tj is distinct from bj and sj is distinct from bj and tj is distinct from sj),
                   (select coalesce(jsonb_agg(k), '[]') from m where tj is not distinct from bj and sj is distinct from bj and sj is null),
                   (select coalesce(jsonb_agg(sj), '[]') from m where tj is not distinct from bj and sj is distinct from bj and sj is not null and tj is not null),
                   (select coalesce(jsonb_agg(sj), '[]') from m where tj is not distinct from bj and sj is distinct from bj and sj is not null and tj is null)$f$, pk, bsch, t, bord, tsch, ssch, ra);
        declare
            c_keys text[];
            c_n bigint;
            d jsonb;
            u jsonb;
            ins jsonb;
        begin
            execute q into c_keys, c_n, d, u, ins;
            nconf := nconf + c_n;
            conflicts := conflicts || c_keys;
            dels := dels || d;
            upds := upds || u;
            inss := inss || ins;
        end;
    end loop;
    if nconf > 0 then
        raise exception 'merge-conflict: % key(s) changed differently on both branches: %', nconf, array_to_string(conflicts[1:10], ', ') using errcode = '40001';
    end if;
    begin
        -- deletes, children first
        for i in reverse n .. 1 loop
            t := ordered[i];
            if jsonb_array_length(dels[i]) > 0 then
                select string_agg(format('x.%I', a.attname), ', ' order by array_position(ix.indkey::int2[], a.attnum)) into pk
                  from pg_index ix join pg_attribute a on a.attrelid = ix.indrelid and a.attnum = any (ix.indkey) where ix.indrelid = format('%I.%I', tsch, t)::regclass and ix.indisprimary;
                execute format('delete from %1$I.%2$I x using jsonb_array_elements($1) e(k) where jsonb_build_array(%3$s) = e.k', tsch, t, pk) using dels[i];
                get diagnostics rc := row_count;
                applied := applied + rc;
            end if;
        end loop;
        -- updates and inserts, parents first
        for i in 1 .. n loop
            t := ordered[i];
            select string_agg(format('x.%I', a.attname), ', ' order by array_position(ix.indkey::int2[], a.attnum)) into pk
              from pg_index ix join pg_attribute a on a.attrelid = ix.indrelid and a.attnum = any (ix.indkey) where ix.indrelid = format('%I.%I', tsch, t)::regclass and ix.indisprimary;
            select string_agg(format('r.%I', a.attname), ', ' order by array_position(ix.indkey::int2[], a.attnum)) into pkq
              from pg_index ix join pg_attribute a on a.attrelid = ix.indrelid and a.attnum = any (ix.indkey) where ix.indrelid = format('%I.%I', tsch, t)::regclass and ix.indisprimary;
            select string_agg(quote_ident(a.attname), ', ' order by a.attnum), string_agg('r.' || quote_ident(a.attname), ', ' order by a.attnum) into cols, rcols
              from pg_attribute a where a.attrelid = format('%I.%I', tsch, t)::regclass and a.attnum > 0 and not a.attisdropped and a.attgenerated = '';
            if jsonb_array_length(upds[i]) > 0 then
                execute format('update %1$I.%2$I x set (%3$s) = row(%6$s) from jsonb_populate_recordset(null::%1$I.%2$I, $1) r where jsonb_build_array(%4$s) = jsonb_build_array(%5$s)', tsch, t, cols, pk, pkq, rcols) using upds[i];
                applied := applied + jsonb_array_length(upds[i]);
            end if;
            if jsonb_array_length(inss[i]) > 0 then
                execute format('insert into %1$I.%2$I (%3$s) overriding system value select %3$s from jsonb_populate_recordset(null::%1$I.%2$I, $1)', tsch, t, cols) using inss[i];
                applied := applied + jsonb_array_length(inss[i]);
            end if;
        end loop;
    exception when integrity_constraint_violation then
        raise exception 'merge-constraint: %', sqlerrm using errcode = sqlstate;
    end;
    return applied;
end $$;

create or replace function cdb.on_ddl() returns event_trigger language plpgsql as $$
declare
    r record;
    k "char";
    part boolean;
    ns name;
begin
    for r in select objid from pg_event_trigger_ddl_commands() where object_type = 'table' loop
        select c.relkind, c.relispartition, n.nspname into k, part, ns from pg_class c join pg_namespace n on n.oid = c.relnamespace where c.oid = r.objid;
        -- a fork's own copying (cdb.fork) makes tables that are a base and not a change: it tracks them itself, afterwards
        continue when current_setting('cdb.forking', true) = 'on';
        continue when (ns is distinct from 'public' and ns not like 'cdb\_b\_%') or k not in ('r', 'p');
        if k = 'p' or part then
            raise exception 'cdb: partitioned tables are not supported (%)', r.objid::regclass using errcode = '0A000';
        end if;
        perform cdb.track(r.objid::regclass);
    end loop;
end $$;

drop event trigger if exists cdb_ddl;
create event trigger cdb_ddl on ddl_command_end when tag in ('CREATE TABLE', 'CREATE TABLE AS', 'ALTER TABLE') execute function cdb.on_ddl();

-- A dropped table (or schema, with its tables) takes its entries in cdb.cur with it: a table made again under the name must not inherit the salts of the one before.
create or replace function cdb.on_drop() returns event_trigger language plpgsql as $$
begin
    delete from cdb.cur c using pg_event_trigger_dropped_objects() d where d.object_type = 'table' and c.sch = d.schema_name and c.tbl = d.object_name;
end $$;

drop event trigger if exists cdb_drop;
create event trigger cdb_drop on sql_drop execute function cdb.on_drop();
