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
--   cdb.facts(x)    the NET facts of transaction x as the text `C` takes in tools/state.py: `kind:table:pk:old:new`, hex, `-` for none, in (table, pk) order
--
-- A row image is the jsonb text of the row; its hash is SHA-256("cancho-db/row/v1" || 0x00 || that text). A primary key is the jsonb text of the array of its column
-- values, in index order. Both are PostgreSQL's own canonical jsonb text, which does not depend on the client or on the session.

create schema if not exists cdb;

create table if not exists cdb.delta (
    seq bigserial primary key,
    xid bigint not null default txid_current(),
    commit_id bytea,
    tbl text not null,
    pk bytea not null,
    sch text not null default 'public',
    old_hash bytea,
    new_hash bytea,
    old_row jsonb,
    new_row jsonb
);
alter table cdb.delta add column if not exists sch text not null default 'public';
create index if not exists delta_xid on cdb.delta (xid);
create index if not exists delta_commit on cdb.delta (commit_id) where commit_id is not null;

create or replace function cdb.row_hash(r jsonb) returns bytea language sql immutable as $$
    select sha256(convert_to('cancho-db/row/v1', 'UTF8') || '\x00'::bytea || convert_to(r::text, 'UTF8'))
$$;

create or replace function cdb.capture() returns trigger language plpgsql as $$
declare
    pkcols text[] := string_to_array(TG_ARGV[0], ',');
    onclause text;
    pkexpr text;
    t text := TG_TABLE_NAME;
    sc text := TG_TABLE_SCHEMA;
begin
    -- key columns are never null, so plain equality is the join (and is what a full join needs to be hash- or merge-joinable)
    select string_agg(format('o.%1$I = n.%1$I', c), ' and ') into onclause from unnest(pkcols) c;
    select format('convert_to(jsonb_build_array(%s)::text, ''UTF8'')', string_agg(format('%%1$s.%I', c), ', ')) into pkexpr from unnest(pkcols) c;
    if TG_OP = 'INSERT' then
        execute format('insert into cdb.delta(sch, tbl, pk, new_hash, new_row) select %L, %L, %s, cdb.row_hash(to_jsonb(n)), to_jsonb(n) from new_rows n', sc, t, format(pkexpr, 'n'));
    elsif TG_OP = 'DELETE' then
        execute format('insert into cdb.delta(sch, tbl, pk, old_hash, old_row) select %L, %L, %s, cdb.row_hash(to_jsonb(o)), to_jsonb(o) from old_rows o', sc, t, format(pkexpr, 'o'));
    else
        -- matched by primary key: an update; a row only in the old image is a delete of its key, only in the new one an insert (a changed key). A row of the new side
        -- with no old row has a null first key column in `o`, which is how the two sides are told apart (key columns are never null)
        execute format($f$insert into cdb.delta(sch, tbl, pk, old_hash, new_hash, old_row, new_row)
            select %L, %L, case when o.%I is null then %s else %s end, cdb.row_hash(to_jsonb(o)), cdb.row_hash(to_jsonb(n)), to_jsonb(o), to_jsonb(n)
            from old_rows o full join new_rows n on %s$f$, sc, t, pkcols[1], format(pkexpr, 'n'), format(pkexpr, 'o'), onclause);
    end if;
    return null;
end $$;

create or replace function cdb.track(tbl regclass) returns void language plpgsql as $$
declare
    cols text;
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
    execute format('create trigger cdb_ins after insert on %s referencing new table as new_rows for each statement execute function cdb.capture(%L)', tbl, cols);
    execute format('create trigger cdb_upd after update on %s referencing old table as old_rows new table as new_rows for each statement execute function cdb.capture(%L)', tbl, cols);
    execute format('create trigger cdb_del after delete on %s referencing old table as old_rows for each statement execute function cdb.capture(%L)', tbl, cols);
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
    select coalesce(string_agg(k.kind::text || ':' || encode(convert_to(c.tbl, 'UTF8'), 'hex') || ':' || encode(c.pk, 'hex') || ':' || coalesce(encode(c.oh, 'hex'), '-') || ':' || coalesce(encode(c.nh, 'hex'), '-'),
                                ' ' order by convert_to(c.tbl, 'UTF8'), c.pk), '')
      from (select tbl, pk, (array_agg(old_hash order by seq))[1] as oh, (array_agg(new_hash order by seq desc))[1] as nh from cdb.delta where xid = x group by tbl, pk) c
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
    for r in select c.oid::regclass as t from pg_class c join pg_namespace s on s.oid = c.relnamespace where s.nspname = dst and c.relkind = 'r' loop
        perform cdb.track(r.t);
    end loop;
    perform set_config('cdb.forking', 'off', true);
    return n;
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
