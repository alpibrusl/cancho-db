-- The measurement of docs/m2-branches.md section 13: `cdb.asof(null::t, n)` over 100,000 rows and 70,000 later changes, against a copy made at the mark.
--   createdb asof_proto; psql -d asof_proto -q -f scripts/measure_asof.sql      (from the repository root; a scratch database: it installs the capture)
--   The `count` lines are timed (`\timing`); `differences` and `same_at_latest` must be 0.
\set ON_ERROR_STOP 1
\timing off

drop table if exists ao_t cascade;
\i sql/capture.sql
alter table cdb.delta add column if not exists ord bigint;
create index if not exists delta_ord on cdb.delta (sch, tbl, ord);
create or replace function cdb.asof(t anyelement, n bigint) returns setof anyelement language plpgsql stable as $$
declare
    rel oid; sc text; tb text; pkexpr text;
begin
    select c.oid, s.nspname, c.relname into rel, sc, tb from pg_class c join pg_namespace s on s.oid = c.relnamespace where c.reltype = pg_typeof(t)::oid;
    select string_agg(format('x.%I', a.attname), ', ' order by array_position(i.indkey::int2[], a.attnum)) into pkexpr
      from pg_index i join pg_attribute a on a.attrelid = i.indrelid and a.attnum = any (i.indkey) where i.indrelid = rel and i.indisprimary;
    return query execute format($f$
        select x.* from %1$s x
         where not exists (select 1 from cdb.delta d where d.sch = %2$L and d.tbl = %3$L and d.ord > %4$s and d.pk = convert_to(jsonb_build_array(%5$s)::text, 'UTF8'))
        union all
        select (jsonb_populate_record(null::%1$s, e.old_row)).*
          from (select distinct on (d.pk) d.old_row from cdb.delta d where d.sch = %2$L and d.tbl = %3$L and d.ord > %4$s order by d.pk, d.ord, d.seq) e
         where e.old_row is not null
    $f$, rel::regclass, sc, tb, n, pkexpr);
end $$;
create table ao_t (id int primary key, a text, b int);
insert into ao_t select g, md5(g::text), g % 100 from generate_series(1, 100000) g;
update cdb.delta set commit_id = '\x01', ord = 1 where tbl = 'ao_t';
alter event trigger cdb_ddl disable;
create table ao_copy as table ao_t;
alter event trigger cdb_ddl enable;
-- 70,000 later changes: 50,000 updates, 10,000 deletes, 10,000 inserts
update ao_t set a = 'u' where id <= 50000;
delete from ao_t where id > 50000 and id <= 60000;
insert into ao_t select g, 'n', 0 from generate_series(100001, 110000) g;
update cdb.delta set commit_id = '\x02', ord = 2 where tbl = 'ao_t' and ord is null;
\timing on
select count(*) from cdb.asof(null::public.ao_t, 1);
select count(*) from cdb.asof(null::public.ao_t, 1);
\timing off
select count(*) as differences from ((select * from cdb.asof(null::public.ao_t, 1) except select * from ao_copy) union all (select * from ao_copy except select * from cdb.asof(null::public.ao_t, 1))) z;
select count(*) as same_at_latest from (select * from cdb.asof(null::public.ao_t, 2) except select * from ao_t) z;
explain (costs off) select count(*) from cdb.asof(null::public.ao_t, 1);
