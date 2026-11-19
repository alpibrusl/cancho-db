-- The measurement of docs/m2-branches.md section 15: a three-way merge of two branches in SQL, by keys, over 100,000 rows.
--   createdb merge_proto; psql -d merge_proto -q -f scripts/measure_merge.sql      (from the repository root; a scratch database: it installs the capture)
-- The branches are made by cdb.fork; each then changes a tenth of the rows, 1,000 of them the same rows (500 to the same image, 500 to different ones); `merge ms` is the time of cdb.merge_proto.
\set ON_ERROR_STOP 1
drop table if exists mt cascade;
\i sql/capture.sql
create or replace function cdb.merge_proto(tsch text, ssch text, bsch text, bord bigint, tbl text, apply boolean) returns text language plpgsql as $$
declare
    pk text;
    cols text;
    conflicts int;
    taken int;
begin
    select string_agg(format('x.%I', a.attname), ', ' order by array_position(i.indkey::int2[], a.attnum)) into pk
      from pg_index i join pg_attribute a on a.attrelid = i.indrelid and a.attnum = any (i.indkey) where i.indrelid = format('%I.%I', tsch, tbl)::regclass and i.indisprimary;
    execute format($f$create temporary table cdb_m on commit drop as
        select coalesce(t.k, s.k, b.k) as k, b.j as bj, t.j as tj, s.j as sj
          from (select jsonb_build_array(%1$s) as k, to_jsonb(x) as j from cdb.asof(null::%2$I.%3$I, %4$s) x) b
          full join (select jsonb_build_array(%1$s) as k, to_jsonb(x) as j from %5$I.%3$I x) t on t.k = b.k
          full join (select jsonb_build_array(%1$s) as k, to_jsonb(x) as j from %6$I.%3$I x) s on s.k = coalesce(t.k, b.k)$f$, pk, bsch, tbl, bord, tsch, ssch);
    select count(*) into conflicts from cdb_m where tj is distinct from bj and sj is distinct from bj and tj is distinct from sj;
    select count(*) into taken from cdb_m where tj is not distinct from bj and sj is distinct from bj;
    if apply and conflicts = 0 then
        select string_agg(quote_ident(a.attname), ', ' order by a.attnum) into cols from pg_attribute a where a.attrelid = format('%I.%I', tsch, tbl)::regclass and a.attnum > 0 and not a.attisdropped and a.attgenerated = '';
        execute format('delete from %1$I.%2$I x using cdb_m m where m.tj is not distinct from m.bj and m.sj is null and m.bj is not null and jsonb_build_array(%3$s) = m.k', tsch, tbl, pk);
        execute format('insert into %1$I.%2$I (%3$s) overriding system value select %3$s from (select (jsonb_populate_record(null::%1$I.%2$I, m.sj)).* from cdb_m m where m.tj is null and m.sj is not null and m.bj is null) r', tsch, tbl, cols);
        execute format('update %1$I.%2$I x set (%3$s) = (select %3$s from (select (jsonb_populate_record(null::%1$I.%2$I, m.sj)).* ) r) from cdb_m m where m.tj is not null and m.sj is not null and m.tj is not distinct from m.bj and m.sj is distinct from m.bj and jsonb_build_array(%4$s) = m.k', tsch, tbl, cols, pk);
    end if;
    drop table cdb_m;
    return conflicts || ' conflicts, ' || taken || ' taken from the source';
end $$;
create table mt (id int primary key, a text, b int);
insert into mt select g, md5(g::text), g % 100 from generate_series(1, 100000) g;
update cdb.delta set commit_id = '\x01', ord = 1 where tbl = 'mt';
insert into cdb.mark values ('\x01', 'public', 1);
select cdb.fork('public', 'cdb_b_s');
-- the target: 10,000 rows changed (ids 1..10000, 500 of them also changed by the source: ids 1..500 to the same image, ids 501..1000 to another)
update mt set a = 'T' where id <= 10000 and id > 1000;
update mt set a = 'same' where id <= 500;
update mt set a = 'T-only' where id > 500 and id <= 1000;
update cdb.delta set commit_id = '\x02', ord = 2 where tbl = 'mt' and ord is null and sch = 'public';
update cdb_b_s.mt set a = 'S' where id > 90000 and id <= 99000;
update cdb_b_s.mt set a = 'same' where id <= 500;
update cdb_b_s.mt set a = 'S-other' where id > 500 and id <= 1000;
\timing on
select cdb.merge_proto('public', 'cdb_b_s', 'public', 1, 'mt', false) as dry_run_finds;
\timing off
-- remove the conflicts (the 500 rows both changed to different images) and merge for real
update cdb_b_s.mt set a = 'T-only' where id > 500 and id <= 1000;
\timing on
begin;
select cdb.merge_proto('public', 'cdb_b_s', 'public', 1, 'mt', true) as merge;
\timing off
select count(*) filter (where a = 'S') as rows_taken_from_source, count(*) filter (where a = 'T') as target_changes_kept, count(*) filter (where a = 'same') as same_both from mt;
select count(*) as facts_recorded from cdb.facts(txid_current()) f, regexp_split_to_table(f, ' ') r where r <> '' limit 1;
rollback;
