-- The cost of row-delta capture (docs/m2-branches.md section 3.3 and 8): the same statements on a table with and without sql/capture.sql's triggers.
--     psql -h HOST -p PORT -U postgres -d DB -f sql/capture.sql
--     psql -h HOST -p PORT -U postgres -d DB -f scripts/measure_m2.sql
\set ON_ERROR_STOP 1
drop table if exists m_plain, m_cap;
create table m_plain(id bigint primary key, owner int, body text);
create table m_cap(id bigint primary key, owner int, body text);
select cdb.track('m_cap');
\timing on
\echo --- 2000 single-row inserts, plain then captured (ms total)
do $$ begin for i in 1..2000 loop insert into m_plain values (i, i % 10, 'x'); end loop; end $$;
do $$ begin for i in 1..2000 loop insert into m_cap values (i, i % 10, 'x'); end loop; end $$;
\echo --- one insert of 100,000 rows, plain then captured
insert into m_plain select g, 1, repeat('x', 50) from generate_series(10001, 110000) g;
insert into m_cap select g, 1, repeat('x', 50) from generate_series(10001, 110000) g;
\echo --- one update of 100,000 rows, plain then captured
update m_plain set owner = owner + 1 where id > 10000;
update m_cap set owner = owner + 1 where id > 10000;
\echo --- one delete of 100,000 rows, plain then captured
delete from m_plain where id > 10000;
delete from m_cap where id > 10000;
\timing off
select pg_size_pretty(pg_total_relation_size('cdb.delta')) as delta_size, count(*) as delta_rows from cdb.delta where tbl = 'm_cap';
\echo --- the net facts of the 100,000-row update, as one transaction (ms)
\timing on
begin;
update m_cap set owner = owner + 1 where id <= 2000;
select length(cdb.facts(txid_current())) as facts_text_bytes;
rollback;
\timing off
drop table m_plain, m_cap;
delete from cdb.delta where tbl in ('m_cap');
