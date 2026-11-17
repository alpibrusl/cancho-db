// node-postgres through the proxy (tests/drivers_e2e.py): node drivers_node.js PORT USER PASSWORD DATABASE
const { Client } = require('pg');
const [port, user, password, database] = process.argv.slice(2);
(async () => {
  const c = new Client({ host: '127.0.0.1', port: +port, user, password, database });
  await c.connect();
  const r = await c.query('select b from xe where a = $1', [1]);
  await c.query({ name: 'named', text: 'select b from xe where a = $1', values: [1] });
  const r2 = await c.query({ name: 'named', text: 'select b from xe where a = $1', values: [2] });
  await c.query('begin'); await c.query('insert into xo values ($1, $2)', [700, 'n']); await c.query('commit');
  console.log(r.rows[0].b, r2.rows[0].b);
  await c.end();
})().catch((e) => { console.error(e.message); process.exit(1); });
