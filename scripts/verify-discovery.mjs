// Validates the exact discovery queries used by the discover-postgres Edge Function
// against in-memory Postgres (PGlite): syntax, shape, and row mapping.
import { PGlite } from '@electric-sql/pglite';

const db = new PGlite();
await db.exec(`
  create schema app;
  create table app.customers (id uuid primary key, email text not null, created_at timestamptz);
  create table app.orders (id bigint generated always as identity primary key, customer_id uuid, total numeric(10,2));
  create view app.vip_customers as select id, email from app.customers;
`);

const TABLES_QUERY = `
  select table_schema, table_name, table_type
  from information_schema.tables
  where table_schema not in ('pg_catalog', 'information_schema')
    and table_type in ('BASE TABLE', 'VIEW')
  order by table_schema, table_name
  limit 2000;
`;
const COLUMNS_QUERY = `
  select table_schema, table_name, column_name, data_type, is_nullable, ordinal_position
  from information_schema.columns
  where table_schema not in ('pg_catalog', 'information_schema')
  order by table_schema, table_name, ordinal_position
  limit 20000;
`;

const tables = await db.query(TABLES_QUERY);
const columns = await db.query(COLUMNS_QUERY);
const names = tables.rows.map((r) => `${r.table_schema}.${r.table_name} (${r.table_type})`);
console.log('tables:', JSON.stringify(names));
console.log('column count:', columns.rows.length);
const first = columns.rows[0];
console.log('first column row keys:', Object.keys(first).join(','));
const byTable = new Map();
for (const c of columns.rows) {
  const k = `${c.table_schema}.${c.table_name}`;
  byTable.set(k, [...(byTable.get(k) ?? []), { name: c.column_name, type: c.data_type, nullable: c.is_nullable === 'YES', position: c.ordinal_position }]);
}
console.log('app.customers columns:', JSON.stringify(byTable.get('app.customers')));
let estimatesOk = true;
try {
  const est = await db.query('select schemaname, relname, n_live_tup from pg_stat_user_tables;');
  console.log('row estimates rows:', est.rows.length);
} catch (e) {
  estimatesOk = false;
  console.log('row estimates unavailable (best-effort path):', e.message.slice(0, 80));
}
const assert = (cond, msg) => { if (!cond) { console.error('FAIL:', msg); process.exitCode = 1; } else console.log('ok:', msg); };
assert(names.includes('app.customers (BASE TABLE)'), 'discovers base tables');
assert(names.includes('app.vip_customers (VIEW)'), 'discovers views');
assert(!names.some((n) => n.startsWith('pg_catalog.') || n.startsWith('information_schema.')), 'excludes system schemas');
assert(byTable.get('app.customers').length === 3, 'maps all columns of app.customers');
assert(byTable.get('app.customers')[1].name === 'email' && byTable.get('app.customers')[1].nullable === false, 'nullable mapping correct');
assert(estimatesOk, 'pg_stat_user_tables readable');
