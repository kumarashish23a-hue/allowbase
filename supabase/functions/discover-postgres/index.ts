// supabase/functions/discover-postgres/index.ts
//
// Discovers the schema of a connected PostgreSQL database and imports it
// into the Data Control Plane catalog.
//
// - Validates the caller's JWT (Supabase Auth) and requires an
//   owner/admin/security role in the organization (RLS enforces this too).
// - The database password is supplied per discovery run, used once over TLS,
//   and never stored, logged, or returned.
// - Only metadata is read (table/column names, types, row estimates). No row
//   data is ever selected or persisted. The session is set read-only as
//   defense in depth.
// - Discovered tables are upserted into data_assets (asset_type 'table') with
//   their columns in metadata. Every column is classified by the deterministic
//   rules engine (pattern/semantic-name rules); low-confidence or unmatched
//   columns are flagged for human review. Re-discovery preserves any
//   classification labels the user already set manually.
// - Sensitive columns produce open findings in sensitive_data_findings.
//
// Deploy: supabase functions deploy discover-postgres

import { serve } from 'https://deno.land/std@0.224.0/http/server.ts';
import { createClient } from 'https://esm.sh/@supabase/supabase-js@2.44.4';
import { Client } from 'https://deno.land/x/postgres@v0.17.0/mod.ts';
import {
  CLASSIFIER_VERSION,
  classifyColumn,
  rollupAsset,
} from '../_shared/classify.ts';
import type { ClassifiedColumn } from '../_shared/classify.ts';
import { refreshFindings } from '../_shared/findings.ts';

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
};

interface DiscoverPayload {
  organization_id: string;
  source_id: string;
  password: string;
}

interface ConnectionConfig {
  host: string;
  port: number;
  database: string;
  username: string;
}

const UUID_RE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const DISCOVER_TIMEOUT_MS = 60000;
const MAX_TABLES = 2000;
const MAX_COLUMNS = 20000;

const TABLES_QUERY = `
  select table_schema, table_name, table_type
  from information_schema.tables
  where table_schema not in ('pg_catalog', 'information_schema')
    and table_type in ('BASE TABLE', 'VIEW')
  order by table_schema, table_name
  limit ${MAX_TABLES};
`;

const COLUMNS_QUERY = `
  select table_schema, table_name, column_name, data_type, is_nullable, ordinal_position
  from information_schema.columns
  where table_schema not in ('pg_catalog', 'information_schema')
  order by table_schema, table_name, ordinal_position
  limit ${MAX_COLUMNS};
`;

const ROW_ESTIMATES_QUERY = `
  select schemaname, relname, n_live_tup
  from pg_stat_user_tables;
`;

function badRequest(message: string): Response {
  return new Response(JSON.stringify({ error: message }), {
    status: 400,
    headers: { ...corsHeaders, 'Content-Type': 'application/json' },
  });
}

function forbidden(message: string): Response {
  return new Response(JSON.stringify({ error: message }), {
    status: 403,
    headers: { ...corsHeaders, 'Content-Type': 'application/json' },
  });
}

function configFromMetadata(metadata: unknown): ConnectionConfig | null {
  if (!metadata || typeof metadata !== 'object') return null;
  const m = metadata as Record<string, unknown>;
  if (
    typeof m.host !== 'string' ||
    typeof m.port !== 'number' ||
    typeof m.database !== 'string' ||
    typeof m.username !== 'string'
  ) {
    return null;
  }
  return { host: m.host, port: m.port, database: m.database, username: m.username };
}

serve(async (req: Request): Promise<Response> => {
  if (req.method === 'OPTIONS') {
    return new Response('ok', { headers: corsHeaders });
  }
  if (req.method !== 'POST') {
    return new Response(JSON.stringify({ error: 'Method not allowed' }), {
      status: 405,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    });
  }

  const supabaseUrl = Deno.env.get('SUPABASE_URL');
  const supabaseAnonKey = Deno.env.get('SUPABASE_ANON_KEY');
  if (!supabaseUrl || !supabaseAnonKey) {
    return new Response(JSON.stringify({ error: 'Server misconfigured' }), {
      status: 500,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    });
  }

  // 1. Authenticate the caller from the Authorization header.
  const authHeader = req.headers.get('Authorization');
  if (!authHeader?.startsWith('Bearer ')) {
    return new Response(JSON.stringify({ error: 'Missing authorization' }), {
      status: 401,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    });
  }

  const supabase = createClient(supabaseUrl, supabaseAnonKey, {
    global: { headers: { Authorization: authHeader } },
    auth: { persistSession: false },
  });

  const {
    data: { user },
    error: userError,
  } = await supabase.auth.getUser();
  if (userError || !user) {
    return new Response(JSON.stringify({ error: 'Invalid or expired session' }), {
      status: 401,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    });
  }

  // 2. Validate input (never trust the client).
  let body: DiscoverPayload;
  try {
    body = await req.json();
  } catch {
    return badRequest('Request body must be valid JSON.');
  }
  const { organization_id, source_id, password } = body;
  if (!organization_id || !UUID_RE.test(organization_id)) return badRequest('organization_id must be a UUID.');
  if (!source_id || !UUID_RE.test(source_id)) return badRequest('source_id must be a UUID.');
  if (!password || typeof password !== 'string' || password.length === 0 || password.length > 500) {
    return badRequest('password is required.');
  }

  // 3. Discovery is privileged: owner, admin, or security only.
  const { data: privileged, error: roleError } = await supabase.rpc('has_org_role', {
    org_id: organization_id,
    allowed: ['owner', 'admin', 'security'],
  });
  if (roleError || !privileged) {
    return forbidden('Running discovery requires the owner, admin, or security role.');
  }

  // 4. Load the source and its (non-secret) connection config.
  const { data: source, error: sourceError } = await supabase
    .from('data_sources')
    .select('id,type,status,metadata')
    .eq('id', source_id)
    .eq('organization_id', organization_id)
    .single();
  if (sourceError || !source) {
    return new Response(JSON.stringify({ error: 'Data source not found.' }), {
      status: 404,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    });
  }
  if (source.type !== 'postgresql') {
    return badRequest('Discovery currently supports PostgreSQL sources only.');
  }
  const config = configFromMetadata(source.metadata);
  if (!config) {
    return new Response(JSON.stringify({ error: 'This source has no connection details saved.' }), {
      status: 500,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    });
  }

  // 5. Connect and read metadata only. The session is set read-only so that
  //    even a bug in this function cannot write to the customer's database.
  //    The password lives only in this request's memory.
  const client = new Client({
    hostname: config.host,
    port: config.port,
    database: config.database,
    user: config.username,
    password,
    tls: { enabled: true, enforce: false },
    connection: { attempts: 1 },
  });

  let timer: number | undefined;
  type TableRow = { table_schema: string; table_name: string; table_type: string };
  type ColumnRow = {
    table_schema: string;
    table_name: string;
    column_name: string;
    data_type: string;
    is_nullable: string;
    ordinal_position: number;
  };
  let tables: TableRow[] = [];
  let columns: ColumnRow[] = [];
  const rowEstimates = new Map<string, number>();
  try {
    const timeout = new Promise<never>((_, reject) => {
      timer = setTimeout(() => reject(new Error('Discovery timed out.')), DISCOVER_TIMEOUT_MS);
    });
    await Promise.race([
      (async () => {
        await client.connect();
        await client.queryObject('set default_transaction_read_only = on');
        const tablesRes = await client.queryObject<TableRow>(TABLES_QUERY);
        tables = tablesRes.rows;
        const columnsRes = await client.queryObject<ColumnRow>(COLUMNS_QUERY);
        columns = columnsRes.rows;
        try {
          const estRes = await client.queryObject<{ schemaname: string; relname: string; n_live_tup: number }>(
            ROW_ESTIMATES_QUERY,
          );
          for (const row of estRes.rows) {
            rowEstimates.set(`${row.schemaname}.${row.relname}`, Number(row.n_live_tup) || 0);
          }
        } catch {
          // Row estimates are best-effort; discovery continues without them.
        }
      })(),
      timeout,
    ]);
  } catch (err) {
    const detail = err instanceof Error ? err.message : 'unknown error';
    return new Response(
      JSON.stringify({ error: `Discovery failed (${detail}). Check the password and network access.` }),
      { status: 502, headers: { ...corsHeaders, 'Content-Type': 'application/json' } },
    );
  } finally {
    if (timer !== undefined) clearTimeout(timer);
    await client.end().catch(() => {});
  }

  // 6. Upsert one data_assets row per table. Existing classification and
  //    sensitivity labels are preserved on re-discovery.
  const columnsByTable = new Map<string, ColumnRow[]>();
  for (const col of columns) {
    const key = `${col.table_schema}.${col.table_name}`;
    const list = columnsByTable.get(key) ?? [];
    list.push(col);
    columnsByTable.set(key, list);
  }

  const { data: existingAssets, error: existingError } = await supabase
    .from('data_assets')
    .select('id,name,classification,sensitivity_level,metadata')
    .eq('organization_id', organization_id)
    .eq('data_source_id', source_id);
  if (existingError) {
    return new Response(JSON.stringify({ error: 'Could not read the existing catalog.' }), {
      status: 500,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    });
  }
  const existingByName = new Map(
    ((existingAssets ?? []) as { id: string; name: string }[]).map((a) => [a.name, a.id]),
  );
  const existingMetaByName = new Map(
    ((existingAssets ?? []) as { name: string; metadata: unknown }[]).map((a) => [a.name, a.metadata]),
  );

  // Classify one column with the deterministic rules engine. A column the user
  // already labeled manually keeps the user's verdict; everything else is
  // re-evaluated. Unknown columns are flagged for human review, never guessed.
  function classifyDiscoveredColumn(
    c: ColumnRow,
    manualByName: Map<string, ClassifiedColumn>,
  ): ClassifiedColumn {
    const base = {
      name: c.column_name,
      type: c.data_type,
      nullable: c.is_nullable === 'YES',
      position: c.ordinal_position,
    };
    const manual = manualByName.get(c.column_name);
    if (manual) return { ...base, ...pickVerdict(manual), classified_by: 'manual' };
    const verdict = classifyColumn(c.column_name);
    if (!verdict) {
      return {
        ...base,
        classification: 'internal',
        sensitivity: 'none',
        confidence: null,
        rule: null,
        category: null,
        needs_review: true,
        classified_by: CLASSIFIER_VERSION,
      };
    }
    return {
      ...base,
      classification: verdict.classification,
      sensitivity: verdict.sensitivity,
      confidence: verdict.confidence,
      rule: verdict.rule,
      category: verdict.category,
      needs_review: verdict.needs_review,
      classified_by: CLASSIFIER_VERSION,
    };
  }

  function pickVerdict(manual: ClassifiedColumn): Omit<ClassifiedColumn, 'name' | 'type' | 'nullable' | 'position' | 'classified_by'> {
    return {
      classification: manual.classification,
      sensitivity: manual.sensitivity,
      confidence: manual.confidence,
      rule: manual.rule,
      category: manual.category,
      needs_review: manual.needs_review,
    };
  }

  const discoveredAt = new Date().toISOString();
  let inserted = 0;
  let updated = 0;
  let findingsWritten = 0;
  let columnsNeedReview = 0;
  for (const table of tables) {
    const key = `${table.table_schema}.${table.table_name}`;
    const rawColumns = columnsByTable.get(key) ?? [];

    // Manual column labels survive re-discovery.
    const manualByName = new Map<string, ClassifiedColumn>();
    const existingMeta = existingMetaByName.get(key) as { columns?: unknown; classification_source?: string } | undefined;
    if (existingMeta && Array.isArray(existingMeta.columns)) {
      for (const col of existingMeta.columns as ClassifiedColumn[]) {
        if (col && typeof col.name === 'string' && col.classified_by === 'manual') {
          manualByName.set(col.name, col);
        }
      }
    }

    const tableColumns = rawColumns.map((c) => classifyDiscoveredColumn(c, manualByName));
    columnsNeedReview += tableColumns.filter((c) => c.needs_review).length;
    const rollup = rollupAsset(tableColumns, { classification: 'internal', sensitivity: 'none' });
    const metadata = {
      schema: table.table_schema,
      table: table.table_name,
      table_type: table.table_type,
      columns: tableColumns,
      column_count: tableColumns.length,
      row_estimate: rowEstimates.has(key) ? rowEstimates.get(key) : null,
      discovered_at: discoveredAt,
      discovered_by: 'postgres-connector',
      classification_source: CLASSIFIER_VERSION,
      classified_at: discoveredAt,
      columns_need_review: tableColumns.filter((c) => c.needs_review).length,
    };
    const existingId = existingByName.get(key);
    let assetId: string | undefined;
    if (existingId) {
      // Re-discovery refreshes structure and classification, but an asset the
      // user labeled manually at asset level keeps the user's labels.
      const assetLevelManual = existingMeta?.classification_source === 'manual';
      const patch: Record<string, unknown> = { metadata, last_scanned_at: discoveredAt };
      if (!assetLevelManual) {
        patch.classification = rollup.classification;
        patch.sensitivity_level = rollup.sensitivity;
      }
      const { error: updateError } = await supabase
        .from('data_assets')
        .update(patch)
        .eq('id', existingId);
      if (updateError) {
        return new Response(
          JSON.stringify({ error: `Could not update the catalog entry for ${key}.` }),
          { status: 500, headers: { ...corsHeaders, 'Content-Type': 'application/json' } },
        );
      }
      assetId = existingId;
      updated += 1;
    } else {
      const { data: insertedRow, error: insertError } = await supabase
        .from('data_assets')
        .insert({
          organization_id,
          data_source_id: source_id,
          name: key,
          asset_type: 'table',
          classification: rollup.classification,
          sensitivity_level: rollup.sensitivity,
          metadata,
          last_scanned_at: discoveredAt,
        })
        .select('id')
        .single();
      if (insertError) {
        return new Response(
          JSON.stringify({ error: `Could not add the catalog entry for ${key}.` }),
          { status: 500, headers: { ...corsHeaders, 'Content-Type': 'application/json' } },
        );
      }
      assetId = (insertedRow as { id: string }).id;
      inserted += 1;
    }

    // Refresh this classifier's open findings for the asset.
    try {
      findingsWritten += await refreshFindings(supabase, organization_id, assetId as string, key, tableColumns);
    } catch (e) {
      return new Response(
        JSON.stringify({ error: e instanceof Error ? e.message : 'Could not record findings.' }),
        { status: 500, headers: { ...corsHeaders, 'Content-Type': 'application/json' } },
      );
    }
  }

  // 7. Record the discovery on the source.
  const totalColumns = tables.reduce(
    (sum, t) => sum + (columnsByTable.get(`${t.table_schema}.${t.table_name}`) ?? []).length,
    0,
  );
  await supabase
    .from('data_sources')
    .update({
      status: 'connected',
      last_scan_at: discoveredAt,
      metadata: {
        ...(source.metadata as Record<string, unknown>),
        discovered: true,
        table_count: tables.length,
        column_count: totalColumns,
        last_discovery_at: discoveredAt,
      },
    })
    .eq('id', source_id);

  return new Response(
    JSON.stringify({
      tables: tables.length,
      columns: totalColumns,
      inserted,
      updated,
      truncated: tables.length >= MAX_TABLES,
      findings: findingsWritten,
      columns_need_review: columnsNeedReview,
      classifier: CLASSIFIER_VERSION,
      discovered_at: discoveredAt,
    }),
    { status: 200, headers: { ...corsHeaders, 'Content-Type': 'application/json' } },
  );
});
