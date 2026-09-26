// supabase/functions/classify-assets/index.ts
//
// Re-runs the deterministic column classifier over catalog assets.
//
// - Validates the caller's JWT (Supabase Auth) and requires an
//   owner/admin/security role in the organization (RLS enforces this too).
// - Scope: one asset (asset_id), one source (source_id), or the whole
//   organization's catalog. Only assets with discovered columns are touched.
// - Columns the user labeled manually are never overwritten; their verdict
//   feeds the asset rollup instead.
// - Optional `overrides` (asset scope only) apply manual column labels:
//     { column_name, classification } — the user is the source of truth.
// - Refreshes this classifier's open findings per asset; human-resolved or
//   ignored findings are never touched.
//
// Deploy: supabase functions deploy classify-assets

import { serve } from 'https://deno.land/std@0.224.0/http/server.ts';
import { createClient } from 'https://esm.sh/@supabase/supabase-js@2.44.4';
import {
  CLASSIFIER_VERSION,
  classifyColumn,
  rollupAsset,
} from '../_shared/classify.ts';
import type {
  Classification,
  ClassifiedColumn,
  Sensitivity,
} from '../_shared/classify.ts';
import { refreshFindings } from '../_shared/findings.ts';

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
};

interface OverrideInput {
  column_name: string;
  classification: string;
}

interface ClassifyPayload {
  organization_id: string;
  source_id?: string;
  asset_id?: string;
  overrides?: OverrideInput[];
}

const UUID_RE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const VALID_CLASSIFICATIONS: Classification[] = ['public', 'internal', 'confidential', 'restricted'];
const MANUAL_SENSITIVITY: Record<Classification, Sensitivity> = {
  public: 'none',
  internal: 'low',
  confidential: 'high',
  restricted: 'critical',
};

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
  let body: ClassifyPayload;
  try {
    body = await req.json();
  } catch {
    return badRequest('Request body must be valid JSON.');
  }
  const { organization_id, source_id, asset_id, overrides } = body;
  if (!organization_id || !UUID_RE.test(organization_id)) {
    return badRequest('organization_id must be a UUID.');
  }
  if (source_id !== undefined && !UUID_RE.test(source_id)) {
    return badRequest('source_id must be a UUID when provided.');
  }
  if (asset_id !== undefined && !UUID_RE.test(asset_id)) {
    return badRequest('asset_id must be a UUID when provided.');
  }
  if (overrides !== undefined) {
    if (!asset_id) return badRequest('overrides require asset_id scope.');
    if (!Array.isArray(overrides) || overrides.length > 500) {
      return badRequest('overrides must be an array of at most 500 entries.');
    }
    for (const o of overrides) {
      if (!o || typeof o.column_name !== 'string' || o.column_name.length === 0 || o.column_name.length > 200) {
        return badRequest('Each override needs a column_name (max 200 chars).');
      }
      if (!VALID_CLASSIFICATIONS.includes(o.classification as Classification)) {
        return badRequest(`Invalid classification "${o.classification}".`);
      }
    }
  }

  // 3. Classification is privileged: owner, admin, or security only.
  const { data: privileged, error: roleError } = await supabase.rpc('has_org_role', {
    org_id: organization_id,
    allowed: ['owner', 'admin', 'security'],
  });
  if (roleError || !privileged) {
    return forbidden('Running classification requires the owner, admin, or security role.');
  }

  // 4. Load in-scope assets that have discovered columns.
  let query = supabase
    .from('data_assets')
    .select('id,name,metadata')
    .eq('organization_id', organization_id);
  if (asset_id) query = query.eq('id', asset_id);
  else if (source_id) query = query.eq('data_source_id', source_id);
  const { data: assets, error: assetsError } = await query;
  if (assetsError) {
    return new Response(JSON.stringify({ error: 'Could not read the catalog.' }), {
      status: 500,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    });
  }

  const overrideByName = new Map<string, Classification>();
  for (const o of overrides ?? []) overrideByName.set(o.column_name, o.classification as Classification);

  const classifiedAt = new Date().toISOString();
  let assetsProcessed = 0;
  let columnsClassified = 0;
  let columnsNeedReview = 0;
  let findingsWritten = 0;

  for (const asset of (assets ?? []) as { id: string; name: string; metadata: unknown }[]) {
    const meta = (asset.metadata ?? {}) as { columns?: unknown; classification_source?: string };
    if (!Array.isArray(meta.columns) || meta.columns.length === 0) continue;

    const finalColumns: ClassifiedColumn[] = [];
    for (const raw of meta.columns as Record<string, unknown>[]) {
      const name = typeof raw.name === 'string' ? raw.name : '';
      if (!name) continue;
      const base = {
        name,
        type: typeof raw.type === 'string' ? raw.type : undefined,
        nullable: typeof raw.nullable === 'boolean' ? raw.nullable : undefined,
        position: typeof raw.position === 'number' ? raw.position : undefined,
      };

      const override = overrideByName.get(name);
      if (override) {
        finalColumns.push({
          ...base,
          classification: override,
          sensitivity: MANUAL_SENSITIVITY[override],
          confidence: 1,
          rule: 'Manual label',
          category: 'contact',
          needs_review: false,
          classified_by: 'manual',
        });
        continue;
      }
      if (raw.classified_by === 'manual') {
        // The user's verdict stands; keep it verbatim.
        finalColumns.push({
          ...base,
          classification: VALID_CLASSIFICATIONS.includes(raw.classification as Classification)
            ? (raw.classification as Classification)
            : 'internal',
          sensitivity: (raw.sensitivity as Sensitivity) ?? 'low',
          confidence: typeof raw.confidence === 'number' ? raw.confidence : 1,
          rule: typeof raw.rule === 'string' ? raw.rule : 'Manual label',
          category: typeof raw.category === 'string' ? raw.category : 'contact',
          needs_review: false,
          classified_by: 'manual',
        });
        continue;
      }
      const verdict = classifyColumn(name);
      if (!verdict) {
        finalColumns.push({
          ...base,
          classification: 'internal',
          sensitivity: 'none',
          confidence: null,
          rule: null,
          category: null,
          needs_review: true,
          classified_by: CLASSIFIER_VERSION,
        });
      } else {
        finalColumns.push({
          ...base,
          classification: verdict.classification,
          sensitivity: verdict.sensitivity,
          confidence: verdict.confidence,
          rule: verdict.rule,
          category: verdict.category,
          needs_review: verdict.needs_review,
          classified_by: CLASSIFIER_VERSION,
        });
      }
    }

    columnsClassified += finalColumns.length;
    columnsNeedReview += finalColumns.filter((c) => c.needs_review).length;
    const rollup = rollupAsset(finalColumns, { classification: 'internal', sensitivity: 'none' });
    const newMetadata = {
      ...(meta as Record<string, unknown>),
      columns: finalColumns,
      // Column-level `manual` flags already preserve user intent; the asset
      // rollup stays deterministic so re-discovery keeps working.
      classification_source: CLASSIFIER_VERSION,
      classified_at: classifiedAt,
      columns_need_review: finalColumns.filter((c) => c.needs_review).length,
    };

    const { error: updateError } = await supabase
      .from('data_assets')
      .update({
        metadata: newMetadata,
        classification: rollup.classification,
        sensitivity_level: rollup.sensitivity,
        last_scanned_at: classifiedAt,
      })
      .eq('id', asset.id);
    if (updateError) {
      return new Response(
        JSON.stringify({ error: `Could not update the catalog entry for ${asset.name}.` }),
        { status: 500, headers: { ...corsHeaders, 'Content-Type': 'application/json' } },
      );
    }

    try {
      findingsWritten += await refreshFindings(supabase, organization_id, asset.id, asset.name, finalColumns);
    } catch (e) {
      return new Response(
        JSON.stringify({ error: e instanceof Error ? e.message : 'Could not record findings.' }),
        { status: 500, headers: { ...corsHeaders, 'Content-Type': 'application/json' } },
      );
    }
    assetsProcessed += 1;
  }

  return new Response(
    JSON.stringify({
      assets_processed: assetsProcessed,
      columns_classified: columnsClassified,
      columns_need_review: columnsNeedReview,
      findings: findingsWritten,
      classifier: CLASSIFIER_VERSION,
      classified_at: classifiedAt,
    }),
    { status: 200, headers: { ...corsHeaders, 'Content-Type': 'application/json' } },
  );
});
