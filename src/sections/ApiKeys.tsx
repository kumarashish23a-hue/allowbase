import { Check, Copy, KeyRound, Plus, ShieldAlert } from 'lucide-react';
import { useEffect, useState } from 'react';
import { Modal } from '../components/Modal';
import { Reveal } from '../components/Reveal';
import { SectionHeading } from '../components/SectionHeading';
import { getActiveOrganizationId, getSupabase, isSupabaseConfigured } from '../lib/supabase';
import {
  createApiKey,
  getIngestEndpoint,
  listApiKeys,
  revokeApiKey,
  type ApiKeyItem,
  type CreatedApiKey,
} from '../services/apiKeysService';
import { getMyOrganizationRole } from '../services/organizationService';

const EXPIRIES = [
  { label: 'Never expires', days: 0 },
  { label: '30 days', days: 30 },
  { label: '90 days', days: 90 },
  { label: '1 year', days: 365 },
];

function formatDate(value: string | null): string {
  if (!value) return '—';
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleDateString();
}

function keyStatus(key: ApiKeyItem): { label: string; tone: string } {
  if (key.revoked_at) return { label: 'Revoked', tone: 'border-line text-mist-500' };
  if (key.expires_at && new Date(key.expires_at) <= new Date())
    return { label: 'Expired', tone: 'border-amber-400/30 bg-amber-400/10 text-amber-400' };
  return { label: 'Active', tone: 'border-mint-400/30 bg-mint-400/10 text-mint-400' };
}

function CopyButton({ text, label }: { text: string; label: string }) {
  const [copied, setCopied] = useState(false);
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(text);
    } catch {
      const textarea = document.createElement('textarea');
      textarea.value = text;
      document.body.appendChild(textarea);
      textarea.select();
      document.execCommand('copy');
      document.body.removeChild(textarea);
    }
    setCopied(true);
    window.setTimeout(() => setCopied(false), 1600);
  };
  return (
    <button
      type="button"
      onClick={copy}
      aria-label={label}
      className="inline-flex items-center gap-1.5 rounded-lg border border-line px-2.5 py-1.5 text-xs text-mist-300 transition hover:border-line-strong hover:text-mist-100"
    >
      {copied ? <Check size={13} className="text-mint-400" /> : <Copy size={13} />}
      {copied ? 'Copied' : 'Copy'}
    </button>
  );
}

export function ApiKeys() {
  const [signedIn, setSignedIn] = useState<boolean | null>(null);
  const [keys, setKeys] = useState<ApiKeyItem[]>([]);
  const [canManage, setCanManage] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [createOpen, setCreateOpen] = useState(false);
  const [keyName, setKeyName] = useState('');
  const [expiryDays, setExpiryDays] = useState(0);
  const [creating, setCreating] = useState(false);
  const [created, setCreated] = useState<CreatedApiKey | null>(null);
  const [confirmRevoke, setConfirmRevoke] = useState<string | null>(null);
  const [revoking, setRevoking] = useState(false);
  const endpoint = getIngestEndpoint();

  const reload = async () => {
    try {
      const loaded = await listApiKeys();
      setKeys(loaded);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not load API keys.');
    }
  };

  useEffect(() => {
    let cancelled = false;
    (async () => {
      if (!isSupabaseConfigured()) {
        if (!cancelled) setSignedIn(false);
        return;
      }
      const supabase = getSupabase();
      const {
        data: { session },
      } = await supabase!.auth.getSession();
      if (!session) {
        if (!cancelled) setSignedIn(false);
        return;
      }
      if (!cancelled) setSignedIn(true);
      try {
        const orgId = await getActiveOrganizationId();
        if (cancelled) return;
        if (orgId) {
          const role = await getMyOrganizationRole(orgId);
          if (!cancelled) setCanManage(role === 'owner' || role === 'admin');
        }
        await reload();
      } catch (err) {
        if (!cancelled) setError(err instanceof Error ? err.message : 'Could not load API keys.');
      }
    })();
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const closeCreate = () => {
    setCreateOpen(false);
    setCreated(null);
    setKeyName('');
    setExpiryDays(0);
    setError(null);
  };

  const handleCreate = async () => {
    if (!keyName.trim() || creating) return;
    setCreating(true);
    setError(null);
    try {
      const expiresAt =
        expiryDays > 0 ? new Date(Date.now() + expiryDays * 86400000).toISOString() : null;
      const result = await createApiKey(keyName, expiresAt);
      setCreated(result);
      await reload();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not create the API key.');
    } finally {
      setCreating(false);
    }
  };

  const handleRevoke = async (id: string) => {
    if (confirmRevoke !== id) {
      setConfirmRevoke(id);
      return;
    }
    setRevoking(true);
    setError(null);
    try {
      await revokeApiKey(id);
      setConfirmRevoke(null);
      await reload();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not revoke the API key.');
    } finally {
      setRevoking(false);
    }
  };

  const curlExample = `curl -X POST ${endpoint ?? 'https://<project>.supabase.co/functions/v1/ingest-event'} \\
  -H "x-api-key: dcp_live_..." \\
  -H "Content-Type: application/json" \\
  -d '{
    "event_id": "evt_9f32c1",
    "model_name": "support-copilot",
    "purpose": "customer-support",
    "data_asset_ids": ["<asset-uuid>"]
  }'
# → {"decision":"allow","risk":"low", ...}
# Check-mode: only call the model when decision is "allow".`;

  return (
    <section id="api-keys" className="border-y border-line bg-ink-900/40">
      <div className="mx-auto max-w-7xl px-4 py-20 sm:px-6 lg:px-8 lg:py-28">
        <SectionHeading
          eyebrow="API keys"
          title="The front door to AllowBase."
          description="Machine keys let your backend ask for a decision before calling a model. A key authenticates the organization; every call runs the same deterministic policy engine and lands in the audit log."
        />

        <div className="mt-12">
          {signedIn === false ? (
            <div className="rounded-xl border border-line bg-ink-950/60 p-8 text-center">
              <p className="text-sm text-mist-300">Sign in to manage API keys for your workspace.</p>
            </div>
          ) : signedIn === null && !error ? (
            <div className="rounded-xl border border-line bg-ink-950/60 p-8">
              <p className="text-sm text-mist-500">Loading API keys…</p>
            </div>
          ) : error && keys.length === 0 ? (
            <div className="rounded-xl border border-rose-400/30 bg-ink-950/60 p-8">
              <p className="text-xs font-semibold uppercase tracking-[0.18em] text-rose-400">
                Could not load API keys
              </p>
              <p className="mt-2 text-sm text-mist-300">{error}</p>
            </div>
          ) : (
            <div className="space-y-6">
              <Reveal>
                <div className="overflow-hidden rounded-xl border border-line bg-ink-950/60">
                  <div className="flex items-center justify-between gap-4 border-b border-line px-5 py-4">
                    <div className="flex items-center gap-2">
                      <KeyRound size={15} className="text-accent-600" />
                      <h3 className="text-sm font-semibold uppercase tracking-[0.18em] text-mist-400">
                        Keys ({keys.length})
                      </h3>
                    </div>
                    {canManage ? (
                      <button
                        type="button"
                        onClick={() => setCreateOpen(true)}
                        className="btn-primary inline-flex items-center gap-1.5 rounded-lg px-3.5 py-2 text-sm font-semibold"
                      >
                        <Plus size={14} />
                        New key
                      </button>
                    ) : null}
                  </div>
                  {!canManage ? (
                    <p className="border-b border-line px-5 py-3 text-xs text-mist-500">
                      Key management needs the owner or admin role. Members can see key metadata below.
                    </p>
                  ) : null}
                  {keys.length === 0 ? (
                    <p className="px-5 py-8 text-center text-sm text-mist-500">
                      No keys yet. Create one to let your backend ask AllowBase for decisions.
                    </p>
                  ) : (
                    <ul className="divide-y divide-line">
                      {keys.map((key) => {
                        const status = keyStatus(key);
                        const live = !key.revoked_at && !(key.expires_at && new Date(key.expires_at) <= new Date());
                        return (
                          <li key={key.id} className="flex flex-wrap items-center gap-x-6 gap-y-3 px-5 py-4">
                            <div className="min-w-0 flex-1">
                              <p className="truncate text-sm font-semibold text-mist-100">{key.name}</p>
                              <p className="mt-0.5 font-mono text-xs text-mist-500">
                                {key.key_prefix}… · created {formatDate(key.created_at)}
                                {key.last_used_at ? ` · last used ${formatDate(key.last_used_at)}` : ' · never used'}
                                {key.expires_at ? ` · expires ${formatDate(key.expires_at)}` : ''}
                              </p>
                            </div>
                            <span
                              className={`rounded-full border px-2.5 py-1 text-xs font-medium ${status.tone}`}
                            >
                              {status.label}
                            </span>
                            {canManage && live ? (
                              <button
                                type="button"
                                disabled={revoking}
                                onClick={() => void handleRevoke(key.id)}
                                className={`rounded-lg border px-3 py-1.5 text-xs font-medium transition ${
                                  confirmRevoke === key.id
                                    ? 'border-rose-400/50 bg-rose-400/10 text-rose-400 hover:bg-rose-400/20'
                                    : 'border-line text-mist-400 hover:border-line-strong hover:text-mist-100'
                                }`}
                              >
                                {confirmRevoke === key.id ? 'Confirm revoke' : 'Revoke'}
                              </button>
                            ) : null}
                          </li>
                        );
                      })}
                    </ul>
                  )}
                </div>
              </Reveal>

              <Reveal>
                <div className="overflow-hidden rounded-xl border border-line bg-ink-950/80">
                  <div className="flex items-center justify-between border-b border-line px-4 py-3">
                    <p className="text-xs font-semibold uppercase tracking-[0.18em] text-mist-500">
                      Call it before the model
                    </p>
                    <CopyButton text={curlExample} label="Copy curl example" />
                  </div>
                  <pre className="code-block thin-scroll overflow-x-auto p-5 text-mist-200">{curlExample}</pre>
                </div>
              </Reveal>
            </div>
          )}
        </div>
      </div>

      <Modal
        open={createOpen}
        onClose={closeCreate}
        title={created ? 'Key created' : 'Create API key'}
        subtitle={
          created
            ? 'Copy it now — it will never be shown again.'
            : 'The plaintext is shown once. Only a hash is stored.'
        }
      >
        {created ? (
          <div className="space-y-4">
            <div className="rounded-xl border border-amber-400/30 bg-amber-400/10 p-4">
              <div className="flex items-start gap-2.5">
                <ShieldAlert size={16} className="mt-0.5 shrink-0 text-amber-400" />
                <p className="text-sm text-mist-200">
                  This is the only time you will see this key. Store it in your backend's secret
                  manager now — it cannot be recovered later.
                </p>
              </div>
            </div>
            <div className="flex items-center justify-between gap-3 rounded-xl border border-line bg-ink-950/80 px-4 py-3">
              <code className="thin-scroll overflow-x-auto font-mono text-sm text-mist-100">{created.key}</code>
              <CopyButton text={created.key} label="Copy API key" />
            </div>
            <button type="button" onClick={closeCreate} className="btn-primary w-full rounded-lg px-4 py-2.5 text-sm font-semibold">
              I've stored it safely
            </button>
          </div>
        ) : (
          <div className="space-y-5">
            {error ? <p className="text-sm text-rose-400">{error}</p> : null}
            <div>
              <label htmlFor="api-key-name" className="mb-1.5 block text-sm font-medium text-mist-200">
                Key name
              </label>
              <input
                id="api-key-name"
                type="text"
                value={keyName}
                onChange={(event) => setKeyName(event.target.value)}
                placeholder="Production backend"
                maxLength={100}
                className="w-full rounded-lg border border-line bg-ink-950/60 px-3.5 py-2.5 text-sm text-mist-100 placeholder:text-mist-600 focus:border-accent-400 focus:outline-none"
              />
            </div>
            <div>
              <label htmlFor="api-key-expiry" className="mb-1.5 block text-sm font-medium text-mist-200">
                Expires
              </label>
              <select
                id="api-key-expiry"
                value={expiryDays}
                onChange={(event) => setExpiryDays(Number(event.target.value))}
                className="w-full rounded-lg border border-line bg-ink-950/60 px-3.5 py-2.5 text-sm text-mist-100 focus:border-accent-400 focus:outline-none"
              >
                {EXPIRIES.map((option) => (
                  <option key={option.days} value={option.days}>
                    {option.label}
                  </option>
                ))}
              </select>
            </div>
            <button
              type="button"
              onClick={() => void handleCreate()}
              disabled={!keyName.trim() || creating}
              className="btn-primary w-full rounded-lg px-4 py-2.5 text-sm font-semibold disabled:cursor-not-allowed disabled:opacity-50"
            >
              {creating ? 'Creating…' : 'Create key'}
            </button>
          </div>
        )}
      </Modal>
    </section>
  );
}
