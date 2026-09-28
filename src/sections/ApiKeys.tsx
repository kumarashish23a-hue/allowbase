import { Check, Copy, KeyRound, Plus, RefreshCcw, ShieldAlert, Siren } from 'lucide-react';
import { useEffect, useState } from 'react';
import { Modal } from '../components/Modal';
import { Reveal } from '../components/Reveal';
import { SectionHeading } from '../components/SectionHeading';
import { getActiveOrganizationId, getSupabase, isSupabaseConfigured } from '../lib/supabase';
import {
  API_KEY_SCOPES,
  createApiKey,
  getIngestEndpoint,
  listApiKeys,
  parseCidrList,
  revokeAllApiKeys,
  revokeApiKey,
  rotateApiKey,
  type ApiKeyItem,
  type ApiKeyScope,
  type CreatedApiKey,
} from '../services/apiKeysService';
import { getMyOrganizationRole } from '../services/organizationService';

const EXPIRIES = [
  { label: 'Never expires', days: 0 },
  { label: '30 days', days: 30 },
  { label: '90 days', days: 90 },
  { label: '1 year', days: 365 },
];

const GRACE_OPTIONS = [
  { label: 'Revoke the old key immediately', hours: 0 },
  { label: 'Keep the old key for 1 hour', hours: 1 },
  { label: 'Keep the old key for 24 hours', hours: 24 },
  { label: 'Keep the old key for 3 days', hours: 72 },
  { label: 'Keep the old key for 7 days', hours: 168 },
];

const inputCls =
  'w-full rounded-lg border border-line bg-ink-950/60 px-3.5 py-2.5 text-sm text-mist-100 placeholder:text-mist-600 focus:border-accent-400 focus:outline-none';

function formatDate(value: string | null): string {
  if (!value) return '—';
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleDateString();
}

function isLive(key: ApiKeyItem): boolean {
  return !key.revoked_at && !(key.expires_at && new Date(key.expires_at) <= new Date());
}

function keyStatus(key: ApiKeyItem): { label: string; tone: string } {
  if (key.revoked_at) return { label: 'Revoked', tone: 'border-line text-mist-500' };
  if (key.expires_at && new Date(key.expires_at) <= new Date())
    return { label: 'Expired', tone: 'border-amber-400/30 bg-amber-400/10 text-amber-400' };
  if (key.expires_at && new Date(key.expires_at).getTime() - Date.now() < 7 * 86400000)
    return { label: 'Expiring soon', tone: 'border-amber-400/30 bg-amber-400/10 text-amber-400' };
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

function PlaintextKey({ created, onDone }: { created: CreatedApiKey; onDone: () => void }) {
  return (
    <div className="space-y-4">
      <div className="rounded-xl border border-amber-400/30 bg-amber-400/10 p-4">
        <div className="flex items-start gap-2.5">
          <ShieldAlert size={16} className="mt-0.5 shrink-0 text-amber-400" />
          <p className="text-sm text-mist-200">
            This is the only time you will see this key. Store it in your backend&apos;s secret manager now — it
            cannot be recovered later.
            {created.grace_hours !== undefined
              ? created.grace_hours === 0
                ? ' The previous key has been revoked.'
                : ` The previous key keeps working for ${created.grace_hours}h.`
              : ''}
          </p>
        </div>
      </div>
      <div className="flex items-center justify-between gap-3 rounded-xl border border-line bg-ink-950/80 px-4 py-3">
        <code className="thin-scroll overflow-x-auto font-mono text-sm text-mist-100">{created.key}</code>
        <CopyButton text={created.key} label="Copy API key" />
      </div>
      <button type="button" onClick={onDone} className="btn-primary w-full rounded-lg px-4 py-2.5 text-sm font-semibold">
        I&apos;ve stored it safely
      </button>
    </div>
  );
}

export function ApiKeys() {
  const [signedIn, setSignedIn] = useState<boolean | null>(null);
  const [keys, setKeys] = useState<ApiKeyItem[]>([]);
  const [canManage, setCanManage] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [listError, setListError] = useState<string | null>(null);

  const [createOpen, setCreateOpen] = useState(false);
  const [keyName, setKeyName] = useState('');
  const [expiryDays, setExpiryDays] = useState(0);
  const [allowContent, setAllowContent] = useState(true);
  const [cidrText, setCidrText] = useState('');
  const [rateLimit, setRateLimit] = useState(120);
  const [creating, setCreating] = useState(false);
  const [created, setCreated] = useState<CreatedApiKey | null>(null);

  const [rotateTarget, setRotateTarget] = useState<ApiKeyItem | null>(null);
  const [graceHours, setGraceHours] = useState(24);
  const [rotated, setRotated] = useState<CreatedApiKey | null>(null);
  const [rotating, setRotating] = useState(false);

  const [confirmRevoke, setConfirmRevoke] = useState<string | null>(null);
  const [revoking, setRevoking] = useState(false);

  const [emergencyOpen, setEmergencyOpen] = useState(false);
  const [emergencyReason, setEmergencyReason] = useState('');
  const [emergencyConfirm, setEmergencyConfirm] = useState('');
  const [emergencyResult, setEmergencyResult] = useState<number | null>(null);

  const endpoint = getIngestEndpoint();
  const liveCount = keys.filter(isLive).length;

  const reload = async () => {
    try {
      setKeys(await listApiKeys());
      setListError(null);
    } catch (err) {
      setListError(err instanceof Error ? err.message : 'Could not load API keys.');
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
        if (!cancelled) setListError(err instanceof Error ? err.message : 'Could not load API keys.');
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
    setAllowContent(true);
    setCidrText('');
    setRateLimit(120);
    setError(null);
  };

  const handleCreate = async () => {
    if (!keyName.trim() || creating) return;
    const { values, invalid } = parseCidrList(cidrText);
    if (invalid.length > 0) {
      setError(`Not a valid IP or CIDR range: ${invalid.join(', ')}`);
      return;
    }
    if (values.length > 20) {
      setError('At most 20 IP ranges per key.');
      return;
    }
    if (!Number.isInteger(rateLimit) || rateLimit < 1 || rateLimit > 10000) {
      setError('Rate limit must be a whole number between 1 and 10000.');
      return;
    }
    setCreating(true);
    setError(null);
    try {
      const expiresAt = expiryDays > 0 ? new Date(Date.now() + expiryDays * 86400000).toISOString() : null;
      const scopes: ApiKeyScope[] = allowContent ? ['ingest', 'ingest:content'] : ['ingest'];
      setCreated(
        await createApiKey({ name: keyName, expiresAt, scopes, allowedCidrs: values, rateLimitPerMinute: rateLimit }),
      );
      await reload();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not create the API key.');
    } finally {
      setCreating(false);
    }
  };

  const closeRotate = () => {
    setRotateTarget(null);
    setRotated(null);
    setGraceHours(24);
    setError(null);
  };

  const handleRotate = async () => {
    if (!rotateTarget || rotating) return;
    setRotating(true);
    setError(null);
    try {
      const result = await rotateApiKey(rotateTarget.id, graceHours);
      setRotated({ ...result, grace_hours: graceHours });
      await reload();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not rotate the API key.');
    } finally {
      setRotating(false);
    }
  };

  const handleRevoke = async (id: string) => {
    if (confirmRevoke !== id) {
      setConfirmRevoke(id);
      return;
    }
    setRevoking(true);
    setListError(null);
    try {
      await revokeApiKey(id, 'Revoked from console');
      setConfirmRevoke(null);
      await reload();
    } catch (err) {
      setListError(err instanceof Error ? err.message : 'Could not revoke the API key.');
    } finally {
      setRevoking(false);
    }
  };

  const closeEmergency = () => {
    setEmergencyOpen(false);
    setEmergencyReason('');
    setEmergencyConfirm('');
    setEmergencyResult(null);
    setError(null);
  };

  const handleEmergency = async () => {
    if (!emergencyReason.trim() || emergencyConfirm !== 'REVOKE' || revoking) return;
    setRevoking(true);
    setError(null);
    try {
      setEmergencyResult(await revokeAllApiKeys(emergencyReason));
      await reload();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not revoke the API keys.');
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
# 429 + Retry-After when the key's rate limit is hit.
# Check-mode: only call the model when decision is "allow".`;

  return (
    <section id="api-keys" className="border-y border-line bg-ink-900/40">
      <div className="mx-auto max-w-7xl px-4 py-20 sm:px-6 lg:px-8 lg:py-28">
        <SectionHeading
          eyebrow="API keys"
          title="The front door to AllowBase."
          description="Machine keys let your backend ask for a decision before calling a model. Keys are scoped, optionally locked to IP ranges, rate limited, rotatable without downtime, and every use lands in the audit log."
        />

        <div className="mt-12">
          {signedIn === false ? (
            <div className="rounded-xl border border-line bg-ink-950/60 p-8 text-center">
              <p className="text-sm text-mist-300">Sign in to manage API keys for your workspace.</p>
            </div>
          ) : signedIn === null && !listError ? (
            <div className="rounded-xl border border-line bg-ink-950/60 p-8">
              <p className="text-sm text-mist-500">Loading API keys…</p>
            </div>
          ) : listError && keys.length === 0 ? (
            <div className="rounded-xl border border-rose-400/30 bg-ink-950/60 p-8">
              <p className="text-xs font-semibold uppercase tracking-[0.18em] text-rose-400">Could not load API keys</p>
              <p className="mt-2 text-sm text-mist-300">{listError}</p>
            </div>
          ) : (
            <div className="space-y-6">
              <Reveal>
                <div className="overflow-hidden rounded-xl border border-line bg-ink-950/60">
                  <div className="flex flex-wrap items-center justify-between gap-4 border-b border-line px-5 py-4">
                    <div className="flex items-center gap-2">
                      <KeyRound size={15} className="text-accent-600" />
                      <h3 className="text-sm font-semibold uppercase tracking-[0.18em] text-mist-400">
                        Keys ({keys.length})
                      </h3>
                    </div>
                    {canManage ? (
                      <div className="flex items-center gap-2">
                        {liveCount > 0 ? (
                          <button
                            type="button"
                            onClick={() => setEmergencyOpen(true)}
                            className="inline-flex items-center gap-1.5 rounded-lg border border-rose-400/40 px-3 py-2 text-sm font-medium text-rose-300 transition hover:bg-rose-400/10"
                          >
                            <Siren size={14} aria-hidden="true" />
                            Emergency revoke
                          </button>
                        ) : null}
                        <button
                          type="button"
                          onClick={() => setCreateOpen(true)}
                          className="btn-primary inline-flex items-center gap-1.5 rounded-lg px-3.5 py-2 text-sm font-semibold"
                        >
                          <Plus size={14} />
                          New key
                        </button>
                      </div>
                    ) : null}
                  </div>
                  {!canManage ? (
                    <p className="border-b border-line px-5 py-3 text-xs text-mist-500">
                      Key management needs the owner or admin role. Members can see key metadata below.
                    </p>
                  ) : null}
                  {listError ? <p className="border-b border-line px-5 py-3 text-xs text-rose-400">{listError}</p> : null}
                  {keys.length === 0 ? (
                    <p className="px-5 py-8 text-center text-sm text-mist-500">
                      No keys yet. Create one to let your backend ask AllowBase for decisions.
                    </p>
                  ) : (
                    <ul className="divide-y divide-line">
                      {keys.map((key) => {
                        const status = keyStatus(key);
                        const live = isLive(key);
                        return (
                          <li key={key.id} className="flex flex-wrap items-center gap-x-6 gap-y-3 px-5 py-4">
                            <div className="min-w-0 flex-1">
                              <p className="truncate text-sm font-semibold text-mist-100">{key.name}</p>
                              <p className="mt-0.5 font-mono text-xs text-mist-500">
                                {key.key_prefix}… · created {formatDate(key.created_at)}
                                {key.last_used_at ? ` · last used ${formatDate(key.last_used_at)}` : ' · never used'}
                                {key.last_used_ip ? ` from ${key.last_used_ip}` : ''}
                                {key.expires_at ? ` · expires ${formatDate(key.expires_at)}` : ''}
                              </p>
                              <div className="mt-2 flex flex-wrap gap-1.5 text-[11px]">
                                {key.scopes.map((scope) => (
                                  <span key={scope} className="rounded-md border border-line bg-ink-900/70 px-1.5 py-0.5 font-mono text-mist-300">
                                    {scope}
                                  </span>
                                ))}
                                <span className="rounded-md border border-line px-1.5 py-0.5 text-mist-400">
                                  {key.rate_limit_per_minute}/min
                                </span>
                                <span
                                  className={`rounded-md border px-1.5 py-0.5 ${
                                    key.allowed_cidrs.length > 0 ? 'border-mint-400/30 text-mint-400' : 'border-line text-mist-500'
                                  }`}
                                  title={key.allowed_cidrs.join(', ') || undefined}
                                >
                                  {key.allowed_cidrs.length > 0
                                    ? `IP locked (${key.allowed_cidrs.length})`
                                    : 'Any IP'}
                                </span>
                                <span className="rounded-md border border-line px-1.5 py-0.5 text-mist-500">
                                  {key.use_count.toLocaleString()} calls
                                </span>
                                {key.rotated_from ? (
                                  <span className="rounded-md border border-sky-400/30 px-1.5 py-0.5 text-sky-300">rotated</span>
                                ) : null}
                                {key.revoked_reason ? (
                                  <span className="rounded-md border border-line px-1.5 py-0.5 text-mist-500">
                                    {key.revoked_reason}
                                  </span>
                                ) : null}
                              </div>
                            </div>
                            <span className={`rounded-full border px-2.5 py-1 text-xs font-medium ${status.tone}`}>
                              {status.label}
                            </span>
                            {canManage && live ? (
                              <div className="flex items-center gap-2">
                                <button
                                  type="button"
                                  onClick={() => setRotateTarget(key)}
                                  className="inline-flex items-center gap-1 rounded-lg border border-line px-3 py-1.5 text-xs font-medium text-mist-400 transition hover:border-line-strong hover:text-mist-100"
                                >
                                  <RefreshCcw size={12} aria-hidden="true" /> Rotate
                                </button>
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
                              </div>
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
        subtitle={created ? 'Copy it now — it will never be shown again.' : 'The plaintext is shown once. Only a hash is stored.'}
      >
        {created ? (
          <PlaintextKey created={created} onDone={closeCreate} />
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
                className={inputCls}
              />
            </div>
            <div className="grid gap-4 sm:grid-cols-2">
              <div>
                <label htmlFor="api-key-expiry" className="mb-1.5 block text-sm font-medium text-mist-200">
                  Expires
                </label>
                <select
                  id="api-key-expiry"
                  value={expiryDays}
                  onChange={(event) => setExpiryDays(Number(event.target.value))}
                  className={inputCls}
                >
                  {EXPIRIES.map((option) => (
                    <option key={option.days} value={option.days}>
                      {option.label}
                    </option>
                  ))}
                </select>
              </div>
              <div>
                <label htmlFor="api-key-rate" className="mb-1.5 block text-sm font-medium text-mist-200">
                  Rate limit (requests/min)
                </label>
                <input
                  id="api-key-rate"
                  type="number"
                  min={1}
                  max={10000}
                  value={rateLimit}
                  onChange={(event) => setRateLimit(Math.floor(Number(event.target.value)))}
                  className={inputCls}
                />
              </div>
            </div>
            <fieldset>
              <legend className="mb-1.5 block text-sm font-medium text-mist-200">Scopes</legend>
              <div className="space-y-2">
                {API_KEY_SCOPES.map((scope) => {
                  const checked = scope.required ? true : allowContent;
                  return (
                    <label key={scope.id} className="flex items-start gap-2.5 rounded-lg border border-line px-3 py-2.5">
                      <input
                        type="checkbox"
                        checked={checked}
                        disabled={scope.required}
                        onChange={(e) => setAllowContent(e.target.checked)}
                        className="mt-0.5 accent-accent-500"
                      />
                      <span>
                        <span className="block font-mono text-xs text-mist-100">{scope.label}</span>
                        <span className="block text-xs text-mist-500">
                          {scope.description}
                          {scope.required ? ' Always required.' : ''}
                        </span>
                      </span>
                    </label>
                  );
                })}
              </div>
            </fieldset>
            <div>
              <label htmlFor="api-key-cidrs" className="mb-1.5 block text-sm font-medium text-mist-200">
                Allowed IPs (optional)
              </label>
              <textarea
                id="api-key-cidrs"
                rows={2}
                value={cidrText}
                onChange={(event) => setCidrText(event.target.value)}
                placeholder="203.0.113.7, 10.0.0.0/8"
                className={`${inputCls} font-mono`}
              />
              <p className="mt-1 text-xs text-mist-500">
                Leave empty to accept any IP. Requests from other addresses get a 403.
              </p>
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

      <Modal
        open={rotateTarget !== null}
        onClose={closeRotate}
        title={rotated ? 'Key rotated' : `Rotate “${rotateTarget?.name ?? ''}”`}
        subtitle={
          rotated
            ? 'Deploy the new key, then let the old one lapse.'
            : 'A new key with the same scopes, IP ranges and rate limit is minted.'
        }
      >
        {rotated ? (
          <PlaintextKey created={rotated} onDone={closeRotate} />
        ) : (
          <div className="space-y-5">
            {error ? <p className="text-sm text-rose-400">{error}</p> : null}
            <div>
              <label htmlFor="rotate-grace" className="mb-1.5 block text-sm font-medium text-mist-200">
                Grace period for the old key
              </label>
              <select
                id="rotate-grace"
                value={graceHours}
                onChange={(event) => setGraceHours(Number(event.target.value))}
                className={inputCls}
              >
                {GRACE_OPTIONS.map((option) => (
                  <option key={option.hours} value={option.hours}>
                    {option.label}
                  </option>
                ))}
              </select>
              <p className="mt-1 text-xs text-mist-500">
                Pick &quot;immediately&quot; if you suspect the key has leaked.
              </p>
            </div>
            <button
              type="button"
              onClick={() => void handleRotate()}
              disabled={rotating}
              className="btn-primary w-full rounded-lg px-4 py-2.5 text-sm font-semibold disabled:opacity-50"
            >
              {rotating ? 'Rotating…' : 'Rotate key'}
            </button>
          </div>
        )}
      </Modal>

      <Modal
        open={emergencyOpen}
        onClose={closeEmergency}
        title="Emergency revoke all keys"
        subtitle="Every live key in this workspace stops working immediately. Integrations will fail until new keys are deployed."
      >
        {emergencyResult !== null ? (
          <div className="space-y-4">
            <p className="text-sm text-mist-200">
              Revoked {emergencyResult} key{emergencyResult === 1 ? '' : 's'}. The action is recorded in the audit log.
            </p>
            <button type="button" onClick={closeEmergency} className="btn-primary w-full rounded-lg px-4 py-2.5 text-sm font-semibold">
              Done
            </button>
          </div>
        ) : (
          <div className="space-y-5">
            {error ? <p className="text-sm text-rose-400">{error}</p> : null}
            <div>
              <label htmlFor="emergency-reason" className="mb-1.5 block text-sm font-medium text-mist-200">
                Reason (recorded in the audit log)
              </label>
              <input
                id="emergency-reason"
                type="text"
                maxLength={500}
                value={emergencyReason}
                onChange={(event) => setEmergencyReason(event.target.value)}
                placeholder="Key committed to a public repository"
                className={inputCls}
              />
            </div>
            <div>
              <label htmlFor="emergency-confirm" className="mb-1.5 block text-sm font-medium text-mist-200">
                Type REVOKE to confirm
              </label>
              <input
                id="emergency-confirm"
                type="text"
                autoComplete="off"
                value={emergencyConfirm}
                onChange={(event) => setEmergencyConfirm(event.target.value)}
                className={`${inputCls} font-mono`}
              />
            </div>
            <button
              type="button"
              onClick={() => void handleEmergency()}
              disabled={!emergencyReason.trim() || emergencyConfirm !== 'REVOKE' || revoking}
              className="w-full rounded-lg bg-rose-500 px-4 py-2.5 text-sm font-semibold text-white transition hover:bg-rose-400 disabled:cursor-not-allowed disabled:opacity-50"
            >
              {revoking ? 'Revoking…' : `Revoke ${liveCount} live key${liveCount === 1 ? '' : 's'}`}
            </button>
          </div>
        )}
      </Modal>
    </section>
  );
}
