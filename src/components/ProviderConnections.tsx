import { useCallback, useEffect, useState } from 'react';
import { KeyRound, Plug } from 'lucide-react';
import { Modal } from './Modal';
import { SectionHeading } from './SectionHeading';
import { getActiveOrganizationId, isSupabaseConfigured } from '../lib/supabase';
import { getMyOrganizationRole } from '../services/organizationService';
import {
  connectProvider,
  listProviders,
  revokeProvider,
  type AIProviderId,
  type ProviderConnection,
} from '../services/providerService';

const PROVIDERS: { id: AIProviderId; name: string; note: string }[] = [
  { id: 'openai', name: 'OpenAI', note: 'GPT models via the AI gateway' },
  { id: 'anthropic', name: 'Anthropic', note: 'Claude models via the AI gateway' },
  { id: 'gemini', name: 'Google Gemini', note: 'Gemini models via the AI gateway' },
  { id: 'custom', name: 'Custom', note: 'Any OpenAI-compatible API' },
];

export function ProviderConnections() {
  const [connections, setConnections] = useState<ProviderConnection[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [isPrivileged, setIsPrivileged] = useState(false);
  const [connecting, setConnecting] = useState<AIProviderId | null>(null);
  const [apiKey, setApiKey] = useState('');
  const [baseUrl, setBaseUrl] = useState('');
  const [saving, setSaving] = useState(false);
  const [busy, setBusy] = useState<AIProviderId | null>(null);

  const refresh = useCallback(async () => {
    if (!isSupabaseConfigured()) {
      setLoading(false);
      return;
    }
    setLoading(true);
    setError(null);
    try {
      const orgId = await getActiveOrganizationId();
      const list = await listProviders().catch((e: unknown) => {
        throw e;
      });
      const role = orgId ? await getMyOrganizationRole(orgId).catch(() => null) : null;
      setConnections(list);
      setIsPrivileged(role === 'owner' || role === 'admin' || role === 'security');
    } catch (e) {
      setError(
        e instanceof Error ? e.message : 'Could not load provider connections.',
      );
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const openConnect = (provider: AIProviderId) => {
    setApiKey('');
    setBaseUrl('');
    setError(null);
    setConnecting(provider);
  };

  const handleConnect = async () => {
    if (!connecting || apiKey.trim().length < 8) {
      setError('Paste a valid API key.');
      return;
    }
    if (connecting === 'custom' && !/^https:\/\/.+/.test(baseUrl.trim())) {
      setError('A custom provider needs an https base URL.');
      return;
    }
    setSaving(true);
    setError(null);
    try {
      await connectProvider({
        provider: connecting,
        api_key: apiKey.trim(),
        ...(connecting === 'custom' ? { base_url: baseUrl.trim() } : {}),
      });
      setConnecting(null);
      await refresh();
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Could not connect the provider.');
    } finally {
      setSaving(false);
    }
  };

  const handleRevoke = async (provider: AIProviderId) => {
    setBusy(provider);
    setError(null);
    try {
      await revokeProvider(provider);
      await refresh();
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Could not revoke the provider.');
    } finally {
      setBusy(null);
    }
  };

  const byId = new Map(connections.map((c) => [c.provider, c]));

  return (
    <section id="ai-providers" aria-label="AI providers">
      <SectionHeading
        eyebrow="Connections"
        title="AI providers"
        description="Connect provider API keys for the AI gateway. Keys are encrypted server-side and never shown again — only the last 4 characters are displayed."
      />
      {!isSupabaseConfigured() ? (
        <p className="mt-4 text-sm text-mist-500">
          Connect Supabase to manage AI provider connections.
        </p>
      ) : loading ? (
        <p className="mt-4 text-sm text-mist-500">Loading provider connections…</p>
      ) : (
        <>
          {error ? (
            <p className="mt-4 rounded-xl border border-rose-400/30 bg-rose-400/10 px-4 py-3 text-sm text-rose-300">
              {error}
            </p>
          ) : null}
          <div className="mt-4 grid gap-3 sm:grid-cols-2">
            {PROVIDERS.map((provider) => {
              const conn = byId.get(provider.id);
              const active = conn?.status === 'active';
              return (
                <div
                  key={provider.id}
                  className="flex items-center justify-between gap-3 rounded-xl border border-line bg-ink-950/60 px-4 py-3"
                >
                  <div className="min-w-0">
                    <p className="flex items-center gap-2 text-sm font-semibold text-mist-100">
                      <Plug size={14} className="text-accent-400" />
                      {conn?.label ?? provider.name}
                    </p>
                    <p className="mt-0.5 text-xs text-mist-500">{provider.note}</p>
                    {active ? (
                      <p className="mt-1 font-mono text-xs text-mint-300">Connected · {conn.key_hint}</p>
                    ) : null}
                  </div>
                  {active ? (
                    <button
                      type="button"
                      disabled={!isPrivileged || busy === provider.id}
                      onClick={() => void handleRevoke(provider.id)}
                      className="shrink-0 rounded-lg border border-line px-3 py-1.5 text-xs font-semibold text-mist-400 transition hover:border-rose-400/40 hover:text-rose-300 disabled:cursor-not-allowed disabled:opacity-40"
                    >
                      {busy === provider.id ? 'Revoking…' : 'Disconnect'}
                    </button>
                  ) : (
                    <button
                      type="button"
                      disabled={!isPrivileged}
                      onClick={() => openConnect(provider.id)}
                      title={isPrivileged ? undefined : 'Owners, admins, and security roles only'}
                      className="shrink-0 rounded-lg border border-accent-400/40 bg-accent-500/10 px-3 py-1.5 text-xs font-semibold text-accent-600 transition hover:bg-accent-500/20 disabled:cursor-not-allowed disabled:opacity-40"
                    >
                      Connect
                    </button>
                  )}
                </div>
              );
            })}
          </div>
          {!isPrivileged ? (
            <p className="mt-3 text-xs text-mist-600">
              Connecting providers requires an owner, admin, or security role.
            </p>
          ) : null}
        </>
      )}

      <Modal open={connecting !== null} onClose={() => setConnecting(null)} title={`Connect ${PROVIDERS.find((p) => p.id === connecting)?.name ?? ''}`}>
        <p className="text-sm leading-relaxed text-mist-400">
          Paste the provider API key. It is encrypted on the server before storage and is never
          displayed again.
        </p>
        {connecting === 'custom' ? (
          <label className="mt-4 block">
            <span className="text-xs font-semibold uppercase tracking-[0.16em] text-mist-500">Base URL</span>
            <input
              type="url"
              value={baseUrl}
              onChange={(e) => setBaseUrl(e.target.value)}
              placeholder="https://your-api.example.com/v1"
              className="mt-2 w-full rounded-xl border border-line bg-ink-950/70 px-3 py-2.5 font-mono text-sm text-mist-100 outline-none placeholder:text-mist-600 focus:border-accent-400/60"
            />
          </label>
        ) : null}
        <label className="mt-4 block">
          <span className="text-xs font-semibold uppercase tracking-[0.16em] text-mist-500">API key</span>
          <input
            type="password"
            value={apiKey}
            onChange={(e) => setApiKey(e.target.value)}
            placeholder="Paste the key — it is never stored in your browser"
            autoComplete="off"
            className="mt-2 w-full rounded-xl border border-line bg-ink-950/70 px-3 py-2.5 font-mono text-sm text-mist-100 outline-none placeholder:text-mist-600 focus:border-accent-400/60"
          />
        </label>
        <div className="mt-5 flex justify-end gap-2">
          <button
            type="button"
            onClick={() => setConnecting(null)}
            className="rounded-xl border border-line px-4 py-2 text-sm font-semibold text-mist-300 transition hover:border-line-strong"
          >
            Cancel
          </button>
          <button
            type="button"
            onClick={() => void handleConnect()}
            disabled={saving}
            className="flex items-center gap-2 rounded-xl bg-accent-500 px-4 py-2 text-sm font-semibold text-white transition hover:bg-accent-400 disabled:opacity-50"
          >
            <KeyRound size={14} />
            {saving ? 'Saving…' : 'Save key'}
          </button>
        </div>
      </Modal>
    </section>
  );
}
