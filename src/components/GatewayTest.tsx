import { useEffect, useState } from 'react';
import { FlaskConical, Send } from 'lucide-react';
import { SectionHeading } from './SectionHeading';
import { isSupabaseConfigured } from '../lib/supabase';
import {
  gatewayChat,
  listProviders,
  type AIProviderId,
  type GatewayResult,
  type ProviderConnection,
} from '../services/providerService';

const DEFAULT_MODELS: Record<AIProviderId, string> = {
  openai: 'gpt-4o-mini',
  anthropic: 'claude-3-5-haiku-latest',
  gemini: 'gemini-2.0-flash',
  custom: 'model',
};

/**
 * Minimal AI gateway test surface: pick a connected provider, type a prompt,
 * and watch the request pass policy evaluation before the provider is called.
 */
export function GatewayTest() {
  const [connections, setConnections] = useState<ProviderConnection[]>([]);
  const [provider, setProvider] = useState<AIProviderId>('openai');
  const [model, setModel] = useState(DEFAULT_MODELS.openai);
  const [purpose, setPurpose] = useState('');
  const [prompt, setPrompt] = useState('');
  const [sending, setSending] = useState(false);
  const [result, setResult] = useState<GatewayResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!isSupabaseConfigured()) return;
    listProviders()
      .then((list) => {
        const active = list.filter((c) => c.status === 'active');
        setConnections(active);
        if (active.length > 0) {
          setProvider(active[0].provider);
          setModel(DEFAULT_MODELS[active[0].provider]);
        }
      })
      .catch(() => {});
  }, []);

  const handleSend = async () => {
    if (!prompt.trim()) {
      setError('Type a prompt first.');
      return;
    }
    setSending(true);
    setError(null);
    setResult(null);
    try {
      const res = await gatewayChat({
        provider,
        model: model.trim() || DEFAULT_MODELS[provider],
        messages: [{ role: 'user', content: prompt.trim() }],
        ...(purpose.trim() ? { purpose: purpose.trim() } : {}),
      });
      setResult(res);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'The gateway did not respond.');
    } finally {
      setSending(false);
    }
  };

  if (!isSupabaseConfigured()) return null;

  return (
    <section aria-label="Protect an AI request" className="mt-2">
      <SectionHeading
        eyebrow="AI Gateway"
        title="Protect an AI request"
        description="Send a real prompt through AllowBase: inspect it, evaluate policy, mask or block sensitive content, and call the provider only when allowed."
      />
      <div className="mt-4 rounded-xl border border-line bg-ink-950/60 p-4">
        {connections.length === 0 ? (
          <p className="text-sm text-mist-500">
            Connect an AI provider below to activate the gateway. Provider keys are encrypted server-side and are never returned to the browser.
          </p>
        ) : (
          <>
            <div className="grid gap-3 sm:grid-cols-3">
              <label className="block">
                <span className="text-xs font-semibold uppercase tracking-[0.16em] text-mist-500">
                  Provider
                </span>
                <select
                  value={provider}
                  onChange={(e) => {
                    const next = e.target.value as AIProviderId;
                    setProvider(next);
                    setModel(DEFAULT_MODELS[next]);
                  }}
                  className="mt-1.5 w-full rounded-xl border border-line bg-ink-900 px-3 py-2 text-sm text-mist-100 outline-none focus:border-accent-400/60"
                >
                  {connections.map((c) => (
                    <option key={c.id} value={c.provider}>
                      {c.label}
                    </option>
                  ))}
                </select>
              </label>
              <label className="block">
                <span className="text-xs font-semibold uppercase tracking-[0.16em] text-mist-500">
                  Model
                </span>
                <input
                  value={model}
                  onChange={(e) => setModel(e.target.value)}
                  placeholder={DEFAULT_MODELS[provider]}
                  className="mt-1.5 w-full rounded-xl border border-line bg-ink-900 px-3 py-2 text-sm text-mist-100 outline-none placeholder:text-mist-600 focus:border-accent-400/60"
                />
              </label>
              <label className="block">
                <span className="text-xs font-semibold uppercase tracking-[0.16em] text-mist-500">
                  Purpose (optional)
                </span>
                <input
                  value={purpose}
                  onChange={(e) => setPurpose(e.target.value)}
                  placeholder="e.g. support-draft"
                  className="mt-1.5 w-full rounded-xl border border-line bg-ink-900 px-3 py-2 text-sm text-mist-100 outline-none placeholder:text-mist-600 focus:border-accent-400/60"
                />
              </label>
            </div>
            <label className="mt-3 block">
              <span className="text-xs font-semibold uppercase tracking-[0.16em] text-mist-500">
                Prompt
              </span>
              <textarea
                value={prompt}
                onChange={(e) => setPrompt(e.target.value)}
                rows={3}
                placeholder="Try a normal request, or paste a test email address to see detection…"
                className="mt-1.5 w-full rounded-xl border border-line bg-ink-900 px-3 py-2.5 text-sm text-mist-100 outline-none placeholder:text-mist-600 focus:border-accent-400/60"
              />
            </label>
            <button
              type="button"
              onClick={() => void handleSend()}
              disabled={sending}
              className="mt-3 flex items-center gap-2 rounded-xl bg-accent-500 px-4 py-2 text-sm font-semibold text-white transition hover:bg-accent-400 disabled:opacity-50"
            >
              {sending ? <FlaskConical size={14} className="animate-pulse" /> : <Send size={14} />}
              {sending ? 'Protecting…' : 'Protect this request'}
            </button>
          </>
        )}

        {error ? (
          <p className="mt-3 rounded-xl border border-rose-400/30 bg-rose-400/10 px-4 py-3 text-sm text-rose-300">
            {error}
          </p>
        ) : null}

        {result ? (
          <div className="mt-3 space-y-2 rounded-xl border border-line bg-ink-900/60 p-4">
            <div className="flex flex-wrap items-center gap-2 text-xs">
              <span
                className={`rounded-full border px-2 py-0.5 font-semibold ${
                  result.decision === 'allow'
                    ? 'border-mint-400/30 bg-mint-400/10 text-mint-300'
                    : result.decision === 'block'
                      ? 'border-rose-400/30 bg-rose-400/10 text-rose-300'
                      : 'border-amber-400/30 bg-amber-400/10 text-amber-300'
                }`}
              >
                {result.decision.toUpperCase()}
              </span>
              {result.masked ? (
                <span className="rounded-full border border-accent-400/30 bg-accent-500/10 px-2 py-0.5 font-semibold text-accent-600">
                  MASKED
                </span>
              ) : null}
              {result.request_id ? (
                <span className="font-mono text-mist-500">request {result.request_id}</span>
              ) : null}
            </div>
            {result.forwarded && result.text ? (
              <p className="whitespace-pre-wrap text-sm leading-relaxed text-mist-200">{result.text}</p>
            ) : (
              <p className="text-sm text-mist-400">
                {result.decision === 'block'
                  ? 'Blocked by policy — the provider was never called.'
                  : result.decision === 'review'
                    ? 'Held for review — approve it in the Approvals tab, then try again.'
                    : result.error ?? 'No response text.'}
              </p>
            )}
            {result.reasons && result.reasons.length > 0 ? (
              <p className="text-xs text-mist-500">{result.reasons.join(' · ')}</p>
            ) : null}
          </div>
        ) : null}
      </div>
    </section>
  );
}
