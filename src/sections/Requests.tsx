import { Activity, KeyRound, RefreshCw } from 'lucide-react';
import { useCallback, useEffect, useState } from 'react';
import { Reveal } from '../components/Reveal';
import { SectionHeading } from '../components/SectionHeading';
import { getSupabase, isSupabaseConfigured } from '../lib/supabase';
import { getAIRequests, type AIRequestRow } from '../services/aiRequestService';

const statusTone: Record<string, string> = {
  allowed: 'border-mint-400/30 bg-mint-400/10 text-mint-400',
  blocked: 'border-rose-400/30 bg-rose-400/10 text-rose-400',
  review: 'border-amber-400/30 bg-amber-400/10 text-amber-400',
  pending: 'border-accent-400/30 bg-accent-400/10 text-accent-600',
  pending_approval: 'border-accent-400/30 bg-accent-400/10 text-accent-600',
  error: 'border-line text-mist-500',
};

const riskTone: Record<string, string> = {
  low: 'text-mint-400',
  medium: 'text-amber-400',
  high: 'text-rose-400',
  critical: 'text-rose-400',
};

function formatDate(value: string): string {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}

export function Requests() {
  const [signedIn, setSignedIn] = useState<boolean | null>(null);
  const [requests, setRequests] = useState<AIRequestRow[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      setRequests(await getAIRequests());
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not load requests.');
    } finally {
      setLoading(false);
    }
  }, []);

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
      await load();
    })();
    return () => {
      cancelled = true;
    };
  }, [load]);

  return (
    <section id="requests" className="border-y border-line bg-ink-900/40">
      <div className="mx-auto max-w-7xl px-4 py-20 sm:px-6 lg:px-8 lg:py-28">
        <SectionHeading
          eyebrow="Requests"
          title="Every AI call, on the record."
          description="Each request through the API — or the simulator — lands here with its verdict, risk level, and the policies that fired. Retried events are deduplicated, never double-counted."
        />

        <div className="mt-12">
          {signedIn === false ? (
            <div className="rounded-xl border border-line bg-ink-950/60 p-8 text-center">
              <p className="text-sm text-mist-300">Sign in to see the request log for your workspace.</p>
            </div>
          ) : signedIn === null && !error ? (
            <div className="rounded-xl border border-line bg-ink-950/60 p-8">
              <p className="text-sm text-mist-500">Loading requests…</p>
            </div>
          ) : error ? (
            <div className="rounded-xl border border-rose-400/30 bg-ink-950/60 p-8">
              <p className="text-xs font-semibold uppercase tracking-[0.18em] text-rose-400">Could not load requests</p>
              <p className="mt-2 text-sm text-mist-300">{error}</p>
            </div>
          ) : (
            <div>
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <Activity size={15} className="text-accent-600" />
                  <h3 className="text-sm font-semibold uppercase tracking-[0.18em] text-mist-400">
                    Recent ({requests.length})
                  </h3>
                </div>
                <button
                  type="button"
                  onClick={() => void load()}
                  disabled={loading}
                  className="inline-flex items-center gap-1.5 rounded-xl border border-line bg-ink-950/60 px-3 py-2 text-xs font-semibold text-mist-300 transition hover:border-accent-400/40 disabled:opacity-60"
                >
                  <RefreshCw size={13} className={loading ? 'animate-spin' : undefined} />
                  {loading ? 'Refreshing…' : 'Refresh'}
                </button>
              </div>

              {requests.length === 0 ? (
                <p className="mt-4 rounded-xl border border-line bg-ink-950/60 p-6 text-sm text-mist-500">
                  No requests yet. Send one through the API — see the curl example in API keys — or run the
                  simulator above.
                </p>
              ) : (
                <div className="mt-4 space-y-3">
                  {requests.map((item, index) => (
                    <Reveal key={item.id} delay={Math.min(index, 5) * 0.04}>
                      <div className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-line bg-ink-950/60 px-5 py-4">
                        <div className="min-w-0 flex-1">
                          <div className="flex flex-wrap items-center gap-2">
                            <p className="text-sm font-semibold text-mist-100">{item.purpose}</p>
                            {item.via_api ? (
                              <span className="inline-flex items-center gap-1 rounded-full border border-line bg-ink-900/70 px-2 py-0.5 text-[10px] font-bold tracking-[0.12em] text-mist-400">
                                <KeyRound size={10} /> API
                              </span>
                            ) : null}
                          </div>
                          <p className="mt-1 truncate font-mono text-xs text-mist-500">
                            {item.event_id ?? item.id.slice(0, 8)}
                            {' · '}
                            {item.model ?? 'Unknown model'}
                            {' · '}
                            {formatDate(item.created_at)}
                          </p>
                          {item.policies.length > 0 ? (
                            <div className="mt-2 flex flex-wrap gap-1.5">
                              {item.policies.map((policy) => (
                                <span
                                  key={policy}
                                  className="rounded-full border border-line bg-ink-900/70 px-2 py-0.5 text-[11px] text-mist-300"
                                >
                                  {policy}
                                </span>
                              ))}
                            </div>
                          ) : null}
                        </div>
                        <div className="flex items-center gap-2">
                          <span
                            className={`rounded-full border px-2.5 py-1 text-[11px] font-bold tracking-[0.12em] ${statusTone[item.status] ?? statusTone.error}`}
                          >
                            {item.status.replace('_', ' ').toUpperCase()}
                          </span>
                          <span className={`text-[11px] font-bold tracking-[0.12em] ${riskTone[item.risk] ?? 'text-mist-400'}`}>
                            {item.risk.toUpperCase()}
                          </span>
                        </div>
                      </div>
                    </Reveal>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </section>
  );
}
