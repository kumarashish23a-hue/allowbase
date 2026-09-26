import { Check, Clock3, X } from 'lucide-react';
import { useEffect, useState } from 'react';
import { Reveal } from '../components/Reveal';
import { SectionHeading } from '../components/SectionHeading';
import { getActiveOrganizationId, getSupabase, isSupabaseConfigured } from '../lib/supabase';
import { decideApproval, listApprovals, type ApprovalItem } from '../services/approvalService';
import { getMyOrganizationRole } from '../services/organizationService';

const statusTone: Record<string, string> = {
  pending: 'border-accent-400/30 bg-accent-400/10 text-accent-300',
  approved: 'border-mint-400/30 bg-mint-400/10 text-mint-400',
  rejected: 'border-rose-400/30 bg-rose-400/10 text-rose-400',
  expired: 'border-line text-mist-500',
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

export function Approvals() {
  const [signedIn, setSignedIn] = useState<boolean | null>(null);
  const [approvals, setApprovals] = useState<ApprovalItem[]>([]);
  const [canDecide, setCanDecide] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notes, setNotes] = useState<Record<string, string>>({});
  const [deciding, setDeciding] = useState<string | null>(null);

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
        const [loaded, orgId] = await Promise.all([listApprovals(), getActiveOrganizationId()]);
        if (cancelled) return;
        setApprovals(loaded);
        if (orgId) {
          const role = await getMyOrganizationRole(orgId);
          if (!cancelled) setCanDecide(role === 'owner' || role === 'admin');
        }
      } catch (err) {
        if (!cancelled) setError(err instanceof Error ? err.message : 'Could not load approvals.');
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  const decide = async (id: string, decision: 'approved' | 'rejected') => {
    setDeciding(id);
    setError(null);
    try {
      await decideApproval(id, decision, notes[id]);
      const loaded = await listApprovals();
      setApprovals(loaded);
      setNotes((current) => {
        const next = { ...current };
        delete next[id];
        return next;
      });
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not decide the approval.');
    } finally {
      setDeciding(null);
    }
  };

  const pending = approvals.filter((item) => item.status === 'pending');
  const decided = approvals.filter((item) => item.status !== 'pending');

  return (
    <section className="border-y border-line bg-ink-900/40">
      <div className="mx-auto max-w-7xl px-4 py-20 sm:px-6 lg:px-8 lg:py-28">
        <SectionHeading
          eyebrow="Approvals"
          title="Humans decide the risky calls."
          description="Policies with a require-approval action pause the request here instead of guessing. Owners and admins allow or reject; every decision is audit-logged."
        />

        <div className="mt-12">
          {signedIn === false ? (
            <div className="rounded-xl border border-line bg-ink-950/60 p-8 text-center">
              <p className="text-sm text-mist-300">Sign in to review approval requests for your workspace.</p>
            </div>
          ) : signedIn === null && !error ? (
            <div className="rounded-xl border border-line bg-ink-950/60 p-8">
              <p className="text-sm text-mist-500">Loading approvals…</p>
            </div>
          ) : error ? (
            <div className="rounded-xl border border-rose-400/30 bg-ink-950/60 p-8">
              <p className="text-xs font-semibold uppercase tracking-[0.18em] text-rose-400">Could not load approvals</p>
              <p className="mt-2 text-sm text-mist-300">{error}</p>
            </div>
          ) : (
            <div className="space-y-10">
              <div>
                <div className="flex items-center gap-2">
                  <Clock3 size={15} className="text-accent-300" />
                  <h3 className="text-sm font-semibold uppercase tracking-[0.18em] text-mist-400">
                    Pending ({pending.length})
                  </h3>
                </div>
                {pending.length === 0 ? (
                  <p className="mt-4 rounded-xl border border-line bg-ink-950/60 p-6 text-sm text-mist-500">
                    Nothing waiting. Requests paused by a require-approval policy will appear here.
                  </p>
                ) : (
                  <div className="mt-4 grid gap-4 lg:grid-cols-2">
                    {pending.map((item, index) => (
                      <Reveal key={item.id} delay={index * 0.05}>
                        <div className="flex h-full flex-col rounded-xl border border-line bg-ink-950/60 p-6 shadow-card">
                          <div className="flex items-start justify-between gap-3">
                            <div>
                              <p className="text-base font-semibold text-mist-100">{item.request.purpose}</p>
                              <p className="mt-1 text-xs text-mist-500">
                                {item.request.model ?? 'Unknown model'} · requested {formatDate(item.request.created_at)}
                              </p>
                            </div>
                            <span className={`rounded-full border px-2.5 py-1 text-[11px] font-bold tracking-[0.12em] ${statusTone.pending}`}>
                              PENDING
                            </span>
                          </div>
                          <div className="mt-4 flex flex-wrap gap-2 text-xs">
                            <span className={`rounded-full border border-line px-2.5 py-1 font-semibold ${riskTone[item.request.risk_level] ?? 'text-mist-400'}`}>
                              {item.request.risk_level.toUpperCase()} RISK
                            </span>
                            {item.request.policies.map((policy) => (
                              <span key={policy} className="rounded-full border border-line bg-ink-900/70 px-2.5 py-1 text-mist-300">
                                {policy}
                              </span>
                            ))}
                          </div>
                          {canDecide ? (
                            <div className="mt-5">
                              <label htmlFor={`note-${item.id}`} className="text-xs font-semibold uppercase tracking-[0.16em] text-mist-500">
                                Decision note (optional)
                              </label>
                              <input
                                id={`note-${item.id}`}
                                value={notes[item.id] ?? ''}
                                onChange={(event) => setNotes((current) => ({ ...current, [item.id]: event.target.value }))}
                                className="mt-2 w-full rounded-xl border border-line bg-ink-900/70 px-3 py-2.5 text-sm text-mist-100 placeholder:text-mist-600 focus:border-accent-400/60 focus:outline-none"
                                placeholder="Why are you allowing or rejecting this?"
                              />
                              <div className="mt-3 flex gap-3">
                                <button
                                  type="button"
                                  disabled={deciding === item.id}
                                  onClick={() => void decide(item.id, 'approved')}
                                  className="inline-flex flex-1 items-center justify-center gap-1.5 rounded-xl bg-mint-500 px-4 py-2.5 text-sm font-semibold text-ink-950 transition hover:bg-mint-400 disabled:opacity-60"
                                >
                                  <Check size={15} /> {deciding === item.id ? 'Working…' : 'Approve'}
                                </button>
                                <button
                                  type="button"
                                  disabled={deciding === item.id}
                                  onClick={() => void decide(item.id, 'rejected')}
                                  className="inline-flex flex-1 items-center justify-center gap-1.5 rounded-xl border border-rose-400/40 bg-rose-400/10 px-4 py-2.5 text-sm font-semibold text-rose-300 transition hover:bg-rose-400/20 disabled:opacity-60"
                                >
                                  <X size={15} /> {deciding === item.id ? 'Working…' : 'Reject'}
                                </button>
                              </div>
                            </div>
                          ) : (
                            <p className="mt-5 text-xs text-mist-600">
                              Only organization owners and admins can decide approvals.
                            </p>
                          )}
                        </div>
                      </Reveal>
                    ))}
                  </div>
                )}
              </div>

              {decided.length > 0 ? (
                <div>
                  <h3 className="text-sm font-semibold uppercase tracking-[0.18em] text-mist-400">
                    Decided ({decided.length})
                  </h3>
                  <div className="mt-4 space-y-3">
                    {decided.map((item) => (
                      <div
                        key={item.id}
                        className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-line bg-ink-950/60 px-5 py-4"
                      >
                        <div>
                          <p className="text-sm font-semibold text-mist-100">{item.request.purpose}</p>
                          <p className="mt-0.5 text-xs text-mist-500">
                            {item.request.model ?? 'Unknown model'}
                            {item.note ? ` · “${item.note}”` : ''}
                          </p>
                        </div>
                        <span className={`rounded-full border px-2.5 py-1 text-[11px] font-bold tracking-[0.12em] ${statusTone[item.status]}`}>
                          {item.status.toUpperCase()}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              ) : null}
            </div>
          )}
        </div>
      </div>
    </section>
  );
}
