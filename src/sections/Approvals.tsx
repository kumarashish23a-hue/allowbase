import { ArrowUpCircle, Check, ChevronDown, Clock3, UserCheck, X } from 'lucide-react';
import { useEffect, useState } from 'react';
import { ApprovalThread } from '../components/ApprovalThread';
import { Reveal } from '../components/Reveal';
import { SectionHeading } from '../components/SectionHeading';
import { getActiveOrganizationId, getLocalUserId, getSupabase, isSupabaseConfigured } from '../lib/supabase';
import { listMembers } from '../services/adminService';
import {
  decideApproval,
  delegateApproval,
  escalateApproval,
  listApprovals,
  type ApprovalItem,
} from '../services/approvalService';
import { getMyOrganizationRole } from '../services/organizationService';

const statusTone: Record<string, string> = {
  pending: 'border-accent-400/30 bg-accent-400/10 text-accent-600',
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

interface Reviewer {
  user_id: string;
  name: string;
  role: string;
}

function formatDate(value: string): string {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}

function timeLeft(expiresAt: string | null): { label: string; urgent: boolean } | null {
  if (!expiresAt) return null;
  const msLeft = new Date(expiresAt).getTime() - Date.now();
  if (Number.isNaN(msLeft)) return null;
  if (msLeft <= 0) return { label: 'Expired', urgent: true };
  const hours = Math.floor(msLeft / 3600000);
  const minutes = Math.floor((msLeft % 3600000) / 60000);
  const label = hours >= 24 ? `${Math.floor(hours / 24)}d ${hours % 24}h left` : `${hours}h ${minutes}m left`;
  return { label, urgent: msLeft < 6 * 3600000 };
}

export function Approvals() {
  const [signedIn, setSignedIn] = useState<boolean | null>(null);
  const [approvals, setApprovals] = useState<ApprovalItem[]>([]);
  const [role, setRole] = useState<string | null>(null);
  const [userId, setUserId] = useState<string | null>(null);
  const [reviewers, setReviewers] = useState<Reviewer[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [notes, setNotes] = useState<Record<string, string>>({});
  const [busy, setBusy] = useState<string | null>(null);
  const [openThread, setOpenThread] = useState<string | null>(null);

  const isAdmin = role === 'owner' || role === 'admin';

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
        const [loaded, orgId, me] = await Promise.all([
          listApprovals(),
          getActiveOrganizationId(),
          getLocalUserId().catch(() => null),
        ]);
        if (cancelled) return;
        setApprovals(loaded);
        setUserId(me);
        if (orgId) {
          const myRole = await getMyOrganizationRole(orgId);
          if (cancelled) return;
          setRole(myRole);
          if (myRole === 'owner' || myRole === 'admin') {
            const members = await listMembers(orgId).catch(() => []);
            if (!cancelled) {
              setReviewers(
                members
                  .filter((m) => m.status === 'active' && ['owner', 'admin', 'security'].includes(m.role))
                  .map((m) => ({ user_id: m.user_id, name: m.full_name ?? 'Unnamed member', role: m.role })),
              );
            }
          }
        }
      } catch (err) {
        if (!cancelled) setError(err instanceof Error ? err.message : 'Could not load approvals.');
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  const reload = async () => setApprovals(await listApprovals());

  const run = async (id: string, action: () => Promise<unknown>) => {
    setBusy(id);
    setActionError(null);
    try {
      await action();
      await reload();
    } catch (err) {
      setActionError(err instanceof Error ? err.message : 'That action failed.');
    } finally {
      setBusy(null);
    }
  };

  const decide = (id: string, decision: 'approved' | 'rejected') =>
    run(id, async () => {
      await decideApproval(id, decision, notes[id]);
      setNotes((current) => {
        const next = { ...current };
        delete next[id];
        return next;
      });
    });

  const canDecide = (item: ApprovalItem) =>
    isAdmin || (role === 'security' && item.assigned_to !== null && item.assigned_to === userId);

  const reviewerName = (id: string | null) =>
    id ? (reviewers.find((r) => r.user_id === id)?.name ?? (id === userId ? 'you' : 'a delegated reviewer')) : null;

  const pending = approvals.filter((item) => item.status === 'pending');
  const decided = approvals.filter((item) => item.status !== 'pending');

  return (
    <section className="border-y border-line bg-ink-900/40">
      <div className="mx-auto max-w-7xl px-4 py-20 sm:px-6 lg:px-8 lg:py-28">
        <SectionHeading
          eyebrow="Approvals"
          title="Humans decide the risky calls."
          description="Require-approval policies pause the request here. Requests expire after 72 hours (failing closed), auto-escalate after 24, and can be delegated to a security reviewer. Every step is audit-logged."
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
              {actionError ? (
                <p role="alert" className="rounded-xl border border-rose-400/30 bg-rose-400/10 px-4 py-3 text-sm text-rose-300">
                  {actionError}
                </p>
              ) : null}
              <div>
                <div className="flex items-center gap-2">
                  <Clock3 size={15} className="text-accent-600" />
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
                    {pending.map((item, index) => {
                      const expiry = timeLeft(item.expires_at);
                      const assignee = reviewerName(item.assigned_to);
                      const working = busy === item.id;
                      return (
                        <Reveal key={item.id} delay={index * 0.05}>
                          <div className="flex h-full flex-col rounded-xl border border-line bg-ink-950/60 p-6 shadow-card">
                            <div className="flex items-start justify-between gap-3">
                              <div className="min-w-0">
                                <p className="text-base font-semibold text-mist-100">{item.request.purpose}</p>
                                <p className="mt-1 text-xs text-mist-500">
                                  {item.request.model ?? 'Unknown model'} · requested {formatDate(item.request.created_at)}
                                </p>
                              </div>
                              <span className={`shrink-0 rounded-full border px-2.5 py-1 text-[11px] font-bold tracking-[0.12em] ${statusTone.pending}`}>
                                PENDING
                              </span>
                            </div>
                            <div className="mt-4 flex flex-wrap gap-2 text-xs">
                              <span className={`rounded-full border border-line px-2.5 py-1 font-semibold ${riskTone[item.request.risk_level] ?? 'text-mist-400'}`}>
                                {item.request.risk_level.toUpperCase()} RISK
                              </span>
                              {expiry ? (
                                <span
                                  className={`rounded-full border px-2.5 py-1 font-medium ${
                                    expiry.urgent ? 'border-rose-400/40 bg-rose-400/10 text-rose-300' : 'border-line text-mist-400'
                                  }`}
                                >
                                  {expiry.label}
                                </span>
                              ) : null}
                              {item.escalation_level > 0 ? (
                                <span className="rounded-full border border-amber-400/40 bg-amber-400/10 px-2.5 py-1 font-semibold text-amber-300">
                                  ESCALATED L{item.escalation_level}
                                </span>
                              ) : null}
                              {assignee ? (
                                <span className="inline-flex items-center gap-1 rounded-full border border-sky-400/30 bg-sky-400/10 px-2.5 py-1 text-sky-300">
                                  <UserCheck size={11} aria-hidden="true" /> {assignee}
                                </span>
                              ) : null}
                              {item.request.policies.map((policy) => (
                                <span key={policy} className="rounded-full border border-line bg-ink-900/70 px-2.5 py-1 text-mist-300">
                                  {policy}
                                </span>
                              ))}
                            </div>

                            {canDecide(item) ? (
                              <div className="mt-5">
                                <label htmlFor={`note-${item.id}`} className="text-xs font-semibold uppercase tracking-[0.16em] text-mist-500">
                                  Decision note (optional)
                                </label>
                                <input
                                  id={`note-${item.id}`}
                                  value={notes[item.id] ?? ''}
                                  maxLength={1000}
                                  onChange={(event) => setNotes((current) => ({ ...current, [item.id]: event.target.value }))}
                                  className="mt-2 w-full rounded-xl border border-line bg-ink-900/70 px-3 py-2.5 text-sm text-mist-100 placeholder:text-mist-600 focus:border-accent-400/60 focus:outline-none"
                                  placeholder="Why are you allowing or rejecting this?"
                                />
                                <div className="mt-3 flex gap-3">
                                  <button
                                    type="button"
                                    disabled={working}
                                    onClick={() => void decide(item.id, 'approved')}
                                    className="inline-flex flex-1 items-center justify-center gap-1.5 rounded-xl bg-mint-500 px-4 py-2.5 text-sm font-semibold text-ink-950 transition hover:bg-mint-400 disabled:opacity-60"
                                  >
                                    <Check size={15} /> {working ? 'Working…' : 'Approve'}
                                  </button>
                                  <button
                                    type="button"
                                    disabled={working}
                                    onClick={() => void decide(item.id, 'rejected')}
                                    className="inline-flex flex-1 items-center justify-center gap-1.5 rounded-xl border border-rose-400/40 bg-rose-400/10 px-4 py-2.5 text-sm font-semibold text-rose-300 transition hover:bg-rose-400/20 disabled:opacity-60"
                                  >
                                    <X size={15} /> {working ? 'Working…' : 'Reject'}
                                  </button>
                                </div>
                              </div>
                            ) : (
                              <p className="mt-5 text-xs text-mist-600">
                                Owners, admins, or the delegated security reviewer can decide this request.
                              </p>
                            )}

                            <div className="mt-4 flex flex-wrap items-center gap-2">
                              {item.escalation_level < 3 ? (
                                <button
                                  type="button"
                                  disabled={working}
                                  onClick={() => void run(item.id, () => escalateApproval(item.id))}
                                  className="inline-flex items-center gap-1.5 rounded-lg border border-line px-3 py-1.5 text-xs text-mist-400 transition hover:border-amber-400/50 hover:text-amber-300 disabled:opacity-50"
                                >
                                  <ArrowUpCircle size={13} aria-hidden="true" /> Escalate
                                </button>
                              ) : null}
                              {isAdmin && reviewers.length > 0 ? (
                                <>
                                  <label htmlFor={`delegate-${item.id}`} className="sr-only">
                                    Assign reviewer
                                  </label>
                                  <select
                                    id={`delegate-${item.id}`}
                                    disabled={working}
                                    value={item.assigned_to ?? ''}
                                    onChange={(e) =>
                                      void run(item.id, () => delegateApproval(item.id, e.target.value || null))
                                    }
                                    className="rounded-lg border border-line bg-ink-900/70 px-2.5 py-1.5 text-xs text-mist-300 focus:border-accent-400/60 focus:outline-none disabled:opacity-50"
                                  >
                                    <option value="">Unassigned</option>
                                    {reviewers.map((r) => (
                                      <option key={r.user_id} value={r.user_id}>
                                        {r.name} ({r.role})
                                      </option>
                                    ))}
                                  </select>
                                </>
                              ) : null}
                              <button
                                type="button"
                                onClick={() => setOpenThread((current) => (current === item.id ? null : item.id))}
                                aria-expanded={openThread === item.id}
                                className="ml-auto inline-flex items-center gap-1 text-xs font-medium text-accent-400 underline-offset-2 hover:underline"
                              >
                                Activity
                                <ChevronDown
                                  size={13}
                                  aria-hidden="true"
                                  className={`transition ${openThread === item.id ? 'rotate-180' : ''}`}
                                />
                              </button>
                            </div>
                            {openThread === item.id ? <ApprovalThread approvalId={item.id} canComment /> : null}
                          </div>
                        </Reveal>
                      );
                    })}
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
                      <div key={item.id} className="rounded-xl border border-line bg-ink-950/60 px-5 py-4">
                        <div className="flex flex-wrap items-center justify-between gap-3">
                          <div className="min-w-0">
                            <p className="text-sm font-semibold text-mist-100">{item.request.purpose}</p>
                            <p className="mt-0.5 text-xs text-mist-500">
                              {item.request.model ?? 'Unknown model'}
                              {item.note ? ` · “${item.note}”` : ''}
                            </p>
                          </div>
                          <div className="flex items-center gap-3">
                            <button
                              type="button"
                              onClick={() => setOpenThread((current) => (current === item.id ? null : item.id))}
                              aria-expanded={openThread === item.id}
                              className="text-xs font-medium text-accent-400 underline-offset-2 hover:underline"
                            >
                              {openThread === item.id ? 'Hide activity' : 'Activity'}
                            </button>
                            <span className={`rounded-full border px-2.5 py-1 text-[11px] font-bold tracking-[0.12em] ${statusTone[item.status]}`}>
                              {item.status.toUpperCase()}
                            </span>
                          </div>
                        </div>
                        {openThread === item.id ? <ApprovalThread approvalId={item.id} canComment={false} /> : null}
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
