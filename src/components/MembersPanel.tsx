import { Loader2, Plus, Trash2 } from 'lucide-react';
import { useCallback, useEffect, useState } from 'react';
import {
  MEMBER_ROLES,
  addMember,
  forceLogoutMember,
  getMemberStats,
  listMembers,
  removeMember,
  setMemberRole,
  type AdminMember,
  type MemberStats,
} from '../services/adminService';

const cardCls = 'rounded-xl border border-line bg-ink-950/60 p-5';
const inputCls =
  'w-full rounded-xl border border-line bg-ink-950/70 px-3 py-2.5 text-sm text-mist-100 placeholder:text-mist-600 focus:border-accent-400/60 focus:outline-none';
const btnPrimary =
  'rounded-xl bg-accent-500 px-4 py-2.5 text-sm font-semibold text-accent-ink transition hover:bg-accent-400 disabled:cursor-not-allowed disabled:opacity-60';
const btnGhost =
  'rounded-xl border border-line px-3 py-1.5 text-xs font-medium text-mist-300 transition hover:border-line-strong hover:text-mist-100 disabled:cursor-not-allowed disabled:opacity-60';

interface MembersPanelProps {
  orgId: string | null;
  orgName?: string | null;
  /** When true, management actions are hidden (list only). */
  readOnly?: boolean;
}

/** Workspace member management: stats, list, roles, force logout, add, remove. */
export function MembersPanel({ orgId, orgName, readOnly = false }: MembersPanelProps) {
  const [members, setMembers] = useState<AdminMember[]>([]);
  const [memberStats, setMemberStats] = useState<MemberStats | null>(null);
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [newMemberId, setNewMemberId] = useState('');
  const [newMemberRole, setNewMemberRole] = useState<string>('viewer');

  const refresh = useCallback(async () => {
    if (!orgId) {
      setMembers([]);
      setMemberStats(null);
      setLoading(false);
      return;
    }
    setLoading(true);
    try {
      const memberList = await listMembers(orgId);
      setMembers(memberList);
      getMemberStats(orgId)
        .then(setMemberStats)
        .catch(() => setMemberStats(null));
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Could not load members.');
    } finally {
      setLoading(false);
    }
  }, [orgId]);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const run = async (fn: () => Promise<void>, ok: string) => {
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      await fn();
      await refresh();
      setNotice(ok);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Action failed.');
    } finally {
      setBusy(false);
    }
  };

  if (!orgId) {
    return <p className="text-sm text-mist-500">No workspace selected.</p>;
  }

  return (
    <div>
      {notice ? (
        <p className="mb-4 rounded-xl border border-mint-400/30 bg-mint-400/10 px-4 py-2.5 text-sm text-mint-300">
          {notice}
        </p>
      ) : null}
      {error ? (
        <p className="mb-4 rounded-xl border border-rose-400/30 bg-rose-400/10 px-4 py-2.5 text-sm text-rose-300">
          {error}
        </p>
      ) : null}
      <div className="grid gap-6 lg:grid-cols-[1fr_1fr]">
        <div className={cardCls}>
          <h2 className="text-sm font-semibold text-mist-100">
            Members{orgName ? ` of ${orgName}` : ''}
          </h2>
          <div className="mt-4 grid grid-cols-2 gap-3 sm:max-w-md">
            <div className="rounded-xl border border-line bg-ink-900/70 px-4 py-3">
              <p className="text-2xl font-bold text-mist-100">{memberStats?.total ?? '…'}</p>
              <p className="mt-1 text-xs text-mist-500">Total logins (registered)</p>
            </div>
            <div className="rounded-xl border border-line bg-ink-900/70 px-4 py-3">
              <p className="text-2xl font-bold text-mist-100">
                {memberStats ? (memberStats.activeLast24h ?? '—') : '…'}
              </p>
              <p className="mt-1 text-xs text-mist-500">Active in last 24 hours</p>
            </div>
          </div>
          <div className="mt-6 space-y-3">
            {members.length > 0 && members.every((m) => !m.full_name) ? (
              <p className="rounded-xl border border-amber-400/30 bg-amber-400/10 px-4 py-2.5 text-xs text-amber-400">
                Member names need one database update: run{' '}
                <span className="font-mono">supabase/migrations/013_admin_member_reads.sql</span>{' '}
                once in your Supabase SQL editor. The member list below works without it.
              </p>
            ) : null}
            {loading ? (
              <p className="flex items-center gap-2 text-sm text-mist-500">
                <Loader2 size={14} className="animate-spin" /> Loading members…
              </p>
            ) : null}
            {members.map((member) => (
              <div
                key={member.id}
                className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-line bg-ink-900/70 px-4 py-3"
              >
                <div>
                  <p className="text-sm font-medium text-mist-100">
                    {member.full_name ?? `User ${member.user_id.slice(0, 8)}`}
                  </p>
                  <p className="text-xs text-mist-500">
                    {member.status} · joined {new Date(member.created_at).toLocaleDateString()}
                  </p>
                </div>
                {!readOnly && (
                  <div className="flex items-center gap-2">
                    <select
                      value={member.role}
                      disabled={busy}
                      onChange={(e) =>
                        void run(
                          () => setMemberRole(member.id, e.target.value),
                          'Role updated.',
                        )
                      }
                      className="rounded-xl border border-line bg-ink-950/70 px-3 py-1.5 text-xs text-mist-100 focus:border-accent-400/60 focus:outline-none"
                      aria-label="Member role"
                    >
                      {MEMBER_ROLES.map((role) => (
                        <option key={role} value={role}>
                          {role}
                        </option>
                      ))}
                    </select>
                    <button
                      type="button"
                      disabled={busy}
                      onClick={() => {
                        if (
                          window.confirm(
                            'Sign this member out on all their devices? They can sign back in afterwards.',
                          )
                        ) {
                          void run(
                            () => forceLogoutMember(orgId, member.id, member.user_id),
                            'Sign-out requested. Their app will sign them out shortly.',
                          );
                        }
                      }}
                      className={btnGhost}
                    >
                      Log out
                    </button>
                    <button
                      type="button"
                      disabled={busy}
                      onClick={() => {
                        if (window.confirm('Remove this member from the organization?')) {
                          void run(() => removeMember(member.id), 'Member removed.');
                        }
                      }}
                      className={`${btnGhost} inline-flex items-center gap-1.5 text-rose-400 hover:text-rose-300`}
                    >
                      <Trash2 size={13} /> Remove
                    </button>
                  </div>
                )}
              </div>
            ))}
            {!loading && members.length === 0 ? (
              <p className="text-sm text-mist-500">No members.</p>
            ) : null}
          </div>
        </div>
        {!readOnly && (
          <div className={cardCls}>
            <h2 className="text-sm font-semibold text-mist-100">Add member</h2>
            <p className="mt-1 text-xs text-mist-500">
              The person must already have an account — ask them to copy their user ID from Account
              (top-right) and paste it here.
            </p>
            <form
              className="mt-4 space-y-4"
              onSubmit={(e) => {
                e.preventDefault();
                if (!newMemberId.trim() || !orgId) return;
                void run(
                  () =>
                    addMember(orgId, newMemberId, newMemberRole).then(() => {
                      setNewMemberId('');
                      setNewMemberRole('viewer');
                    }),
                  'Member added.',
                );
              }}
            >
              <div>
                <label className="text-xs font-semibold uppercase tracking-[0.16em] text-mist-500">
                  User ID
                </label>
                <div className="mt-2">
                  <input
                    value={newMemberId}
                    onChange={(e) => setNewMemberId(e.target.value)}
                    placeholder="e.g. 3f9a2c1d-…"
                    className={`${inputCls} font-mono`}
                  />
                </div>
              </div>
              <div>
                <label className="text-xs font-semibold uppercase tracking-[0.16em] text-mist-500">
                  Role
                </label>
                <div className="mt-2">
                  <select
                    value={newMemberRole}
                    onChange={(e) => setNewMemberRole(e.target.value)}
                    className={inputCls}
                  >
                    {MEMBER_ROLES.map((role) => (
                      <option key={role} value={role}>
                        {role}
                      </option>
                    ))}
                  </select>
                </div>
              </div>
              <button type="submit" disabled={busy || !newMemberId.trim()} className={btnPrimary}>
                <span className="inline-flex items-center gap-2">
                  <Plus size={14} /> Add member
                </span>
              </button>
            </form>
          </div>
        )}
      </div>
    </div>
  );
}
