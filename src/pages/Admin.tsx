import { Bot, Building2, KeyRound, Loader2, Pencil, Plus, ShieldAlert, Trash2, Users } from 'lucide-react';
import { useCallback, useEffect, useRef, useState } from 'react';
import { Link } from 'react-router-dom';
import { getActiveOrganizationId, getLocalUserId, getSupabase, getSupabaseUrl, isSupabaseConfigured } from '../lib/supabase';
import { createAgent, deleteAgent, listAgents, setAgentStatus } from '../services/aiAgentService';
import { createApiKey, listApiKeys, revokeApiKey, type ApiKeyItem } from '../services/apiKeysService';
import { createPolicy, type PolicyDraft } from '../services/policyService';
import type { OrganizationRow } from '../lib/db';
import type { Agent } from '../types';
import {
  MEMBER_ROLES,
  addClient,
  addMember,
  deleteOrganization,
  deletePolicy,
  forceLogoutMember,
  getGateMembership,
  getMemberStats,
  listAdminPolicies,
  listMembers,
  removeMember,
  renameOrganization,
  setMemberRole,
  setPolicyStatus,
  switchOrganization,
  type AdminMember,
  type AdminPolicy,
  type MemberStats,
} from '../services/adminService';
import { getMyOrganizations } from '../services/organizationService';
import type { Decision } from '../types';

const tabs = [
  { id: 'clients', label: 'Clients', icon: Building2 },
  { id: 'members', label: 'Members', icon: Users },
  { id: 'policies', label: 'Policies', icon: ShieldAlert },
  { id: 'agents', label: 'Agents', icon: Bot },
  { id: 'keys', label: 'API Keys', icon: KeyRound },
] as const;

type TabId = (typeof tabs)[number]['id'];

const inputCls =
  'w-full rounded-xl border border-line bg-ink-950/70 px-3 py-2.5 text-sm text-mist-100 placeholder:text-mist-600 focus:border-accent-400/60 focus:outline-none';
const btnPrimary =
  'rounded-xl bg-accent-500 px-4 py-2.5 text-sm font-semibold text-accent-ink transition hover:bg-accent-400 disabled:cursor-not-allowed disabled:opacity-60';
const btnGhost =
  'rounded-xl border border-line px-3 py-1.5 text-xs font-medium text-mist-300 transition hover:border-line-strong hover:text-mist-100';
const cardCls = 'rounded-xl border border-line bg-ink-950/60 p-5';

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div>
      <label className="text-xs font-semibold uppercase tracking-[0.16em] text-mist-500">{label}</label>
      <div className="mt-2">{children}</div>
    </div>
  );
}

/** Owner/admin-only control panel: clients, members, policies, agents, API keys. */
export function Admin() {
  // Temporary UI lock (demo only): the real security is the owner/admin role
  // check below plus Supabase RLS. These credentials live in client code.
  const [unlocked, setUnlocked] = useState(
    () => sessionStorage.getItem('dcp-admin-unlocked') === '1',
  );
  const [loginId, setLoginId] = useState('');
  const [loginPass, setLoginPass] = useState('');
  const [loginError, setLoginError] = useState<string | null>(null);
  const [gate, setGate] = useState<'loading' | 'denied' | 'allowed'>('loading');
  const [gateError, setGateError] = useState<string | null>(null);
  const [gateRole, setGateRole] = useState<string | null>(null);
  const [connTest, setConnTest] = useState<string | null>(null);
  const gateStepRef = useRef('starting');

  const testConnection = useCallback(async () => {
    setConnTest('Testing…');
    try {
      const baseUrl = getSupabaseUrl();
      if (!baseUrl) {
        setConnTest('Supabase is not configured.');
        return;
      }
      const started = Date.now();
      const res = await fetch(`${baseUrl}/rest/v1/`, {
        signal: AbortSignal.timeout(10000),
      });
      setConnTest(
        `Reached the database server (status ${res.status}) in ${((Date.now() - started) / 1000).toFixed(1)}s.`,
      );
    } catch (err) {
      setConnTest(
        `Could NOT reach the database server: ${err instanceof Error ? err.message : 'request failed'}. If this persists, try a different network (e.g. mobile hotspot).`,
      );
    }
  }, []);
  const [tab, setTab] = useState<TabId>('clients');
  const [orgs, setOrgs] = useState<OrganizationRow[]>([]);
  const [activeOrgId, setActiveOrgId] = useState<string | null>(null);
  const [members, setMembers] = useState<AdminMember[]>([]);
  const [memberStats, setMemberStats] = useState<MemberStats | null>(null);
  const [policies, setPolicies] = useState<AdminPolicy[]>([]);
  const [agents, setAgents] = useState<Agent[]>([]);
  const [keys, setKeys] = useState<ApiKeyItem[]>([]);
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  // Forms
  const [newOrgName, setNewOrgName] = useState('');
  const [editingOrg, setEditingOrg] = useState<{ id: string; name: string } | null>(null);
  const [newPolicy, setNewPolicy] = useState({ name: '', description: '', effect: 'BLOCK' as Decision });
  const [newAgent, setNewAgent] = useState({ name: '', description: '' });
  const [newMemberId, setNewMemberId] = useState('');
  const [newMemberRole, setNewMemberRole] = useState<string>('viewer');
  const [newKeyName, setNewKeyName] = useState('');
  const [createdKey, setCreatedKey] = useState<{ name: string; key: string } | null>(null);
  const [copiedKey, setCopiedKey] = useState(false);

  const refresh = useCallback(async () => {
    const supabase = getSupabase();
    if (!supabase) return;
    const orgId = await getActiveOrganizationId();
    setActiveOrgId(orgId);
    if (!orgId) {
      setOrgs([]);
      setMembers([]);
      setPolicies([]);
      setAgents([]);
      setKeys([]);
      setMemberStats(null);
      return;
    }
    const [orgList, memberList, policyList, agentList, keyList] = await Promise.all([
      getMyOrganizations(),
      listMembers(orgId),
      listAdminPolicies(orgId),
      listAgents().catch(() => [] as Agent[]),
      listApiKeys().catch(() => [] as ApiKeyItem[]),
    ]);
    setOrgs(orgList);
    setMembers(memberList);
    setPolicies(policyList);
    setAgents(agentList);
    setKeys(keyList);
    getMemberStats(orgId)
      .then(setMemberStats)
      .catch(() => setMemberStats(null));
  }, []);

  useEffect(() => {
    let cancelled = false;
    let finished = false;
    const finish = (state: 'denied' | 'allowed', errMsg: string | null) => {
      if (cancelled || finished) return;
      finished = true;
      window.clearTimeout(timer);
      setGateError(errMsg);
      setGate(state);
    };
    // Never leave the user staring at "Checking access..." — bail out with a retry.
    // The step name makes the next failure diagnosable instead of a mystery.
    const timer = window.setTimeout(() => {
      const step = gateStepRef.current;
      finish(
        'denied',
        `The access check timed out${step && step !== 'done' ? ` while ${step}` : ''}. Try again — if it keeps happening, sign out and back in.`,
      );
    }, 20000);
    (async () => {
      try {
        if (!isSupabaseConfigured()) {
          finish('denied', 'Supabase is not configured.');
          return;
        }
        const supabase = getSupabase();
        if (!supabase) {
          finish('denied', 'Supabase is not configured.');
          return;
        }
        gateStepRef.current = 'reading your login';
        const userId = await getLocalUserId();
        if (cancelled) return;
        if (!userId) {
          finish('denied', null);
          return;
        }
        // One query for workspace + role; it aborts hung requests and retries.
        gateStepRef.current = 'finding your workspace';
        const membership = await getGateMembership(userId).catch(() => null);
        if (cancelled) return;
        if (!membership) {
          finish('denied', 'No workspace found for your account.');
          return;
        }
        gateStepRef.current = 'checking your role';
        const role = membership.role;
        if (role !== 'owner' && role !== 'admin') {
          finish('denied', null);
          return;
        }
        setGateRole(role);
        gateStepRef.current = 'done';
        finish('allowed', null);
        await refresh().catch((err: unknown) => {
          if (!cancelled) setError(err instanceof Error ? err.message : 'Could not load admin data.');
        });
      } catch (err: unknown) {
        finish(
          'denied',
          err instanceof Error ? err.message : 'The access check failed. Please try again.',
        );
      }
    })();
    return () => {
      cancelled = true;
      window.clearTimeout(timer);
    };
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

  const handleCreateKey = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newKeyName.trim() || busy) return;
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      const result = await createApiKey(newKeyName.trim(), null);
      setCreatedKey({ name: newKeyName.trim(), key: result.key });
      setNewKeyName('');
      setCopiedKey(false);
      await refresh();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Could not create the API key.');
    } finally {
      setBusy(false);
    }
  };

  const copyCreatedKey = () => {
    if (!createdKey) return;
    void navigator.clipboard.writeText(createdKey.key).then(() => {
      setCopiedKey(true);
      window.setTimeout(() => setCopiedKey(false), 1500);
    });
  };

  if (!unlocked) {
    return (
      <div className="mx-auto max-w-md px-4 pt-32 sm:px-6">
        <p className="text-xs font-semibold uppercase tracking-[0.2em] text-accent-600">Admin</p>
        <h1 className="mt-3 text-2xl font-bold tracking-tight text-mist-100">
          Enter admin credentials
        </h1>
        <form
          className={`mt-6 space-y-4 ${cardCls}`}
          onSubmit={(e) => {
            e.preventDefault();
            if (loginId === 'admin' && loginPass === 'pass') {
              sessionStorage.setItem('dcp-admin-unlocked', '1');
              setLoginError(null);
              setUnlocked(true);
            } else {
              setLoginError('Wrong ID or password.');
            }
          }}
        >
          <Field label="ID">
            <input
              autoFocus
              value={loginId}
              onChange={(e) => setLoginId(e.target.value)}
              autoComplete="username"
              className={inputCls}
              placeholder="admin"
            />
          </Field>
          <Field label="Password">
            <input
              type="password"
              value={loginPass}
              onChange={(e) => setLoginPass(e.target.value)}
              autoComplete="current-password"
              className={inputCls}
              placeholder="••••"
            />
          </Field>
          {loginError ? <p className="text-sm text-rose-400">{loginError}</p> : null}
          <button type="submit" className={`${btnPrimary} w-full`}>
            Unlock admin panel
          </button>
        </form>
      </div>
    );
  }

  if (gate === 'loading') {
    return (
      <div className="mx-auto flex max-w-7xl items-center gap-3 px-4 pt-32 text-mist-400">
        <Loader2 size={18} className="animate-spin" /> Checking access…
      </div>
    );
  }

  if (gate === 'denied') {
    return (
      <div className="mx-auto max-w-7xl px-4 pt-32 sm:px-6 lg:px-8">
        <h1 className="text-2xl font-bold text-mist-100">Admin panel</h1>
        <p className="mt-3 max-w-xl text-mist-400">
          This area is for workspace owners and admins. Sign in with an owner or admin account to
          manage clients, members, policies, agents, and API keys.
        </p>
        {gateError ? <p className="mt-3 max-w-xl text-sm text-rose-400">{gateError}</p> : null}
        <div className="mt-6 flex flex-wrap gap-3">
          <button type="button" onClick={() => window.location.reload()} className={btnGhost}>
            Try again
          </button>
          <Link to="/app" className={btnGhost}>
            Back to console
          </Link>
          <button type="button" onClick={testConnection} className={btnGhost}>
            Test connection
          </button>
        </div>
        {connTest ? <p className="mt-3 max-w-xl text-xs text-mist-400">{connTest}</p> : null}
      </div>
    );
  }

  const activeOrg = orgs.find((o) => o.id === activeOrgId);

  return (
    <div className="mx-auto max-w-7xl px-4 pt-24 sm:px-6 lg:px-8 lg:pt-28">
      <p className="text-xs font-semibold uppercase tracking-[0.2em] text-accent-600">Admin</p>
      <h1 className="mt-3 text-3xl font-bold tracking-tight text-mist-100 sm:text-4xl">
        Control everything.
      </h1>
      <p className="mt-3 max-w-2xl text-base text-mist-400">
        Managing <span className="text-mist-200">{activeOrg?.name ?? '…'}</span> — clients,
        members, policies, agents, and API keys.
      </p>

      {notice ? (
        <p className="mt-4 rounded-xl border border-mint-400/30 bg-mint-400/10 px-4 py-2.5 text-sm text-mint-400">
          {notice}
        </p>
      ) : null}
      {error ? (
        <p className="mt-4 rounded-xl border border-rose-400/30 bg-rose-400/10 px-4 py-2.5 text-sm text-rose-400">
          {error}
        </p>
      ) : null}

      <div className="mt-6 flex flex-wrap gap-2" role="tablist" aria-label="Admin sections">
        {tabs.map((t) => (
          <button
            key={t.id}
            type="button"
            role="tab"
            aria-selected={tab === t.id}
            onClick={() => setTab(t.id)}
            className={`flex items-center gap-2 rounded-full border px-4 py-2 text-sm font-medium transition ${
              tab === t.id
                ? 'border-accent-400/60 bg-accent-500/15 text-mist-100'
                : 'border-line text-mist-400 hover:border-line-strong hover:text-mist-100'
            }`}
          >
            <t.icon size={14} />
            {t.label}
          </button>
        ))}
      </div>

      <div className="mt-6 pb-20">
        {tab === 'clients' ? (
          <div className="grid gap-6 lg:grid-cols-[1fr_1fr]">
            <div className={cardCls}>
              <h2 className="text-sm font-semibold text-mist-100">Your clients</h2>
              <div className="mt-4 space-y-3">
                {orgs.map((org) => (
                  <div
                    key={org.id}
                    className="flex items-center justify-between gap-3 rounded-xl border border-line bg-ink-900/70 px-4 py-3"
                  >
                    <div className="min-w-0">
                      {editingOrg?.id === org.id ? (
                        <input
                          autoFocus
                          value={editingOrg.name}
                          onChange={(e) => setEditingOrg({ id: org.id, name: e.target.value })}
                          onKeyDown={(e) => {
                            if (e.key === 'Enter') {
                              void run(
                                () => renameOrganization(org.id, editingOrg.name).then(() => setEditingOrg(null)),
                                'Client renamed.',
                              );
                            }
                            if (e.key === 'Escape') setEditingOrg(null);
                          }}
                          className={inputCls}
                        />
                      ) : (
                        <>
                          <p className="truncate text-sm font-medium text-mist-100">{org.name}</p>
                          <p className="text-xs text-mist-500">
                            {org.plan} · {org.id === activeOrgId ? 'active' : ''}
                          </p>
                        </>
                      )}
                    </div>
                    <div className="flex shrink-0 items-center gap-2">
                      {org.id !== activeOrgId ? (
                        <button
                          type="button"
                          disabled={busy}
                          onClick={() =>
                            run(async () => {
                              switchOrganization(org.id);
                            }, `Switched to ${org.name}.`)
                          }
                          className={btnGhost}
                        >
                          Switch
                        </button>
                      ) : null}
                      <button
                        type="button"
                        disabled={busy}
                        onClick={() => setEditingOrg({ id: org.id, name: org.name })}
                        className={btnGhost}
                        aria-label={`Rename ${org.name}`}
                      >
                        <Pencil size={13} />
                      </button>
                      {gateRole === 'owner' ? (
                        <button
                          type="button"
                          disabled={busy}
                          onClick={() => {
                            if (
                              window.confirm(
                                `Delete client "${org.name}"? This permanently removes the workspace and everything in it.`,
                              )
                            ) {
                              void run(() => deleteOrganization(org.id), 'Client deleted.');
                            }
                          }}
                          className={`${btnGhost} inline-flex items-center gap-1.5 text-rose-400 hover:text-rose-300`}
                          aria-label={`Delete ${org.name}`}
                        >
                          <Trash2 size={13} />
                        </button>
                      ) : null}
                    </div>
                  </div>
                ))}
                {orgs.length === 0 ? (
                  <p className="text-sm text-mist-500">No organizations yet.</p>
                ) : null}
              </div>
            </div>
            <div className={cardCls}>
              <h2 className="text-sm font-semibold text-mist-100">Add a client</h2>
              <p className="mt-1 text-xs text-mist-500">
                Creates a new workspace and makes you its owner. It becomes your active client.
              </p>
              <form
                className="mt-4 space-y-4"
                onSubmit={(e) => {
                  e.preventDefault();
                  if (!newOrgName.trim()) return;
                  void run(() => addClient(newOrgName).then(() => setNewOrgName('')), 'Client created.');
                }}
              >
                <Field label="Client name">
                  <input
                    value={newOrgName}
                    onChange={(e) => setNewOrgName(e.target.value)}
                    placeholder="Acme Corp"
                    className={inputCls}
                  />
                </Field>
                <button type="submit" disabled={busy || !newOrgName.trim()} className={btnPrimary}>
                  <span className="inline-flex items-center gap-2">
                    <Plus size={14} /> Add client
                  </span>
                </button>
              </form>
            </div>
          </div>
        ) : null}

        {tab === 'members' ? (
          <div className="grid gap-6 lg:grid-cols-[1fr_1fr]">
            <div className={cardCls}>
              <h2 className="text-sm font-semibold text-mist-100">Members of {activeOrg?.name}</h2>
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
                            () =>
                              activeOrgId
                                ? forceLogoutMember(activeOrgId, member.id, member.user_id)
                                : Promise.reject(new Error('No active client.')),
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
                </div>
              ))}
              {members.length === 0 ? <p className="text-sm text-mist-500">No members.</p> : null}
            </div>
            </div>
            <div className={cardCls}>
              <h2 className="text-sm font-semibold text-mist-100">Add member</h2>
              <p className="mt-1 text-xs text-mist-500">
                The person must already have an account — ask them to copy their user ID from
                Account (top-right) and paste it here.
              </p>
              <form
                className="mt-4 space-y-4"
                onSubmit={(e) => {
                  e.preventDefault();
                  if (!newMemberId.trim() || !activeOrgId) return;
                  void run(
                    () =>
                      addMember(activeOrgId, newMemberId, newMemberRole).then(() => {
                        setNewMemberId('');
                        setNewMemberRole('viewer');
                      }),
                    'Member added.',
                  );
                }}
              >
                <Field label="User ID">
                  <input
                    value={newMemberId}
                    onChange={(e) => setNewMemberId(e.target.value)}
                    placeholder="e.g. 3f9a2c1d-…"
                    className={`${inputCls} font-mono`}
                  />
                </Field>
                <Field label="Role">
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
                </Field>
                <button type="submit" disabled={busy || !newMemberId.trim()} className={btnPrimary}>
                  <span className="inline-flex items-center gap-2">
                    <Plus size={14} /> Add member
                  </span>
                </button>
              </form>
            </div>
          </div>
        ) : null}

        {tab === 'policies' ? (
          <div className="grid gap-6 lg:grid-cols-[1fr_1fr]">
            <div className={cardCls}>
              <h2 className="text-sm font-semibold text-mist-100">Policies</h2>
              <div className="mt-4 space-y-3">
                {policies.map((policy) => (
                  <div
                    key={policy.id}
                    className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-line bg-ink-900/70 px-4 py-3"
                  >
                    <div className="min-w-0">
                      <p className="truncate text-sm font-medium text-mist-100">{policy.name}</p>
                      <p className="text-xs text-mist-500">
                        {policy.action} · priority {policy.priority} · {policy.status}
                      </p>
                    </div>
                    <div className="flex items-center gap-2">
                      <button
                        type="button"
                        disabled={busy}
                        onClick={() =>
                          void run(
                            () =>
                              setPolicyStatus(
                                policy.id,
                                policy.status === 'active' ? 'paused' : 'active',
                              ),
                            policy.status === 'active' ? 'Policy paused.' : 'Policy activated.',
                          )
                        }
                        className={btnGhost}
                      >
                        {policy.status === 'active' ? 'Pause' : 'Activate'}
                      </button>
                      <button
                        type="button"
                        disabled={busy}
                        onClick={() => {
                          if (window.confirm(`Delete policy "${policy.name}"?`)) {
                            void run(() => deletePolicy(policy.id), 'Policy deleted.');
                          }
                        }}
                        className={`${btnGhost} inline-flex items-center gap-1.5 text-rose-400 hover:text-rose-300`}
                        aria-label={`Delete ${policy.name}`}
                      >
                        <Trash2 size={13} />
                      </button>
                    </div>
                  </div>
                ))}
                {policies.length === 0 ? <p className="text-sm text-mist-500">No policies yet.</p> : null}
              </div>
            </div>
            <div className={cardCls}>
              <h2 className="text-sm font-semibold text-mist-100">Create policy</h2>
              <p className="mt-1 text-xs text-mist-500">
                Quick policy with no conditions (matches every request). Fine-tune conditions in the
                Policy Engine.
              </p>
              <form
                className="mt-4 space-y-4"
                onSubmit={(e) => {
                  e.preventDefault();
                  const draft: PolicyDraft = {
                    name: newPolicy.name.trim(),
                    description: newPolicy.description.trim(),
                    effect: newPolicy.effect,
                    conditions: [],
                  };
                  if (!draft.name) return;
                  void run(
                    () =>
                      createPolicy(draft).then(() =>
                        setNewPolicy({ name: '', description: '', effect: 'BLOCK' }),
                      ),
                    'Policy created.',
                  );
                }}
              >
                <Field label="Name">
                  <input
                    value={newPolicy.name}
                    onChange={(e) => setNewPolicy({ ...newPolicy, name: e.target.value })}
                    placeholder="Block external AI for finance"
                    className={inputCls}
                  />
                </Field>
                <Field label="Description">
                  <input
                    value={newPolicy.description}
                    onChange={(e) => setNewPolicy({ ...newPolicy, description: e.target.value })}
                    placeholder="Why this policy exists"
                    className={inputCls}
                  />
                </Field>
                <Field label="Effect">
                  <select
                    value={newPolicy.effect}
                    onChange={(e) =>
                      setNewPolicy({
                        ...newPolicy,
                        effect: e.target.value as 'ALLOW' | 'BLOCK' | 'REDACT',
                      })
                    }
                    className={inputCls}
                  >
                    <option value="BLOCK">Block</option>
                    <option value="ALLOW">Allow</option>
                    <option value="REDACT">Send to review</option>
                  </select>
                </Field>
                <button type="submit" disabled={busy || !newPolicy.name.trim()} className={btnPrimary}>
                  <span className="inline-flex items-center gap-2">
                    <Plus size={14} /> Create policy
                  </span>
                </button>
              </form>
            </div>
          </div>
        ) : null}

        {tab === 'agents' ? (
          <div className="grid gap-6 lg:grid-cols-[1fr_1fr]">
            <div className={cardCls}>
              <h2 className="text-sm font-semibold text-mist-100">AI agents</h2>
              <p className="mt-1 text-xs text-mist-500">
                Pause an agent to stop it from being evaluated, or resume it.
              </p>
              <div className="mt-4 space-y-3">
                {agents.map((agent) => (
                  <div
                    key={agent.id}
                    className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-line bg-ink-900/70 px-4 py-3"
                  >
                    <div>
                      <p className="text-sm font-medium text-mist-100">{agent.name}</p>
                      <p className="text-xs text-mist-500">{agent.status}</p>
                    </div>
                    <div className="flex items-center gap-2">
                      <button
                        type="button"
                        disabled={busy}
                        onClick={() =>
                          void run(
                            () =>
                              setAgentStatus(
                                agent.id,
                                agent.status === 'Active' ? 'paused' : 'active',
                              ),
                            agent.status === 'Active' ? 'Agent paused.' : 'Agent resumed.',
                          )
                        }
                        className={btnGhost}
                      >
                        {agent.status === 'Active' ? 'Pause' : 'Resume'}
                      </button>
                      <button
                        type="button"
                        disabled={busy}
                        onClick={() => {
                          if (window.confirm(`Delete agent "${agent.name}"?`)) {
                            void run(() => deleteAgent(agent.id), 'Agent deleted.');
                          }
                        }}
                        className={`${btnGhost} inline-flex items-center gap-1.5 text-rose-400 hover:text-rose-300`}
                        aria-label={`Delete ${agent.name}`}
                      >
                        <Trash2 size={13} />
                      </button>
                    </div>
                  </div>
                ))}
                {agents.length === 0 ? <p className="text-sm text-mist-500">No agents yet.</p> : null}
              </div>
            </div>
            <div className={cardCls}>
              <h2 className="text-sm font-semibold text-mist-100">Add agent</h2>
              <p className="mt-1 text-xs text-mist-500">
                Creates an agent in {activeOrg?.name ?? 'the active client'}.
              </p>
              <form
                className="mt-4 space-y-4"
                onSubmit={(e) => {
                  e.preventDefault();
                  if (!newAgent.name.trim()) return;
                  void run(
                    () =>
                      createAgent(newAgent.name, newAgent.description).then(() =>
                        setNewAgent({ name: '', description: '' }),
                      ),
                    'Agent created.',
                  );
                }}
              >
                <Field label="Name">
                  <input
                    value={newAgent.name}
                    onChange={(e) => setNewAgent({ ...newAgent, name: e.target.value })}
                    placeholder="Support copilot"
                    className={inputCls}
                  />
                </Field>
                <Field label="Description">
                  <input
                    value={newAgent.description}
                    onChange={(e) => setNewAgent({ ...newAgent, description: e.target.value })}
                    placeholder="What this agent does"
                    className={inputCls}
                  />
                </Field>
                <button type="submit" disabled={busy || !newAgent.name.trim()} className={btnPrimary}>
                  <span className="inline-flex items-center gap-2">
                    <Plus size={14} /> Add agent
                  </span>
                </button>
              </form>
            </div>
          </div>
        ) : null}

        {tab === 'keys' ? (
          <div className="grid gap-6 lg:grid-cols-[1fr_1fr]">
            <div className={cardCls}>
              <h2 className="text-sm font-semibold text-mist-100">API keys</h2>
              <p className="mt-1 text-xs text-mist-500">
                Revoke a key to immediately stop API access.
              </p>
              <div className="mt-4 space-y-3">
                {keys.map((key) => (
                  <div
                    key={key.id}
                    className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-line bg-ink-900/70 px-4 py-3"
                  >
                    <div>
                      <p className="text-sm font-medium text-mist-100">{key.name}</p>
                      <p className="text-xs text-mist-500">
                        {key.revoked_at ? 'revoked' : 'active'} · created{' '}
                        {new Date(key.created_at).toLocaleDateString()}
                      </p>
                    </div>
                    {!key.revoked_at ? (
                      <button
                        type="button"
                        disabled={busy}
                        onClick={() => {
                          if (window.confirm(`Revoke API key "${key.name}"?`)) {
                            void run(() => revokeApiKey(key.id), 'API key revoked.');
                          }
                        }}
                        className={`${btnGhost} inline-flex items-center gap-1.5 text-rose-400 hover:text-rose-300`}
                      >
                        <Trash2 size={13} /> Revoke
                      </button>
                    ) : null}
                  </div>
                ))}
                {keys.length === 0 ? <p className="text-sm text-mist-500">No API keys yet.</p> : null}
              </div>
            </div>
            <div className={cardCls}>
              <h2 className="text-sm font-semibold text-mist-100">New API key</h2>
              <p className="mt-1 text-xs text-mist-500">
                The plaintext is shown once. Only a hash is stored.
              </p>
              {createdKey ? (
                <div className="mt-4 space-y-4">
                  <div className="rounded-xl border border-amber-400/30 bg-amber-400/10 p-4">
                    <p className="text-sm text-mist-200">
                      Copy it now — it will never be shown again.
                    </p>
                  </div>
                  <div className="flex items-center justify-between gap-3 rounded-xl border border-line bg-ink-900/80 px-4 py-3">
                    <code className="overflow-x-auto font-mono text-sm text-mist-100">
                      {createdKey.key}
                    </code>
                    <button type="button" onClick={copyCreatedKey} className={btnGhost}>
                      {copiedKey ? 'Copied' : 'Copy'}
                    </button>
                  </div>
                  <button
                    type="button"
                    onClick={() => setCreatedKey(null)}
                    className={`${btnPrimary} w-full`}
                  >
                    I've stored it safely
                  </button>
                </div>
              ) : (
                <form className="mt-4 space-y-4" onSubmit={handleCreateKey}>
                  <Field label="Key name">
                    <input
                      value={newKeyName}
                      onChange={(e) => setNewKeyName(e.target.value)}
                      placeholder="Backend ingest"
                      className={inputCls}
                    />
                  </Field>
                  <button type="submit" disabled={busy || !newKeyName.trim()} className={btnPrimary}>
                    <span className="inline-flex items-center gap-2">
                      <Plus size={14} /> New key
                    </span>
                  </button>
                </form>
              )}
            </div>
          </div>
        ) : null}
      </div>
    </div>
  );
}
