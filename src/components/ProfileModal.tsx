import { useEffect, useState } from 'react';
import { Building2, Loader2, LogOut, Save, ShieldCheck, UserRound } from 'lucide-react';
import type { OrganizationRow } from '../lib/db';
import { clearOrgCache, getSupabase, isSupabaseConfigured } from '../lib/supabase';
import {
  createOrganization,
  getActiveOrganization,
  getMyOrganizationRole,
  getOrganizationMemberCount,
} from '../services/organizationService';
import { Modal } from './Modal';

interface ProfileModalProps {
  open: boolean;
  onClose: () => void;
  onOpenSetup?: () => void;
}

interface WorkspaceStats {
  sources: number | null;
  policies: number | null;
  agents: number | null;
  requests: number | null;
}

const inputClass =
  'mt-2 w-full rounded-xl border border-line bg-ink-950/70 px-3 py-2.5 text-sm text-mist-100 focus:border-accent-400/60 focus:outline-none';
const labelClass = 'text-xs font-semibold uppercase tracking-[0.16em] text-mist-500';

export function ProfileModal({ open, onClose, onOpenSetup }: ProfileModalProps) {
  const configured = isSupabaseConfigured();
  const [loading, setLoading] = useState(true);
  const [email, setEmail] = useState('');
  const [memberSince, setMemberSince] = useState('');
  const [fullName, setFullName] = useState('');
  const [jobTitle, setJobTitle] = useState('');
  const [department, setDepartment] = useState('');
  const [org, setOrg] = useState<OrganizationRow | null>(null);
  const [role, setRole] = useState<string | null>(null);
  const [memberCount, setMemberCount] = useState<number | null>(null);
  const [stats, setStats] = useState<WorkspaceStats>({ sources: null, policies: null, agents: null, requests: null });
  const [saving, setSaving] = useState(false);
  const [savedNote, setSavedNote] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [orgName, setOrgName] = useState('');
  const [creatingOrg, setCreatingOrg] = useState(false);

  useEffect(() => {
    if (!open || !configured) return;
    let cancelled = false;
    setLoading(true);
    setError(null);
    setSavedNote(false);
    (async () => {
      const supabase = getSupabase();
      if (!supabase) return;
      const {
        data: { user },
      } = await supabase.auth.getUser();
      if (cancelled) return;
      if (!user) {
        setLoading(false);
        return;
      }
      setEmail(user.email ?? '');
      setMemberSince(user.created_at ? new Date(user.created_at).toLocaleDateString() : '');
      const { data: profile } = await supabase
        .from('profiles')
        .select('full_name, job_title, department')
        .eq('id', user.id)
        .maybeSingle();
      if (!cancelled && profile) {
        setFullName(profile.full_name ?? '');
        setJobTitle(profile.job_title ?? '');
        setDepartment(profile.department ?? '');
      }
      const activeOrg = await getActiveOrganization().catch(() => null);
      if (cancelled) return;
      setOrg(activeOrg);
      if (activeOrg) {
        const [myRole, count] = await Promise.all([
          getMyOrganizationRole(activeOrg.id).catch(() => null),
          getOrganizationMemberCount(activeOrg.id).catch(() => null),
        ]);
        if (cancelled) return;
        setRole(myRole);
        setMemberCount(count);
        const tables = ['data_sources', 'policies', 'ai_agents', 'ai_requests'] as const;
        const counts = await Promise.all(
          tables.map((table) =>
            Promise.resolve(
              supabase.from(table).select('id', { count: 'exact', head: true }).eq('organization_id', activeOrg.id),
            )
              .then(({ count: c, error: e }) => (e ? null : (c ?? 0)))
              .catch((): number | null => null),
          ),
        );
        if (cancelled) return;
        setStats({
          sources: counts[0],
          policies: counts[1],
          agents: counts[2],
          requests: counts[3],
        });
      }
      if (!cancelled) setLoading(false);
    })().catch((err: unknown) => {
      if (!cancelled) {
        setError(err instanceof Error ? err.message : 'Could not load your profile.');
        setLoading(false);
      }
    });
    return () => {
      cancelled = true;
    };
  }, [open, configured]);

  const saveProfile = async () => {
    const supabase = getSupabase();
    if (!supabase) return;
    setSaving(true);
    setError(null);
    setSavedNote(false);
    try {
      const {
        data: { user },
      } = await supabase.auth.getUser();
      if (!user) throw new Error('You are not signed in.');
      const { error: updateError } = await supabase
        .from('profiles')
        .update({
          full_name: fullName.trim() || null,
          job_title: jobTitle.trim() || null,
          department: department.trim() || null,
        })
        .eq('id', user.id);
      if (updateError) throw updateError;
      setSavedNote(true);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not save your profile.');
    } finally {
      setSaving(false);
    }
  };

  const handleCreateOrg = async () => {
    if (!orgName.trim()) {
      setError('Give your organization a name first.');
      return;
    }
    setCreatingOrg(true);
    setError(null);
    try {
      await createOrganization(orgName.trim());
      const activeOrg = await getActiveOrganization();
      setOrg(activeOrg);
      if (activeOrg) {
        const [myRole, count] = await Promise.all([
          getMyOrganizationRole(activeOrg.id).catch(() => null),
          getOrganizationMemberCount(activeOrg.id).catch(() => null),
        ]);
        setRole(myRole);
        setMemberCount(count);
      }
      setOrgName('');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not create the organization.');
    } finally {
      setCreatingOrg(false);
    }
  };

  const signOut = async () => {
    const supabase = getSupabase();
    if (!supabase) return;
    await supabase.auth.signOut();
    clearOrgCache();
    onClose();
  };

  const initial = (fullName.trim() || email).charAt(0).toUpperCase() || '?';

  return (
    <Modal open={open} onClose={onClose} title="Profile" subtitle="Your account and workspace." wide>
      {!configured ? (
        <p className="text-sm text-mist-400">
          Connect Supabase (set VITE_SUPABASE_URL and VITE_SUPABASE_ANON_KEY) to use profiles.
        </p>
      ) : loading ? (
        <div className="flex items-center justify-center gap-3 py-12 text-mist-400">
          <Loader2 size={18} className="animate-spin" />
          <span className="text-sm">Loading your profile…</span>
        </div>
      ) : !email ? (
        <p className="text-sm text-mist-400">You are not signed in.</p>
      ) : (
        <div className="space-y-6">
          {/* Identity */}
          <div className="flex items-center gap-4 rounded-xl border border-line bg-ink-950/60 p-5">
            <span className="flex h-14 w-14 shrink-0 items-center justify-center rounded-xl bg-accent-500/20 text-2xl font-bold text-accent-600">
              {initial}
            </span>
            <div className="min-w-0">
              <p className="truncate text-base font-semibold text-mist-100">{fullName.trim() || email}</p>
              <p className="truncate text-sm text-mist-500">{email}</p>
              {memberSince ? <p className="mt-1 text-xs text-mist-600">Member since {memberSince}</p> : null}
            </div>
          </div>

          {/* Editable profile */}
          <div className="rounded-xl border border-line bg-ink-950/60 p-5">
            <div className="flex items-center gap-2">
              <UserRound size={16} className="text-accent-600" />
              <h4 className="text-sm font-semibold text-mist-100">Profile details</h4>
            </div>
            <div className="mt-4 grid gap-4 sm:grid-cols-2">
              <div>
                <label htmlFor="profile-name" className={labelClass}>
                  Full name
                </label>
                <input
                  id="profile-name"
                  value={fullName}
                  onChange={(event) => setFullName(event.target.value)}
                  className={inputClass}
                  placeholder="Ada Lovelace"
                  autoComplete="name"
                />
              </div>
              <div>
                <label htmlFor="profile-title" className={labelClass}>
                  Job title
                </label>
                <input
                  id="profile-title"
                  value={jobTitle}
                  onChange={(event) => setJobTitle(event.target.value)}
                  className={inputClass}
                  placeholder="Security engineer"
                  autoComplete="organization-title"
                />
              </div>
              <div className="sm:col-span-2">
                <label htmlFor="profile-dept" className={labelClass}>
                  Department
                </label>
                <input
                  id="profile-dept"
                  value={department}
                  onChange={(event) => setDepartment(event.target.value)}
                  className={inputClass}
                  placeholder="Platform security"
                />
              </div>
            </div>
            <div className="mt-4 flex items-center gap-3">
              <button
                type="button"
                disabled={saving}
                onClick={() => void saveProfile()}
                className="inline-flex items-center gap-2 rounded-xl bg-accent-500 px-4 py-2.5 text-sm font-semibold text-[#06202a] transition hover:bg-accent-400 disabled:cursor-not-allowed disabled:opacity-60"
              >
                {saving ? <Loader2 size={15} className="animate-spin" /> : <Save size={15} />}
                {saving ? 'Saving…' : 'Save changes'}
              </button>
              {savedNote ? <span className="text-xs text-mint-400">Saved.</span> : null}
            </div>
          </div>

          {/* Organization */}
          <div className="rounded-xl border border-line bg-ink-950/60 p-5">
            <div className="flex items-center gap-2">
              <Building2 size={16} className="text-accent-600" />
              <h4 className="text-sm font-semibold text-mist-100">Organization</h4>
            </div>
            {org ? (
              <div className="mt-4">
                <div className="flex flex-wrap items-center gap-3">
                  <p className="text-base font-semibold text-mist-100">{org.name}</p>
                  {role ? (
                    <span className="inline-flex items-center gap-1.5 rounded-full border border-accent-400/30 bg-accent-500/10 px-2.5 py-1 text-xs font-semibold text-accent-600">
                      <ShieldCheck size={12} />
                      {role}
                    </span>
                  ) : null}
                </div>
                <p className="mt-1 text-xs text-mist-500">
                  Plan: {org.plan}
                  {memberCount !== null ? ` · ${memberCount} member${memberCount === 1 ? '' : 's'}` : ''}
                </p>
                <div className="mt-4 grid grid-cols-2 gap-3 sm:grid-cols-4">
                  {(
                    [
                      ['Data sources', stats.sources],
                      ['Policies', stats.policies],
                      ['AI agents', stats.agents],
                      ['AI requests', stats.requests],
                    ] as const
                  ).map(([label, value]) => (
                    <div key={label} className="rounded-xl border border-line bg-ink-900/60 px-3 py-3 text-center">
                      <p className="text-xl font-bold text-mist-100">{value === null ? '—' : value}</p>
                      <p className="mt-1 text-[11px] uppercase tracking-[0.12em] text-mist-600">{label}</p>
                    </div>
                  ))}
                </div>
              </div>
            ) : (
              <div className="mt-4">
                <p className="text-sm leading-relaxed text-mist-400">
                  You are signed in, but you do not belong to an organization yet. Nothing is broken — create one
                  below and the live dashboard, data sources, policies, and agents will switch on for your workspace.
                </p>
                <div className="mt-4 flex flex-col gap-3 sm:flex-row">
                  <input
                    value={orgName}
                    onChange={(event) => setOrgName(event.target.value)}
                    className="mt-0 flex-1 rounded-xl border border-line bg-ink-950/70 px-3 py-2.5 text-sm text-mist-100 focus:border-accent-400/60 focus:outline-none"
                    placeholder="Acme Technologies"
                    autoComplete="organization"
                  />
                  <button
                    type="button"
                    disabled={creatingOrg}
                    onClick={() => void handleCreateOrg()}
                    className="inline-flex items-center justify-center gap-2 rounded-xl bg-accent-500 px-4 py-2.5 text-sm font-semibold text-[#06202a] transition hover:bg-accent-400 disabled:cursor-not-allowed disabled:opacity-60"
                  >
                    {creatingOrg ? <Loader2 size={15} className="animate-spin" /> : <Building2 size={15} />}
                    {creatingOrg ? 'Creating…' : 'Create organization'}
                  </button>
                </div>
              </div>
            )}
          </div>

          {error ? <p className="text-sm text-rose-400">{error}</p> : null}

          {onOpenSetup && (
            <button
              type="button"
              onClick={() => {
                onClose();
                onOpenSetup();
              }}
              className="inline-flex w-full items-center justify-center gap-2 rounded-xl border border-accent-500/40 bg-accent-500/10 px-4 py-3 text-sm font-semibold text-accent-600 transition hover:border-accent-400/60 hover:text-accent-600"
            >
              <Building2 size={15} />
              Complete workspace setup
            </button>
          )}

          <button
            type="button"
            onClick={() => void signOut()}
            className="inline-flex w-full items-center justify-center gap-2 rounded-xl border border-line px-4 py-3 text-sm font-semibold text-mist-200 transition hover:border-line-strong hover:text-mist-100"
          >
            <LogOut size={15} />
            Sign out
          </button>
        </div>
      )}
    </Modal>
  );
}
