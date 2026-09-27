import { Check, Eye, Loader2, ShieldCheck } from 'lucide-react';
import { useEffect, useState, type ReactNode } from 'react';
import { getActiveOrganizationId } from '../lib/supabase';
import {
  getActiveOrganization,
  getMyOrganizationRole,
  setEnforcementMode,
  setOrgIndustry,
  type EnforcementMode,
} from '../services/organizationService';

const cardCls = 'rounded-xl border border-line bg-ink-950/60 p-5';
const inputCls =
  'mt-2 w-full rounded-xl border border-line bg-ink-950/70 px-3 py-2.5 text-sm text-mist-100 placeholder:text-mist-600 focus:border-accent-400/60 focus:outline-none';
const secondaryBtn =
  'inline-flex items-center justify-center gap-2 rounded-xl border border-line px-4 py-2.5 text-sm font-semibold text-mist-200 transition hover:border-line-strong hover:text-mist-100 disabled:cursor-not-allowed disabled:opacity-60';

/** Workspace settings: security mode, industry, identity. Owner/admin can edit. */
export function OrgSettingsPanel() {
  const [orgId, setOrgId] = useState<string | null>(null);
  const [orgName, setOrgName] = useState<string | null>(null);
  const [industry, setIndustry] = useState('');
  const [savedIndustry, setSavedIndustry] = useState<string | null>(null);
  const [mode, setMode] = useState<EnforcementMode>('monitor');
  const [canEdit, setCanEdit] = useState(false);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    (async () => {
      try {
        const id = await getActiveOrganizationId();
        setOrgId(id);
        if (!id) return;
        const [org, role] = await Promise.all([
          getActiveOrganization(),
          getMyOrganizationRole(id).catch(() => null),
        ]);
        setOrgName(org?.name ?? null);
        const currentIndustry =
          org && typeof org.settings?.industry === 'string' ? (org.settings.industry as string) : '';
        setIndustry(currentIndustry);
        setSavedIndustry(currentIndustry || null);
        setMode(org?.enforcement_mode ?? 'monitor');
        setCanEdit(role === 'owner' || role === 'admin');
      } catch (err: unknown) {
        setError(err instanceof Error ? err.message : 'Could not load settings.');
      } finally {
        setLoading(false);
      }
    })();
  }, []);

  const handleSaveIndustry = async () => {
    if (!orgId) return;
    setSaving(true);
    setError(null);
    setNotice(null);
    try {
      await setOrgIndustry(orgId, industry.trim());
      setSavedIndustry(industry.trim() || null);
      setNotice('Industry saved.');
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Could not save the industry.');
    } finally {
      setSaving(false);
    }
  };

  const handleChooseMode = async (next: EnforcementMode) => {
    if (!orgId || next === mode) return;
    setSaving(true);
    setError(null);
    setNotice(null);
    try {
      await setEnforcementMode(orgId, next);
      setMode(next);
      setNotice(next === 'monitor' ? 'Monitor mode on — detecting, not blocking.' : 'Enforce mode on — policies now block.');
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Could not change the security mode.');
    } finally {
      setSaving(false);
    }
  };

  if (loading) {
    return (
      <p className="flex items-center gap-2 text-sm text-mist-500">
        <Loader2 size={14} className="animate-spin" /> Loading settings…
      </p>
    );
  }

  if (!orgId) {
    return <p className="text-sm text-mist-500">No workspace selected.</p>;
  }

  const modes: { mode: EnforcementMode; icon: ReactNode; title: string; desc: string }[] = [
    {
      mode: 'monitor',
      icon: <Eye size={16} className="text-accent-400" />,
      title: 'Monitor',
      desc: 'Policies are evaluated and logged, but nothing is blocked.',
    },
    {
      mode: 'enforce',
      icon: <ShieldCheck size={16} className="text-accent-400" />,
      title: 'Enforce',
      desc: 'Risky requests are blocked or held for approval.',
    },
  ];

  return (
    <div className="grid gap-6 lg:grid-cols-2">
      <div className={cardCls}>
        <h2 className="text-sm font-semibold text-mist-100">Security mode</h2>
        <p className="mt-1 text-xs text-mist-500">
          Applies to every AI request in {orgName ?? 'this workspace'}. Switching never deletes
          data.
        </p>
        <div className="mt-4 grid grid-cols-1 gap-2 sm:grid-cols-2">
          {modes.map(({ mode: m, icon, title, desc }) => {
            const selected = mode === m;
            return (
              <button
                key={m}
                type="button"
                disabled={!canEdit || saving}
                onClick={() => void handleChooseMode(m)}
                aria-pressed={selected}
                className={`rounded-xl border p-4 text-left transition ${
                  selected
                    ? 'border-accent-400/60 bg-accent-500/10'
                    : 'border-line bg-ink-950/60 hover:border-line-strong'
                } disabled:cursor-not-allowed disabled:opacity-60`}
              >
                <span className="flex items-center gap-2">
                  {icon}
                  <span className="text-sm font-semibold text-mist-100">{title}</span>
                  {selected && <Check size={14} className="text-mint-300" />}
                </span>
                <span className="mt-1.5 block text-xs leading-relaxed text-mist-400">{desc}</span>
              </button>
            );
          })}
        </div>
        {!canEdit && (
          <p className="mt-3 text-xs text-mist-500">Only owners and admins can change this.</p>
        )}
      </div>

      <div className="space-y-6">
        <div className={cardCls}>
          <h2 className="text-sm font-semibold text-mist-100">Workspace</h2>
          <dl className="mt-3 space-y-2 text-sm">
            <div className="flex justify-between gap-4">
              <dt className="text-mist-500">Name</dt>
              <dd className="text-mist-200">{orgName ?? '—'}</dd>
            </div>
            <div className="flex justify-between gap-4">
              <dt className="text-mist-500">Workspace ID</dt>
              <dd className="font-mono text-xs text-mist-400">{orgId.slice(0, 8)}…</dd>
            </div>
          </dl>
          <label className="mt-4 block text-xs font-semibold uppercase tracking-[0.16em] text-mist-500">
            Industry
          </label>
          <input
            value={industry}
            onChange={(e) => setIndustry(e.target.value)}
            placeholder="e.g. Healthcare"
            disabled={!canEdit || saving}
            aria-label="Industry"
            className={inputCls}
          />
          {canEdit && industry.trim() !== (savedIndustry ?? '') && (
            <button
              type="button"
              disabled={saving}
              onClick={() => void handleSaveIndustry()}
              className={`${secondaryBtn} mt-3`}
            >
              {saving ? <Loader2 size={14} className="animate-spin" /> : null}
              Save industry
            </button>
          )}
        </div>
      </div>

      {notice ? (
        <p className="rounded-xl border border-mint-400/30 bg-mint-400/10 px-4 py-2.5 text-sm text-mint-300 lg:col-span-2">
          {notice}
        </p>
      ) : null}
      {error ? (
        <p className="rounded-xl border border-rose-400/30 bg-rose-400/10 px-4 py-2.5 text-sm text-rose-300 lg:col-span-2">
          {error}
        </p>
      ) : null}
    </div>
  );
}
