import { FlaskConical, History, Pause, Play, Plus, Trash2 } from 'lucide-react';
import { useEffect, useState } from 'react';
import { Modal } from '../components/Modal';
import { PolicyBuilderModal } from '../components/PolicyModals';
import { PolicyTestModal } from '../components/PolicyTestModal';
import { Reveal } from '../components/Reveal';
import { SectionHeading } from '../components/SectionHeading';
import { isSupabaseConfigured } from '../lib/supabase';
import {
  createPolicy,
  deletePolicy,
  getPolicyVersions,
  listPolicies,
  rollbackPolicy,
  setPolicyStatus,
  type PolicyDraft,
  type PolicyVersion,
} from '../services/policyService';
import type { Policy } from '../types';

const effectTone: Record<Policy['effect'], string> = {
  ALLOW: 'border-mint-400/30 bg-mint-400/10 text-mint-400',
  BLOCK: 'border-rose-400/30 bg-rose-400/10 text-rose-400',
  MASK: 'border-sky-400/30 bg-sky-400/10 text-sky-400',
  REDACT: 'border-amber-400/30 bg-amber-400/10 text-amber-400',
};

function PolicyHistoryModal({
  policy,
  onClose,
  onRolledBack,
}: {
  policy: Policy | null;
  onClose: () => void;
  onRolledBack: () => void;
}) {
  const [versions, setVersions] = useState<PolicyVersion[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [busyVersion, setBusyVersion] = useState<number | null>(null);

  useEffect(() => {
    if (!policy) return;
    let cancelled = false;
    setLoading(true);
    setError(null);
    getPolicyVersions(policy.id)
      .then((loaded) => {
        if (!cancelled) setVersions(loaded);
      })
      .catch(() => {
        if (!cancelled) setError('Could not load the policy history.');
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [policy]);

  const handleRollback = async (version: PolicyVersion) => {
    if (!policy) return;
    const latest = versions[0]?.version ?? version.version;
    if (
      !window.confirm(
        `Roll back "${policy.name}" to v${version.version}? This restores that snapshot as v${latest + 1}.`,
      )
    ) {
      return;
    }
    setBusyVersion(version.version);
    setError(null);
    try {
      await rollbackPolicy(policy.id, version.version, `Rolled back to v${version.version}`);
      onRolledBack();
      setVersions(await getPolicyVersions(policy.id));
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Could not roll back the policy.');
    } finally {
      setBusyVersion(null);
    }
  };

  const latestVersion = versions[0]?.version;

  return (
    <Modal
      open={policy !== null}
      title={policy ? `History — ${policy.name}` : 'Policy history'}
      subtitle="Every meaningful edit leaves an immutable snapshot. Rolling back restores a snapshot as a new version."
      onClose={onClose}
      wide
    >
      {loading ? (
        <p className="text-sm text-mist-500">Loading history…</p>
      ) : error && versions.length === 0 ? (
        <p className="text-sm text-rose-400">{error}</p>
      ) : (
        <ul className="space-y-2">
          {versions.map((version) => (
            <li
              key={version.id}
              className="flex flex-wrap items-center justify-between gap-3 rounded-lg border border-line bg-ink-950/60 px-4 py-3"
            >
              <div className="min-w-0">
                <div className="flex items-center gap-2">
                  <span className="rounded-full border border-line bg-ink-900 px-2.5 py-0.5 text-[11px] font-bold tracking-[0.12em] text-mist-200">
                    v{version.version}
                  </span>
                  <span className="truncate text-sm font-medium text-mist-100">
                    {version.name ?? '(deleted)'}
                  </span>
                </div>
                <p className="mt-1 text-xs text-mist-500">
                  {new Date(version.published_at).toLocaleString()}
                  {version.published_by ? ` · by ${version.published_by.slice(0, 8)}` : ''}
                  {version.change_note ? ` · ${version.change_note}` : ''}
                </p>
              </div>
              <button
                type="button"
                disabled={busyVersion !== null || version.version === latestVersion}
                onClick={() => void handleRollback(version)}
                title={
                  version.version === latestVersion
                    ? 'Already the current version'
                    : `Roll back to v${version.version}`
                }
                className="inline-flex items-center gap-1 rounded-lg border border-line px-2.5 py-1.5 text-xs text-mist-400 transition hover:border-line-strong hover:text-mist-100 disabled:cursor-not-allowed disabled:opacity-40"
              >
                {busyVersion === version.version ? 'Rolling back…' : 'Roll back'}
              </button>
            </li>
          ))}
        </ul>
      )}
      {error && versions.length > 0 ? <p className="mt-3 text-sm text-rose-400">{error}</p> : null}
    </Modal>
  );
}

export function PolicyEngine() {
  const [policies, setPolicies] = useState<Policy[]>([]);
  const [open, setOpen] = useState(false);
  const [testPolicy, setTestPolicy] = useState<Policy | null>(null);
  const [historyPolicy, setHistoryPolicy] = useState<Policy | null>(null);
  const [busyId, setBusyId] = useState<string | null>(null);
  const [cardError, setCardError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    listPolicies()
      .then((loaded) => {
        if (!cancelled) setPolicies(loaded);
      })
      .catch(() => {
        /* keep current policies when offline */
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const handleCreate = async (draft: PolicyDraft) => {
    if (!isSupabaseConfigured()) {
      throw new Error('Sign in to save real policies to your workspace.');
    }
    const created = await createPolicy(draft);
    setPolicies((current) => [created, ...current]);
  };

  const handleToggleStatus = async (policy: Policy) => {
    setCardError(null);
    setBusyId(policy.id);
    try {
      const next = policy.status === 'active' ? 'paused' : 'active';
      await setPolicyStatus(policy.id, next);
      setPolicies((current) =>
        current.map((p) => (p.id === policy.id ? { ...p, status: next } : p)),
      );
    } catch (e) {
      setCardError(e instanceof Error ? e.message : 'Could not update the policy.');
    } finally {
      setBusyId(null);
    }
  };

  const handleRolledBack = () => {
    // The rollback bumps the policy version, so reload the list.
    listPolicies()
      .then(setPolicies)
      .catch(() => {
        /* keep current policies when offline */
      });
  };

  const handleDelete = async (policy: Policy) => {
    if (!window.confirm(`Delete the policy "${policy.name}"? This cannot be undone.`)) return;
    setCardError(null);
    setBusyId(policy.id);
    try {
      await deletePolicy(policy.id);
      setPolicies((current) => current.filter((p) => p.id !== policy.id));
    } catch (e) {
      setCardError(e instanceof Error ? e.message : 'Could not delete the policy.');
    } finally {
      setBusyId(null);
    }
  };

  return (
    <section className="mx-auto max-w-7xl px-4 py-20 sm:px-6 lg:px-8 lg:py-28">
      <SectionHeading
        eyebrow="Policy engine"
        title="Turn security rules into enforceable AI policies."
        description="Plain-language rules become deterministic decisions on every AI request."
      />

      <div className="mt-12 grid gap-4 md:grid-cols-2 lg:grid-cols-3">
        {policies.length === 0 ? (
          <div className="rounded-xl border border-dashed border-line bg-ink-900/40 p-8 text-center md:col-span-2 lg:col-span-3">
            <p className="text-sm font-semibold text-mist-200">No policies yet.</p>
            <p className="mt-1 text-sm text-mist-500">
              Create your first policy below to start protecting AI requests.
            </p>
          </div>
        ) : null}
        {policies.map((policy, index) => (
          <Reveal key={policy.id} delay={index * 0.06}>
            <div className="flex h-full flex-col rounded-xl border border-line bg-ink-900/60 p-6 shadow-card transition hover:border-line-strong">
              <div className="flex items-center justify-between gap-3">
                <h3 className="text-base font-semibold text-mist-100">{policy.name}</h3>
                <div className="flex shrink-0 items-center gap-2">
                  {policy.status !== 'active' ? (
                    <span className="rounded-full border border-amber-400/30 bg-amber-400/10 px-2.5 py-1 text-[11px] font-bold tracking-[0.12em] text-amber-400">
                      PAUSED
                    </span>
                  ) : null}
                  <span
                    className="rounded-full border border-line bg-ink-950/70 px-2.5 py-1 text-[11px] font-bold tracking-[0.12em] text-mist-300"
                    title={`Version ${policy.version}`}
                  >
                    v{policy.version}
                  </span>
                  <span
                    className={`rounded-full border px-2.5 py-1 text-[11px] font-bold tracking-[0.12em] ${effectTone[policy.effect]}`}
                  >
                    {policy.effect}
                  </span>
                </div>
              </div>
              <p className="mt-2 text-sm text-mist-400">{policy.description}</p>
              <div className="mt-5 space-y-2 text-sm">
                <p className="text-xs font-semibold uppercase tracking-[0.18em] text-mist-600">If</p>
                {policy.conditions.map((condition, conditionIndex) => (
                  <div key={`${condition.field}-${conditionIndex}`} className="flex items-center gap-2">
                    {conditionIndex > 0 ? (
                      <span className="text-[11px] font-bold text-accent-600">AND</span>
                    ) : null}
                    <span className="rounded-lg border border-line bg-ink-950/70 px-2.5 py-1.5 text-xs text-mist-200">
                      {condition.field} {condition.operator} {condition.value}
                    </span>
                  </div>
                ))}
                <p className="pt-2 text-xs font-semibold uppercase tracking-[0.18em] text-mist-600">Then</p>
                <p className="text-sm text-mist-200">{policy.action}</p>
              </div>
              <div className="mt-auto flex items-center justify-between gap-2 pt-5">
                <p className="text-xs text-mist-600">Updated {policy.updated}</p>
                <div className="flex items-center gap-1.5">
                  <button
                    type="button"
                    onClick={() => setTestPolicy(policy)}
                    title="Test this policy against a sample request"
                    aria-label={`Test ${policy.name}`}
                    className="inline-flex items-center gap-1 rounded-lg border border-line px-2 py-1.5 text-xs text-mist-400 transition hover:border-line-strong hover:text-mist-100"
                  >
                    <FlaskConical size={12} /> Test
                  </button>
                  <button
                    type="button"
                    onClick={() => setHistoryPolicy(policy)}
                    title="View version history and roll back"
                    aria-label={`History of ${policy.name}`}
                    className="inline-flex items-center gap-1 rounded-lg border border-line px-2 py-1.5 text-xs text-mist-400 transition hover:border-line-strong hover:text-mist-100"
                  >
                    <History size={12} /> History
                  </button>
                  <button
                    type="button"
                    disabled={busyId === policy.id}
                    onClick={() => void handleToggleStatus(policy)}
                    title={policy.status === 'active' ? 'Pause this policy' : 'Resume this policy'}
                    aria-label={policy.status === 'active' ? `Pause ${policy.name}` : `Resume ${policy.name}`}
                    className="inline-flex items-center gap-1 rounded-lg border border-line px-2 py-1.5 text-xs text-mist-400 transition hover:border-line-strong hover:text-mist-100 disabled:opacity-40"
                  >
                    {policy.status === 'active' ? <Pause size={12} /> : <Play size={12} />}
                    {policy.status === 'active' ? 'Pause' : 'Resume'}
                  </button>
                  <button
                    type="button"
                    disabled={busyId === policy.id}
                    onClick={() => void handleDelete(policy)}
                    title="Delete this policy"
                    aria-label={`Delete ${policy.name}`}
                    className="inline-flex items-center gap-1 rounded-lg border border-line px-2 py-1.5 text-xs text-mist-400 transition hover:border-rose-400/50 hover:text-rose-400 disabled:opacity-40"
                  >
                    <Trash2 size={12} /> Delete
                  </button>
                </div>
              </div>
            </div>
          </Reveal>
        ))}
      </div>
      {cardError ? <p className="mt-4 text-center text-sm text-rose-400">{cardError}</p> : null}

      <Reveal className="mt-10 text-center">
        <button
          type="button"
          onClick={() => setOpen(true)}
          className="inline-flex items-center gap-2 rounded-xl border border-line bg-ink-900/60 px-6 py-3.5 text-sm font-semibold text-mist-100 transition hover:border-line-strong hover:bg-ink-800"
        >
          <Plus size={16} /> Create Policy
        </button>
      </Reveal>

      <PolicyBuilderModal
        open={open}
        onClose={() => setOpen(false)}
        onCreate={(draft) => handleCreate(draft)}
      />
      <PolicyTestModal
        open={testPolicy !== null}
        policy={testPolicy}
        onClose={() => setTestPolicy(null)}
      />
      <PolicyHistoryModal
        policy={historyPolicy}
        onClose={() => setHistoryPolicy(null)}
        onRolledBack={handleRolledBack}
      />
    </section>
  );
}
