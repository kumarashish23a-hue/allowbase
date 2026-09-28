import { History, RotateCcw } from 'lucide-react';
import { useEffect, useState } from 'react';
import { listPolicyVersions, rollbackPolicy, type PolicyVersion } from '../services/policyService';
import type { Policy } from '../types';
import { Modal } from './Modal';

const changeLabel: Record<PolicyVersion['change_type'], string> = {
  created: 'Created',
  updated: 'Edited',
  status_changed: 'Status changed',
  deleted: 'Deleted',
  rolled_back: 'Rolled back',
};

function describeConditions(version: PolicyVersion): string {
  const conditions = version.rule?.conditions ?? [];
  if (conditions.length === 0) return 'matches every request';
  return conditions
    .map((c) => `${c.field} ${c.operator} ${Array.isArray(c.value) ? c.value.join(', ') : String(c.value)}`)
    .join(' AND ');
}

interface PolicyHistoryModalProps {
  open: boolean;
  policy: Policy | null;
  onClose: () => void;
  onRolledBack: (policy: Policy) => void;
}

/** Immutable version history for a policy with one-click rollback. */
export function PolicyHistoryModal({ open, policy, onClose, onRolledBack }: PolicyHistoryModalProps) {
  const [versions, setVersions] = useState<PolicyVersion[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [confirming, setConfirming] = useState<number | null>(null);
  const [working, setWorking] = useState(false);

  useEffect(() => {
    if (!open || !policy) return;
    let cancelled = false;
    setLoading(true);
    setError(null);
    setConfirming(null);
    listPolicyVersions(policy.id)
      .then((loaded) => {
        if (!cancelled) setVersions(loaded);
      })
      .catch((err) => {
        if (!cancelled) setError(err instanceof Error ? err.message : 'Could not load history.');
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [open, policy]);

  const current = versions[0]?.version ?? null;

  const handleRollback = async (version: number) => {
    if (!policy) return;
    if (confirming !== version) {
      setConfirming(version);
      return;
    }
    setWorking(true);
    setError(null);
    try {
      const restored = await rollbackPolicy(policy.id, version);
      onRolledBack(restored);
      setVersions(await listPolicyVersions(policy.id));
      setConfirming(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not roll back the policy.');
    } finally {
      setWorking(false);
    }
  };

  return (
    <Modal
      open={open}
      onClose={onClose}
      wide
      title={policy ? `History — ${policy.name}` : 'Policy history'}
      subtitle="Every change is a new immutable version. Rolling back creates another version; nothing is overwritten."
    >
      {error ? <p className="mb-4 text-sm text-rose-400">{error}</p> : null}
      {loading ? (
        <p className="text-sm text-mist-500">Loading history…</p>
      ) : versions.length === 0 ? (
        <p className="text-sm text-mist-500">No versions recorded yet.</p>
      ) : (
        <ol className="space-y-3">
          {versions.map((v) => {
            const isCurrent = v.version === current;
            const canRestore = !isCurrent && v.change_type !== 'deleted';
            return (
              <li key={v.id} className="rounded-xl border border-line bg-ink-950/60 p-4">
                <div className="flex flex-wrap items-start justify-between gap-3">
                  <div className="min-w-0">
                    <p className="flex items-center gap-2 text-sm font-semibold text-mist-100">
                      <History size={14} className="text-accent-400" aria-hidden="true" />
                      v{v.version} · {changeLabel[v.change_type]}
                      {v.rolled_back_from ? ` (from v${v.rolled_back_from})` : ''}
                      {isCurrent ? (
                        <span className="rounded-full border border-mint-400/30 bg-mint-400/10 px-2 py-0.5 text-[10px] font-bold tracking-wider text-mint-400">
                          CURRENT
                        </span>
                      ) : null}
                    </p>
                    <p className="mt-0.5 text-xs text-mist-500">{new Date(v.created_at).toLocaleString()}</p>
                  </div>
                  {canRestore ? (
                    <button
                      type="button"
                      disabled={working}
                      onClick={() => void handleRollback(v.version)}
                      className={`inline-flex items-center gap-1.5 rounded-lg border px-3 py-1.5 text-xs font-medium transition disabled:opacity-50 ${
                        confirming === v.version
                          ? 'border-amber-400/50 bg-amber-400/10 text-amber-300'
                          : 'border-line text-mist-400 hover:border-line-strong hover:text-mist-100'
                      }`}
                    >
                      <RotateCcw size={12} aria-hidden="true" />
                      {confirming === v.version ? (working ? 'Restoring…' : 'Confirm restore') : 'Restore'}
                    </button>
                  ) : null}
                </div>
                <dl className="mt-3 grid gap-x-4 gap-y-1 text-xs sm:grid-cols-[auto_1fr]">
                  <dt className="text-mist-600">Action</dt>
                  <dd className="text-mist-300">
                    {v.action} · priority {v.priority} · {v.status}
                  </dd>
                  <dt className="text-mist-600">When</dt>
                  <dd className="break-words font-mono text-mist-300">{describeConditions(v)}</dd>
                </dl>
              </li>
            );
          })}
        </ol>
      )}
    </Modal>
  );
}
