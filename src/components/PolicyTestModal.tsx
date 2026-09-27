import { FlaskConical } from 'lucide-react';
import { useEffect, useState } from 'react';
import {
  evaluateRequest,
  isProviderConditionSupported,
  listModels,
  registerModel,
  type WorkspaceModel,
} from '../services/aiRequestService';
import { listDataAssets, type DataAsset } from '../services/dataAssetService';
import type { MockEvaluation } from '../utils/decision';
import type { Policy } from '../types';
import { Modal } from './Modal';

const inputCls =
  'mt-2 w-full rounded-xl border border-line bg-ink-950/70 px-3 py-2.5 text-sm text-mist-100 focus:border-accent-400/60 focus:outline-none';
const labelCls = 'text-xs font-semibold uppercase tracking-[0.16em] text-mist-500';

const decisionTone: Record<string, string> = {
  ALLOW: 'border-emerald-400/30 bg-emerald-400/10 text-emerald-400',
  BLOCK: 'border-rose-400/30 bg-rose-400/10 text-rose-400',
  MASK: 'border-amber-400/30 bg-amber-400/10 text-amber-400',
  REDACT: 'border-amber-400/30 bg-amber-400/10 text-amber-400',
};

interface PolicyTestModalProps {
  open: boolean;
  policy: Policy | null;
  onClose: () => void;
}

/**
 * One-click policy test: pick an AI model, a data asset, and a purpose, then
 * run the real enforcement engine and see the decision immediately — no SQL
 * Editor, no tab-hopping to the simulator.
 */
export function PolicyTestModal({ open, policy, onClose }: PolicyTestModalProps) {
  const [models, setModels] = useState<WorkspaceModel[]>([]);
  const [assets, setAssets] = useState<DataAsset[]>([]);
  const [modelName, setModelName] = useState('');
  const [assetName, setAssetName] = useState('');
  const [purpose, setPurpose] = useState('personal use');
  const [providerSupported, setProviderSupported] = useState<boolean | null>(null);
  const [loading, setLoading] = useState(false);
  const [running, setRunning] = useState(false);
  const [adding, setAdding] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<MockEvaluation | null>(null);

  useEffect(() => {
    if (!open) return;
    setError(null);
    setResult(null);
    setProviderSupported(null);
    let cancelled = false;
    setLoading(true);
    Promise.all([listModels(), listDataAssets(), isProviderConditionSupported()])
      .then(([m, a, supported]) => {
        if (cancelled) return;
        setModels(m);
        setAssets(a);
        setProviderSupported(supported);
        if (m.length > 0 && !modelName) setModelName(m[0].name);
        if (a.length > 0 && !assetName) setAssetName(a[0].name);
      })
      .catch((e) => {
        if (!cancelled) setError(e instanceof Error ? e.message : 'Could not load test data.');
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open ]);

  const hasOpenAiModel = models.some((m) => (m.provider ?? '').toLowerCase() === 'openai');

  const handleAddChatGpt = async () => {
    setError(null);
    setAdding(true);
    try {
      await registerModel('ChatGPT', 'openai');
      const m = await listModels();
      setModels(m);
      setModelName('ChatGPT');
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Could not add ChatGPT.');
    } finally {
      setAdding(false);
    }
  };

  const handleRun = async () => {
    setError(null);
    setResult(null);
    if (!modelName || !assetName || !purpose.trim()) {
      setError('Pick a model, a data asset, and a purpose first.');
      return;
    }
    setRunning(true);
    try {
      const evaluation = await evaluateRequest({
        user: 'policy test',
        ai: modelName,
        data: assetName,
        purpose: purpose.trim(),
      });
      setResult(evaluation);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'The test could not run.');
    } finally {
      setRunning(false);
    }
  };

  return (
    <Modal
      open={open}
      onClose={onClose}
      title={policy ? `Test: ${policy.name}` : 'Test policy'}
      subtitle="Runs the real enforcement engine on a sample request."
    >
      <div className="space-y-4">
        {providerSupported === false ? (
          <p className="rounded-xl border border-amber-400/30 bg-amber-400/10 px-4 py-3 text-sm text-amber-300">
            Your database does not understand the “AI provider” condition yet. Run{' '}
            <span className="font-mono">supabase/migrations/019_provider_condition.sql</span> in the
            Supabase SQL Editor, then test again.
          </p>
        ) : null}

        {!hasOpenAiModel && !loading ? (
          <div className="flex items-center justify-between gap-3 rounded-xl border border-line bg-ink-950/50 px-4 py-3">
            <p className="text-sm text-mist-400">No ChatGPT model in this workspace yet.</p>
            <button
              type="button"
              disabled={adding}
              onClick={() => void handleAddChatGpt()}
              className="shrink-0 rounded-lg border border-line px-3 py-1.5 text-xs font-semibold text-mist-100 transition hover:border-line-strong disabled:opacity-40"
            >
              {adding ? 'Adding…' : 'Add ChatGPT'}
            </button>
          </div>
        ) : null}

        {loading ? (
          <p className="text-sm text-mist-500">Loading workspace data…</p>
        ) : (
          <>
            <div>
              <label htmlFor="test-model" className={labelCls}>
                AI model
              </label>
              <select
                id="test-model"
                value={modelName}
                onChange={(event) => setModelName(event.target.value)}
                className={inputCls}
              >
                {models.map((m) => (
                  <option key={m.id} value={m.name}>
                    {m.name}
                    {m.provider ? ` (${m.provider})` : ''}
                  </option>
                ))}
              </select>
            </div>
            <div>
              <label htmlFor="test-data" className={labelCls}>
                Data
              </label>
              <select
                id="test-data"
                value={assetName}
                onChange={(event) => setAssetName(event.target.value)}
                className={inputCls}
              >
                {assets.map((a) => (
                  <option key={a.id} value={a.name}>
                    {a.label || a.name}
                  </option>
                ))}
              </select>
            </div>
            <div>
              <label htmlFor="test-purpose" className={labelCls}>
                Purpose
              </label>
              <input
                id="test-purpose"
                value={purpose}
                onChange={(event) => setPurpose(event.target.value)}
                placeholder="e.g. personal use"
                className={inputCls}
              />
            </div>
          </>
        )}

        {error ? <p className="text-sm text-rose-400">{error}</p> : null}

        {result ? (
          <div className="rounded-xl border border-line bg-ink-950/50 p-4">
            <div className="flex items-center justify-between gap-3">
              <span
                className={`rounded-full border px-3 py-1 text-xs font-bold tracking-[0.12em] ${decisionTone[result.decision] ?? decisionTone.REDACT}`}
              >
                {result.decision}
              </span>
              <span className="text-xs text-mist-500">via {result.policy}</span>
            </div>
            <p className="mt-3 text-sm text-mist-300">{result.reason}</p>
          </div>
        ) : null}

        <div className="flex items-center justify-end gap-2 pt-1">
          <button
            type="button"
            onClick={onClose}
            className="rounded-xl border border-line px-4 py-2.5 text-sm text-mist-300 transition hover:border-line-strong hover:text-mist-100"
          >
            Close
          </button>
          <button
            type="button"
            disabled={running || loading}
            onClick={() => void handleRun()}
            className="inline-flex items-center gap-2 rounded-xl bg-accent-500 px-5 py-2.5 text-sm font-semibold text-white transition hover:bg-accent-400 disabled:opacity-40"
          >
            <FlaskConical size={15} />
            {running ? 'Running…' : 'Run test'}
          </button>
        </div>
      </div>
    </Modal>
  );
}
