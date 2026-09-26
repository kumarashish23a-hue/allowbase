import { CheckCircle2, Loader2, ShieldAlert, ShieldCheck } from 'lucide-react';
import { useEffect, useRef, useState } from 'react';
import { simulationSteps } from '../data/mock';
import { isSupabaseConfigured } from '../lib/supabase';
import { evaluateRequest } from '../services/aiRequestService';
import type { MockEvaluation } from '../utils/decision';
import { Modal } from './Modal';

interface RequestSimulatorProps {
  open: boolean;
  onClose: () => void;
}

const presets = [
  { label: 'Risky request', user: 'Alex Kim', ai: 'Claude', data: 'Customer Database', purpose: 'Customer Analysis' },
  { label: 'Safe request', user: 'Sarah Chen', ai: 'Internal Support Agent', data: 'Product Documentation', purpose: 'Customer Support' },
];

export function RequestSimulator({ open, onClose }: RequestSimulatorProps) {
  const [user, setUser] = useState('Alex Kim');
  const [ai, setAi] = useState('Claude');
  const [data, setData] = useState('Customer Database');
  const [purpose, setPurpose] = useState('Customer Analysis');
  const [running, setRunning] = useState(false);
  const [stepIndex, setStepIndex] = useState(0);
  const [result, setResult] = useState<MockEvaluation | null>(null);
  const timers = useRef<number[]>([]);

  const clearTimers = () => {
    timers.current.forEach((timer) => window.clearTimeout(timer));
    timers.current = [];
  };

  useEffect(() => {
    if (open) {
      setRunning(false);
      setStepIndex(0);
      setResult(null);
      clearTimers();
    }
    return clearTimers;
  }, [open ]);

  const evaluate = () => {
    clearTimers();
    setResult(null);
    setRunning(true);
    setStepIndex(0);

    simulationSteps.forEach((_, index) => {
      timers.current.push(
        window.setTimeout(() => {
          setStepIndex(index + 1);
          if (index === simulationSteps.length - 1) {
            timers.current.push(
              window.setTimeout(() => {
                void evaluateRequest({ user, ai, data, purpose })
                  .then((evaluation) => {
                    setResult(evaluation);
                  })
                  .catch(() => {
                    setResult(null);
                  })
                  .finally(() => {
                    setRunning(false);
                  });
              }, 650),
            );
          }
        }, index * 700),
      );
    });
  };

  const decisionTone =
    result?.decision === 'BLOCK'
      ? 'border-rose-400/30 bg-rose-400/10 text-rose-400'
      : result?.decision === 'REDACT'
        ? 'border-amber-400/30 bg-amber-400/10 text-amber-400'
        : 'border-mint-400/30 bg-mint-400/10 text-mint-400';

  return (
    <Modal
      open={open}
      onClose={onClose}
      title="Simulate AI Request"
      subtitle={
        isSupabaseConfigured()
          ? 'Evaluated by your Supabase backend when signed in, otherwise simulated locally.'
          : 'Frontend-only demo. No data leaves your browser.'
      }
      wide
    >
      <div className="grid gap-6 lg:grid-cols-[1fr_1fr]">
        <div>
          <div className="flex flex-wrap gap-2">
            {presets.map((preset) => (
              <button
                key={preset.label}
                type="button"
                onClick={() => {
                  setUser(preset.user);
                  setAi(preset.ai);
                  setData(preset.data);
                  setPurpose(preset.purpose);
                  setResult(null);
                }}
                className="rounded-full border border-line px-3 py-1.5 text-xs font-medium text-mist-300 transition hover:border-line-strong hover:text-mist-100"
              >
                {preset.label}
              </button>
            ))}
          </div>

          <div className="mt-5 space-y-4">
            {[
              { id: 'sim-user', label: 'User', value: user, setter: setUser },
              { id: 'sim-ai', label: 'AI System', value: ai, setter: setAi },
              { id: 'sim-data', label: 'Data', value: data, setter: setData },
              { id: 'sim-purpose', label: 'Purpose', value: purpose, setter: setPurpose },
            ].map((field) => (
              <div key={field.id}>
                <label htmlFor={field.id} className="text-xs font-semibold uppercase tracking-[0.16em] text-mist-500">
                  {field.label}
                </label>
                <input
                  id={field.id}
                  value={field.value}
                  onChange={(event) => field.setter(event.target.value)}
                  className="mt-2 w-full rounded-xl border border-line bg-ink-950/70 px-3 py-2.5 text-sm text-mist-100 placeholder:text-mist-600 focus:border-accent-400/60 focus:outline-none"
                  placeholder={`Enter ${field.label.toLowerCase()}`}
                />
              </div>
            ))}
          </div>

          <button
            type="button"
            onClick={evaluate}
            disabled={running}
            className="mt-6 w-full rounded-xl bg-accent-500 px-4 py-3 text-sm font-semibold text-white transition hover:bg-accent-400 disabled:cursor-not-allowed disabled:opacity-60"
          >
            {running ? 'Evaluating…' : 'Evaluate request'}
          </button>
        </div>

        <div className="rounded-2xl border border-line bg-ink-950/60 p-5">
          <p className="text-xs font-semibold uppercase tracking-[0.18em] text-mist-500">Evaluation</p>
          <div className="mt-4 space-y-3">
            {simulationSteps.map((step, index) => {
              const completed = stepIndex > index;
              const active = running && stepIndex === index;
              return (
                <div key={step.id} className="flex items-start gap-3">
                  <span
                    className={`mt-0.5 flex h-6 w-6 items-center justify-center rounded-full border ${
                      completed
                        ? 'border-mint-400/50 bg-mint-400/10 text-mint-400'
                        : active
                          ? 'border-accent-400/60 bg-accent-500/15 text-accent-200'
                          : 'border-line text-mist-600'
                    }`}
                  >
                    {completed ? <CheckCircle2 size={14} /> : active ? <Loader2 size={14} className="animate-spin" /> : index + 1}
                  </span>
                  <div>
                    <p className={`text-sm ${completed || active ? 'text-mist-100' : 'text-mist-600'}`}>{step.label}</p>
                    <p className="text-xs text-mist-600">{step.detail}</p>
                  </div>
                </div>
              );
            })}
          </div>

          {result ? (
            <div className="mt-6 rounded-xl border border-line bg-ink-900/70 p-4">
              <span className={`inline-flex items-center gap-2 rounded-full border px-3 py-1 text-xs font-bold tracking-[0.14em] ${decisionTone}`}>
                {result.decision === 'BLOCK' ? <ShieldAlert size={14} /> : <ShieldCheck size={14} />}
                {result.decision === 'BLOCK' ? 'BLOCKED' : result.decision === 'REDACT' ? 'REDACTED' : 'ALLOWED'}
              </span>
              <p className="mt-3 text-sm text-mist-200">{result.reason}</p>
              <div className="mt-3">
                <p className="text-xs uppercase tracking-[0.16em] text-mist-500">Detected</p>
                <div className="mt-2 flex flex-wrap gap-2">
                  {result.detected.map((item) => (
                    <span key={item} className="rounded-full border border-line bg-ink-950/70 px-2.5 py-1 text-xs text-mist-300">
                      {item}
                    </span>
                  ))}
                </div>
              </div>
              <p className="mt-3 text-xs text-mist-500">Policy: {result.policy}</p>
            </div>
          ) : (
            <p className="mt-6 text-sm text-mist-600">Run an evaluation to see the simulated allow/block decision.</p>
          )}
        </div>
      </div>
    </Modal>
  );
}
