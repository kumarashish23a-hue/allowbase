import { motion } from 'framer-motion';
import {
  Bot,
  CheckCircle2,
  Cloud,
  Code2,
  Cpu,
  Database,
  HardDrive,
  MessagesSquare,
  ScanSearch,
  ShieldCheck,
  Sparkles,
  Users,
  XCircle,
} from 'lucide-react';
import { useCallback, useEffect, useRef, useState } from 'react';
import { aiSystems, dataSources } from '../data/mock';

const sourceIcons = [Database, Code2, MessagesSquare, HardDrive, Users, Cloud];
const aiIcons = [Sparkles, Bot, Cpu, ShieldCheck, ScanSearch];

const stages = [
  'Request received',
  'Inspecting data',
  'Detecting sensitive information',
  'Checking policy',
  'Evaluating destination',
];

const examples = [
  {
    user: 'Alex Kim',
    source: 'Customer Database',
    ai: 'Claude',
    decision: 'BLOCKED' as const,
    reason: 'Customer PII cannot be sent to external AI.',
  },
  {
    user: 'Sarah Chen',
    source: 'Product Documentation',
    ai: 'Internal Support Agent',
    decision: 'ALLOWED' as const,
    reason: 'No sensitive data detected.',
  },
];

export function ArchitectureDiagram() {
  const getReducedMotion = () =>
    typeof window !== 'undefined' && window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  const [exampleIndex, setExampleIndex] = useState(0);
  const [stage, setStage] = useState(() => (getReducedMotion() ? stages.length - 1 : 0));
  // Reduced motion: show the completed inspection immediately, no auto-cycling.
  const [done, setDone] = useState(getReducedMotion);
  const [reducedMotion, setReducedMotion] = useState(getReducedMotion);
  const timer = useRef<number | null>(null);

  const example = examples[exampleIndex];

  const restart = useCallback(() => {
    setStage(0);
    setDone(false);
  }, []);

  useEffect(() => {
    const query = window.matchMedia('(prefers-reduced-motion: reduce)');
    const onChange = (event: MediaQueryListEvent) => setReducedMotion(event.matches);
    query.addEventListener('change', onChange);
    return () => query.removeEventListener('change', onChange);
  }, []);

  useEffect(() => {
    if (reducedMotion) return;
    if (done) {
      timer.current = window.setTimeout(() => {
        setExampleIndex((value) => (value + 1) % examples.length);
        restart();
      }, 2600);
      return () => {
        if (timer.current) window.clearTimeout(timer.current);
      };
    }

    timer.current = window.setTimeout(() => {
      if (stage < stages.length - 1) {
        setStage((value) => value + 1);
      } else {
        setDone(true);
      }
    }, 850);

    return () => {
      if (timer.current) window.clearTimeout(timer.current);
    };
  }, [stage, done, restart, reducedMotion]);

  return (
    <div className="relative overflow-hidden rounded-xl border border-line bg-ink-900/70 shadow-card">
      <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(700px_320px_at_50%_0%,rgba(34,211,238,0.18),transparent_70%)]" />
      <div className="relative grid gap-6 p-6 sm:p-8 lg:grid-cols-[1fr_1.25fr_1fr] lg:p-10">
        <div>
          <p className="text-xs font-semibold uppercase tracking-[0.2em] text-mist-500">Company Data</p>
          <div className="mt-4 space-y-2">
            {dataSources.map((source, index) => {
              const Icon = sourceIcons[index % sourceIcons.length];
              const active = !done && stage >= 1 && example.source === source;
              return (
                <div
                  key={source}
                  className={`flex items-center gap-3 rounded-xl border px-3 py-2.5 text-sm transition ${
                    active ? 'border-accent-400/60 bg-accent-500/10 text-mist-100' : 'border-line bg-ink-800/60 text-mist-300'
                  }`}
                >
                  <Icon size={16} className={active ? 'text-accent-300' : 'text-mist-500'} />
                  {source}
                </div>
              );
            })}
          </div>
        </div>

        <div className="rounded-lg border border-accent-400/30 bg-ink-950/70 p-5 sm:p-6">
          <div className="flex items-center justify-between">
            <p className="text-xs font-semibold uppercase tracking-[0.2em] text-accent-300">Data Control Plane</p>
            <button
              type="button"
              onClick={restart}
              className="rounded-lg border border-line px-3 py-1.5 text-xs font-medium text-mist-300 transition hover:border-line-strong hover:text-mist-100"
            >
              Replay inspection
            </button>
          </div>

          <div className="mt-5 space-y-3">
            {stages.map((label, index) => {
              const isActive = !done && index === stage;
              const isDone = done || index < stage;
              return (
                <div key={label} className="flex items-center gap-3">
                  <span
                    className={`flex h-7 w-7 items-center justify-center rounded-full border text-xs ${
                      isDone
                        ? 'border-mint-400/50 bg-mint-400/10 text-mint-400'
                        : isActive
                          ? 'border-accent-400/70 bg-accent-500/15 text-accent-200'
                          : 'border-line text-mist-600'
                    }`}
                  >
                    {isDone ? <CheckCircle2 size={14} /> : index + 1}
                  </span>
                  <div className="flex-1">
                    <p className={`text-sm ${isActive || isDone ? 'text-mist-100' : 'text-mist-600'}`}>{label}</p>
                    {isActive ? (
                      <motion.div
                        className="mt-2 h-1 overflow-hidden rounded-full bg-ink-700"
                        initial={{ opacity: 0.6 }}
                        animate={{ opacity: 1 }}
                      >
                        <motion.div
                          className="h-full w-1/3 rounded-full bg-accent-400"
                          animate={{ x: ['-100%', '300%'] }}
                          transition={{ duration: 0.85, repeat: Infinity, ease: 'easeInOut' }}
                        />
                      </motion.div>
                    ) : null}
                  </div>
                </div>
              );
            })}
          </div>

          <div className="mt-6 rounded-xl border border-line bg-ink-900/80 p-4">
            <p className="text-xs uppercase tracking-[0.18em] text-mist-500">Live request</p>
            <p className="mt-2 text-sm text-mist-200">
              {example.user} → {example.source} → {example.ai}
            </p>
            {done ? (
              <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} className="mt-3">
                <span
                  className={`inline-flex items-center gap-2 rounded-full px-3 py-1 text-xs font-bold tracking-[0.14em] ${
                    example.decision === 'BLOCKED'
                      ? 'bg-rose-400/10 text-rose-400 border border-rose-400/30'
                      : 'bg-mint-400/10 text-mint-400 border border-mint-400/30'
                  }`}
                >
                  {example.decision === 'BLOCKED' ? <XCircle size={14} /> : <CheckCircle2 size={14} />}
                  {example.decision}
                </span>
                <p className="mt-2 text-sm text-mist-400">{example.reason}</p>
              </motion.div>
            ) : (
              <p className="mt-3 text-sm text-mist-600">Evaluating against policy…</p>
            )}
          </div>
        </div>

        <div>
          <p className="text-xs font-semibold uppercase tracking-[0.2em] text-mist-500">AI Models / Agents</p>
          <div className="mt-4 space-y-2">
            {aiSystems.map((system, index) => {
              const Icon = aiIcons[index % aiIcons.length];
              const active = !done && stage >= 2 && example.ai === system;
              return (
                <div
                  key={system}
                  className={`flex items-center gap-3 rounded-xl border px-3 py-2.5 text-sm transition ${
                    active ? 'border-accent-400/60 bg-accent-500/10 text-mist-100' : 'border-line bg-ink-800/60 text-mist-300'
                  }`}
                >
                  <Icon size={16} className={active ? 'text-accent-300' : 'text-mist-500'} />
                  {system}
                </div>
              );
            })}
          </div>
          <p className="mt-4 text-xs leading-relaxed text-mist-600">
            Demo visualization. Names are illustrative and do not imply partnerships.
          </p>
        </div>
      </div>
    </div>
  );
}
