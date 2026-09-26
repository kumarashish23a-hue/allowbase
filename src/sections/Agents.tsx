import { Bot, Check, Pause, Play, X } from 'lucide-react';
import { useState } from 'react';
import { Reveal } from '../components/Reveal';
import { SectionHeading } from '../components/SectionHeading';
import { agents as seedAgents } from '../data/mock';
import type { Agent } from '../types';

const riskTone: Record<Agent['risk'], string> = {
  Low: 'border-mint-400/30 bg-mint-400/10 text-mint-400',
  Medium: 'border-amber-400/30 bg-amber-400/10 text-amber-400',
  High: 'border-rose-400/30 bg-rose-400/10 text-rose-400',
};

export function Agents() {
  const [agents, setAgents] = useState<Agent[]>(seedAgents);

  const toggle = (id: string) => {
    setAgents((current) =>
      current.map((agent) =>
        agent.id === id ? { ...agent, status: agent.status === 'Active' ? 'Paused' : 'Active' } : agent,
      ),
    );
  };

  return (
    <section className="border-y border-line bg-ink-900/40">
      <div className="mx-auto max-w-7xl px-4 py-20 sm:px-6 lg:px-8 lg:py-28">
        <SectionHeading
          eyebrow="AI agents"
          title="AI agents need permissions too."
          description="AI is moving from answering questions to taking actions. Give every agent explicit data and action permissions."
        />

        <div className="mt-12 grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
          {agents.map((agent, index) => (
            <Reveal key={agent.id} delay={index * 0.06}>
              <div className="flex h-full flex-col rounded-2xl border border-line bg-ink-950/60 p-6 shadow-card">
                <div className="flex items-start justify-between gap-3">
                  <span className="flex h-10 w-10 items-center justify-center rounded-xl border border-line bg-ink-800 text-accent-300">
                    <Bot size={18} />
                  </span>
                  <span className={`rounded-full border px-2.5 py-1 text-[11px] font-bold tracking-[0.12em] ${riskTone[agent.risk]}`}>
                    {agent.risk.toUpperCase()} RISK
                  </span>
                </div>
                <h3 className="mt-4 text-base font-semibold text-mist-100">{agent.name}</h3>
                <p className="mt-1 text-xs text-mist-500">
                  {agent.owner} · {agent.model} · {agent.requests}
                </p>

                <div className="mt-5 space-y-3 text-sm">
                  <div>
                    <p className="text-xs uppercase tracking-[0.16em] text-mist-600">Allowed</p>
                    <ul className="mt-2 space-y-1.5">
                      {agent.allowed.map((item) => (
                        <li key={item} className="flex items-center gap-2 text-mist-300">
                          <Check size={14} className="text-mint-400" /> {item}
                        </li>
                      ))}
                    </ul>
                  </div>
                  <div>
                    <p className="text-xs uppercase tracking-[0.16em] text-mist-600">Denied</p>
                    <ul className="mt-2 space-y-1.5">
                      {agent.denied.map((item) => (
                        <li key={item} className="flex items-center gap-2 text-mist-500">
                          <X size={14} className="text-rose-400" /> {item}
                        </li>
                      ))}
                    </ul>
                  </div>
                </div>

                <div className="mt-auto flex items-center justify-between pt-6">
                  <span
                    className={`inline-flex items-center gap-1.5 text-xs font-medium ${
                      agent.status === 'Active' ? 'text-mint-400' : 'text-mist-500'
                    }`}
                  >
                    <span className={`h-2 w-2 rounded-full ${agent.status === 'Active' ? 'bg-mint-400' : 'bg-mist-600'}`} />
                    {agent.status}
                  </span>
                  <button
                    type="button"
                    onClick={() => toggle(agent.id)}
                    className="inline-flex items-center gap-1.5 rounded-lg border border-line px-3 py-1.5 text-xs font-medium text-mist-300 transition hover:border-line-strong hover:text-mist-100"
                  >
                    {agent.status === 'Active' ? <Pause size={13} /> : <Play size={13} />}
                    {agent.status === 'Active' ? 'Pause' : 'Resume'}
                  </button>
                </div>
              </div>
            </Reveal>
          ))}
        </div>
      </div>
    </section>
  );
}
