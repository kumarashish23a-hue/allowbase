import { Bot, Check, ChevronDown, Pause, Play, X } from 'lucide-react';
import { useEffect, useState } from 'react';
import { Reveal } from '../components/Reveal';
import { SectionHeading } from '../components/SectionHeading';
import { agents as seedAgents } from '../data/mock';
import { getActiveOrganizationId, getSupabase, isSupabaseConfigured } from '../lib/supabase';
import {
  getAgentAssetGrants,
  grantAgentRead,
  listAgents,
  revokeAgentRead,
  setAgentStatus,
} from '../services/aiAgentService';
import { listDataAssets, type DataAsset } from '../services/dataAssetService';
import type { Agent } from '../types';

const riskTone: Record<Agent['risk'], string> = {
  Low: 'border-mint-400/30 bg-mint-400/10 text-mint-400',
  Medium: 'border-amber-400/30 bg-amber-400/10 text-amber-400',
  High: 'border-rose-400/30 bg-rose-400/10 text-rose-400',
};

export function Agents() {
  const [agents, setAgents] = useState<Agent[]>(seedAgents);
  const [live, setLive] = useState(false);
  const [assets, setAssets] = useState<DataAsset[]>([]);
  const [grantMap, setGrantMap] = useState<Record<string, Set<string>>>({});
  const [expanded, setExpanded] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const loaded = await listAgents();
        if (cancelled) return;
        setAgents(loaded);
        const supabase = getSupabase();
        const orgId = await getActiveOrganizationId();
        if (isSupabaseConfigured() && supabase && orgId) {
          const {
            data: { session },
          } = await supabase.auth.getSession();
          if (session && !cancelled) {
            setLive(true);
            const [workspaceAssets, grants] = await Promise.all([listDataAssets(), getAgentAssetGrants()]);
            if (!cancelled) {
              setAssets(workspaceAssets);
              setGrantMap(
                Object.fromEntries(Object.entries(grants).map(([agentId, assetIds]) => [agentId, new Set(assetIds)])),
              );
            }
          }
        }
      } catch {
        /* keep seed agents when offline */
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  const toggleGrant = (agentId: string, assetId: string, assetName: string) => {
    const granted = grantMap[agentId]?.has(assetId) ?? false;
    const apply = (map: Record<string, Set<string>>, has: boolean) => {
      const next = new Set(map[agentId] ?? []);
      if (has) next.add(assetId);
      else next.delete(assetId);
      return { ...map, [agentId]: next };
    };
    setGrantMap((current) => apply(current, !granted));
    setAgents((current) =>
      current.map((item) =>
        item.id === agentId
          ? {
              ...item,
              allowed: granted ? item.allowed.filter((name) => name !== assetName) : [...item.allowed, assetName],
            }
          : item,
      ),
    );
    (granted ? revokeAgentRead(agentId, assetId) : grantAgentRead(agentId, assetId)).catch(() => {
      // Revert the optimistic update if the backend rejects it.
      setGrantMap((current) => apply(current, granted));
      setAgents((current) =>
        current.map((item) =>
          item.id === agentId
            ? {
                ...item,
                allowed: granted ? [...item.allowed, assetName] : item.allowed.filter((name) => name !== assetName),
              }
            : item,
        ),
      );
    });
  };

  const toggle = (id: string) => {
    const agent = agents.find((item) => item.id === id);
    if (!agent) return;
    const nextStatus = agent.status === 'Active' ? 'Paused' : 'Active';
    setAgents((current) =>
      current.map((item) => (item.id === id ? { ...item, status: nextStatus } : item)),
    );
    if (isSupabaseConfigured()) {
      setAgentStatus(id, nextStatus === 'Active' ? 'active' : 'paused').catch(() => {
        // Revert the optimistic update if the backend rejects it.
        setAgents((current) =>
          current.map((item) => (item.id === id ? { ...item, status: agent.status } : item)),
        );
      });
    }
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
              <div className="flex h-full flex-col rounded-xl border border-line bg-ink-950/60 p-6 shadow-card">
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
                      {live && agent.allowed.length === 0 ? (
                        <li className="text-xs text-mist-600">No data access granted — requests are denied by default.</li>
                      ) : null}
                    </ul>
                  </div>
                  <div>
                    <p className="text-xs uppercase tracking-[0.16em] text-mist-600">Denied</p>
                    <ul className="mt-2 space-y-1.5">
                      {(live
                        ? assets.filter((asset) => !(grantMap[agent.id]?.has(asset.id) ?? false)).map((asset) => asset.name)
                        : agent.denied
                      ).map((item) => (
                        <li key={item} className="flex items-center gap-2 text-mist-500">
                          <X size={14} className="text-rose-400" /> {item}
                        </li>
                      ))}
                    </ul>
                  </div>
                </div>

                {live ? (
                  <div className="mt-4 border-t border-line pt-4">
                    <button
                      type="button"
                      onClick={() => setExpanded((current) => (current === agent.id ? null : agent.id))}
                      className="inline-flex items-center gap-1.5 text-xs font-semibold text-accent-300 transition hover:text-accent-200"
                      aria-expanded={expanded === agent.id}
                    >
                      <ChevronDown size={14} className={`transition ${expanded === agent.id ? 'rotate-180' : ''}`} />
                      Manage data access
                    </button>
                    {expanded === agent.id ? (
                      <ul className="mt-3 space-y-2">
                        {assets.map((asset) => {
                          const granted = grantMap[agent.id]?.has(asset.id) ?? false;
                          return (
                            <li key={asset.id}>
                              <label className="flex cursor-pointer items-center gap-2.5 rounded-lg border border-line bg-ink-900/60 px-3 py-2 text-xs text-mist-200 transition hover:border-line-strong">
                                <input
                                  type="checkbox"
                                  checked={granted}
                                  onChange={() => toggleGrant(agent.id, asset.id, asset.name)}
                                  className="h-3.5 w-3.5 accent-emerald-400"
                                />
                                <span className="flex-1">{asset.name}</span>
                                <span className="text-mist-600">{asset.classification}</span>
                              </label>
                            </li>
                          );
                        })}
                        {assets.length === 0 ? (
                          <li className="text-xs text-mist-600">No data assets in this workspace yet.</li>
                        ) : null}
                      </ul>
                    ) : null}
                  </div>
                ) : null}

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
