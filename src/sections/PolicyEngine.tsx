import { Plus } from 'lucide-react';
import { useEffect, useState } from 'react';
import { CreatePolicyModal } from '../components/PolicyModals';
import { Reveal } from '../components/Reveal';
import { SectionHeading } from '../components/SectionHeading';
import { isSupabaseConfigured } from '../lib/supabase';
import { createPolicy, listPolicies } from '../services/policyService';
import type { Policy } from '../types';

const effectTone: Record<Policy['effect'], string> = {
  ALLOW: 'border-mint-400/30 bg-mint-400/10 text-mint-400',
  BLOCK: 'border-rose-400/30 bg-rose-400/10 text-rose-400',
  MASK: 'border-sky-400/30 bg-sky-400/10 text-sky-400',
  REDACT: 'border-amber-400/30 bg-amber-400/10 text-amber-400',
};

export function PolicyEngine() {
  const [policies, setPolicies] = useState<Policy[]>([]);
  const [open, setOpen] = useState(false);

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

  const handleCreate = async (policy: Policy) => {
    if (isSupabaseConfigured()) {
      try {
        const created = await createPolicy({
          name: policy.name,
          description: policy.description,
          effect: policy.effect,
          conditions: policy.conditions,
        });
        setPolicies((current) => [created, ...current]);
        return;
      } catch {
        /* fall through to local state */
      }
    }
    setPolicies((current) => [policy, ...current]);
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
                <span
                  className={`rounded-full border px-2.5 py-1 text-[11px] font-bold tracking-[0.12em] ${effectTone[policy.effect]}`}
                >
                  {policy.effect}
                </span>
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
              <p className="mt-auto pt-5 text-xs text-mist-600">Updated {policy.updated}</p>
            </div>
          </Reveal>
        ))}
      </div>

      <Reveal className="mt-10 text-center">
        <button
          type="button"
          onClick={() => setOpen(true)}
          className="inline-flex items-center gap-2 rounded-xl border border-line bg-ink-900/60 px-6 py-3.5 text-sm font-semibold text-mist-100 transition hover:border-line-strong hover:bg-ink-800"
        >
          <Plus size={16} /> Create Policy
        </button>
      </Reveal>

      <CreatePolicyModal
        open={open}
        onClose={() => setOpen(false)}
        onCreate={(policy) => {
          void handleCreate(policy);
        }}
      />
    </section>
  );
}
