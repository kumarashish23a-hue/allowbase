import { ShieldCheck } from 'lucide-react';
import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { Agents } from '../sections/Agents';
import { AIRequest } from '../sections/AIRequest';
import { Approvals } from '../sections/Approvals';
import { ApiKeys } from '../sections/ApiKeys';
import { DataSources } from '../sections/DataSources';
import { Requests } from '../sections/Requests';
import { PolicyEngine } from '../sections/PolicyEngine';
import { getActiveOrganizationId } from '../lib/supabase';
import { getMyOrganizationRole } from '../services/organizationService';

interface ConsoleProps {
  onSimulate: () => void;
}

/** The live product: policies, agents, data, keys, and the request log. */
export function Console({ onSimulate }: ConsoleProps) {
  const [isAdmin, setIsAdmin] = useState(false);

  useEffect(() => {
    (async () => {
      const orgId = await getActiveOrganizationId().catch(() => null);
      if (!orgId) return;
      const role = await getMyOrganizationRole(orgId).catch(() => null);
      setIsAdmin(role === 'owner' || role === 'admin');
    })();
  }, []);

  return (
    <>
      <div className="mx-auto max-w-7xl px-4 pt-24 sm:px-6 lg:px-8 lg:pt-28">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div>
            <p className="text-xs font-semibold uppercase tracking-[0.2em] text-accent-600">Console</p>
            <h1 className="mt-3 max-w-2xl text-3xl font-bold tracking-tight text-mist-100 sm:text-4xl">
              Your live control plane.
            </h1>
            <p className="mt-3 max-w-2xl text-base leading-relaxed text-mist-400">
              Everything below reads from and writes to your Supabase project in real time — policies,
              approvals, agents, data sources, API keys, and every AI request on the record.
            </p>
          </div>
          {isAdmin ? (
            <Link
              to="/admin"
              className="mt-1 inline-flex items-center gap-2 rounded-xl border border-line px-4 py-2.5 text-sm font-medium text-mist-200 transition hover:border-line-strong hover:text-mist-100"
            >
              <ShieldCheck size={15} /> Admin panel
            </Link>
          ) : null}
        </div>
      </div>
      <AIRequest onSimulate={onSimulate} />
      <PolicyEngine />
      <Approvals />
      <Agents />
      <DataSources />
      <ApiKeys />
      <Requests />
    </>
  );
}
