import { useCallback, useEffect, useState } from 'react';
import { Modal } from '../components/Modal';
import { Reveal } from '../components/Reveal';
import { SectionHeading } from '../components/SectionHeading';
import { connectedSources } from '../data/mock';
import type { DataAssetRow } from '../lib/db';
import { getSupabase, isSupabaseConfigured } from '../lib/supabase';
import {
  classifyAssets,
  connectPostgres,
  discoverPostgres,
  listDataSources,
  listDiscoveredAssets,
  listOpenFindings,
  type ClassificationFinding,
  type ClassifySummary,
  type DiscoverySummary,
} from '../services/dataSourceService';
import type { DataSource } from '../types';

const riskTone: Record<DataSource['risk'], string> = {
  Low: 'text-mint-400 border-mint-400/30 bg-mint-400/10',
  Medium: 'text-amber-400 border-amber-400/30 bg-amber-400/10',
  High: 'text-rose-400 border-rose-400/30 bg-rose-400/10',
};

const classificationTone: Record<string, string> = {
  public: 'text-accent-300 border-accent-400/30 bg-accent-400/10',
  internal: 'text-mist-300 border-line bg-ink-950/70',
  confidential: 'text-amber-300 border-amber-400/30 bg-amber-400/10',
  restricted: 'text-rose-300 border-rose-400/30 bg-rose-400/10',
};

const severityTone: Record<string, string> = {
  critical: 'text-rose-300 border-rose-400/30 bg-rose-400/10',
  high: 'text-amber-300 border-amber-400/30 bg-amber-400/10',
  medium: 'text-mist-300 border-line bg-ink-950/70',
  low: 'text-accent-300 border-accent-400/30 bg-accent-400/10',
};

const CLASSIFICATION_OPTIONS = ['public', 'internal', 'confidential', 'restricted'];

const inputClass =
  'mt-2 w-full rounded-xl border border-line bg-ink-950/70 px-3 py-2.5 text-sm text-mist-100 placeholder:text-mist-600 focus:border-accent-400/60 focus:outline-none';
const labelClass = 'text-xs font-semibold uppercase tracking-[0.16em] text-mist-500';
const primaryButtonClass =
  'w-full rounded-xl bg-accent-500 px-4 py-3 text-sm font-semibold text-[#06202a] transition hover:bg-accent-400 disabled:cursor-not-allowed disabled:opacity-60';

interface DiscoveredColumn {
  name: string;
  type: string;
  nullable: boolean;
  position: number;
  classification?: string;
  sensitivity?: string;
  confidence?: number | null;
  rule?: string | null;
  needs_review?: boolean;
  classified_by?: string;
}

function assetColumns(asset: DataAssetRow): DiscoveredColumn[] {
  const metadata = asset.metadata as { columns?: unknown };
  return Array.isArray(metadata.columns) ? (metadata.columns as DiscoveredColumn[]) : [];
}

function assetRowEstimate(asset: DataAssetRow): number | null {
  const metadata = asset.metadata as { row_estimate?: unknown };
  return typeof metadata.row_estimate === 'number' ? metadata.row_estimate : null;
}

export function DataSources() {
  const [sources, setSources] = useState<DataSource[]>(connectedSources);
  const [signedIn, setSignedIn] = useState<boolean | null>(null);
  const [selected, setSelected] = useState<DataSource | null>(null);

  // Connect form state
  const [connectOpen, setConnectOpen] = useState(false);
  const [connName, setConnName] = useState('');
  const [connHost, setConnHost] = useState('');
  const [connPort, setConnPort] = useState('5432');
  const [connDatabase, setConnDatabase] = useState('');
  const [connUsername, setConnUsername] = useState('');
  const [connPassword, setConnPassword] = useState('');
  const [connecting, setConnecting] = useState(false);
  const [connectError, setConnectError] = useState<string | null>(null);
  const [connectSuccess, setConnectSuccess] = useState<string | null>(null);

  // Discovery state
  const [discoverSource, setDiscoverSource] = useState<DataSource | null>(null);
  const [discoverPassword, setDiscoverPassword] = useState('');
  const [discovering, setDiscovering] = useState(false);
  const [discoverError, setDiscoverError] = useState<string | null>(null);
  const [discoverResult, setDiscoverResult] = useState<DiscoverySummary | null>(null);

  // Catalog state
  const [catalogSource, setCatalogSource] = useState<DataSource | null>(null);
  const [catalogAssets, setCatalogAssets] = useState<DataAssetRow[]>([]);
  const [catalogLoading, setCatalogLoading] = useState(false);
  const [catalogError, setCatalogError] = useState<string | null>(null);
  const [expandedTable, setExpandedTable] = useState<string | null>(null);

  // Classification + findings state
  const [classifying, setClassifying] = useState(false);
  const [classifyError, setClassifyError] = useState<string | null>(null);
  const [classifyResult, setClassifyResult] = useState<ClassifySummary | null>(null);
  const [findings, setFindings] = useState<ClassificationFinding[]>([]);
  const [findingsLoading, setFindingsLoading] = useState(false);
  const [overridePending, setOverridePending] = useState<string | null>(null);

  const refreshCatalog = useCallback(async (source: DataSource) => {
    setCatalogLoading(true);
    setFindingsLoading(true);
    try {
      setCatalogAssets(await listDiscoveredAssets(source.id));
    } catch (err) {
      setCatalogError(err instanceof Error ? err.message : 'Could not load the catalog.');
    } finally {
      setCatalogLoading(false);
    }
    try {
      setFindings(await listOpenFindings(source.id));
    } catch {
      /* findings are secondary; the catalog still shows */
    } finally {
      setFindingsLoading(false);
    }
  }, []);

  const refresh = useCallback(async () => {
    try {
      const loaded = await listDataSources();
      if (loaded.length > 0) setSources(loaded);
    } catch {
      /* keep current sources when offline */
    }
  }, []);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      if (!isSupabaseConfigured()) {
        if (!cancelled) setSignedIn(false);
        return;
      }
      const supabase = getSupabase();
      const {
        data: { session },
      } = await supabase!.auth.getSession();
      if (!cancelled) setSignedIn(!!session);
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    let cancelled = false;
    refresh().then(() => {
      if (cancelled) return;
    });
    return () => {
      cancelled = true;
    };
  }, [refresh]);

  const openConnect = () => {
    setConnectError(null);
    setConnectSuccess(null);
    setConnectOpen(true);
  };

  const submitConnect = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!signedIn) {
      setConnectError('Sign in first, then connect a database.');
      return;
    }
    setConnecting(true);
    setConnectError(null);
    setConnectSuccess(null);
    try {
      const summary = await connectPostgres({
        name: connName.trim(),
        host: connHost.trim(),
        port: Number(connPort) || 5432,
        database: connDatabase.trim(),
        username: connUsername.trim(),
        password: connPassword,
      });
      setConnPassword('');
      setConnectSuccess(
        `Connected to ${summary.host}:${summary.port}/${summary.database}. Open the source and run discovery to import its tables.`,
      );
      await refresh();
    } catch (err) {
      setConnectError(err instanceof Error ? err.message : 'Connection failed.');
    } finally {
      setConnecting(false);
    }
  };

  const openDiscover = (source: DataSource) => {
    setDiscoverSource(source);
    setDiscoverPassword('');
    setDiscoverError(null);
    setDiscoverResult(null);
  };

  const submitDiscover = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!discoverSource) return;
    setDiscovering(true);
    setDiscoverError(null);
    setDiscoverResult(null);
    try {
      const result = await discoverPostgres(discoverSource.id, discoverPassword);
      setDiscoverPassword('');
      setDiscoverResult(result);
      await refresh();
    } catch (err) {
      setDiscoverError(err instanceof Error ? err.message : 'Discovery failed.');
    } finally {
      setDiscovering(false);
    }
  };

  const openCatalog = async (source: DataSource) => {
    setCatalogSource(source);
    setCatalogAssets([]);
    setCatalogError(null);
    setExpandedTable(null);
    setClassifyResult(null);
    setClassifyError(null);
    setFindings([]);
    await refreshCatalog(source);
  };

  const runClassify = async (assetId?: string) => {
    if (!catalogSource) return;
    setClassifying(true);
    setClassifyError(null);
    setClassifyResult(null);
    try {
      const summary = await classifyAssets(
        assetId ? { assetId } : { sourceId: catalogSource.id },
      );
      setClassifyResult(summary);
      await refreshCatalog(catalogSource);
    } catch (err) {
      setClassifyError(err instanceof Error ? err.message : 'Classification failed.');
    } finally {
      setClassifying(false);
    }
  };

  const overrideColumn = async (asset: DataAssetRow, columnName: string, classification: string) => {
    const key = `${asset.id}:${columnName}`;
    setOverridePending(key);
    setClassifyError(null);
    try {
      await classifyAssets({ assetId: asset.id, overrides: [{ column_name: columnName, classification }] });
      if (catalogSource) await refreshCatalog(catalogSource);
    } catch (err) {
      setClassifyError(err instanceof Error ? err.message : 'Could not save the label.');
    } finally {
      setOverridePending(null);
    }
  };

  return (
    <section className="mx-auto max-w-7xl px-4 py-20 sm:px-6 lg:px-8 lg:py-28">
      <SectionHeading
        eyebrow="Data sources"
        title="Know where your data lives."
        description="Connect a real PostgreSQL database to discover its tables into your catalog. Everything else below is a mock integration for the landing-page tour."
      />

      <div className="mt-12 flex flex-wrap items-center justify-between gap-3">
        <p className="text-sm text-mist-500">
          {signedIn
            ? 'Live connections discover real table metadata. Passwords are never stored.'
            : 'Sign in to connect a real PostgreSQL database.'}
        </p>
        <button
          type="button"
          onClick={openConnect}
          className="rounded-xl bg-accent-500 px-4 py-2.5 text-sm font-semibold text-[#06202a] transition hover:bg-accent-400"
        >
          Connect PostgreSQL
        </button>
      </div>

      <div className="mt-6 grid gap-4 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4">
        {sources.map((source, index) => (
          <Reveal key={source.id} delay={index * 0.05}>
            <div className="flex h-full flex-col rounded-xl border border-line bg-ink-900/60 p-6 shadow-card transition hover:border-line-strong">
              <div className="flex items-center justify-between gap-3">
                <h3 className="text-base font-semibold text-mist-100">{source.name}</h3>
                {source.isLive ? (
                  <span className="rounded-full border border-mint-400/30 bg-mint-400/10 px-2.5 py-1 text-[10px] font-bold uppercase tracking-[0.14em] text-mint-400">
                    Live
                  </span>
                ) : (
                  <span className="rounded-full border border-line bg-ink-950/70 px-2.5 py-1 text-[10px] font-bold uppercase tracking-[0.14em] text-mist-500">
                    Mock
                  </span>
                )}
              </div>
              <p className="mt-1 text-xs text-mist-500">{source.category}</p>
              <dl className="mt-5 space-y-2.5 text-sm">
                {(
                  [
                    ['Records', source.records],
                    ['Sensitive assets', source.sensitiveAssets],
                    source.isLive ? ['Discovered tables', source.tableCount != null ? String(source.tableCount) : '—'] : null,
                    ['Last scan', source.lastScan],
                  ] as [string, string][]
                )
                  .filter(Boolean)
                  .map(([label, value]) => (
                    <div key={label} className="flex items-center justify-between gap-3">
                      <dt className="text-mist-500">{label}</dt>
                      <dd className="text-right text-mist-200">{value}</dd>
                    </div>
                  ))}
              </dl>
              <div className="mt-5 flex items-center justify-between gap-2">
                <span className={`rounded-full border px-2.5 py-1 text-[11px] font-bold tracking-[0.12em] ${riskTone[source.risk]}`}>
                  {source.risk.toUpperCase()}
                </span>
                {source.isLive ? (
                  <div className="flex gap-2">
                    <button
                      type="button"
                      onClick={() => openDiscover(source)}
                      className="rounded-lg border border-line px-3 py-1.5 text-xs font-medium text-mist-300 transition hover:border-line-strong hover:text-mist-100"
                    >
                      Discover
                    </button>
                    <button
                      type="button"
                      onClick={() => void openCatalog(source)}
                      className="rounded-lg border border-line px-3 py-1.5 text-xs font-medium text-mist-300 transition hover:border-line-strong hover:text-mist-100"
                    >
                      View catalog
                    </button>
                  </div>
                ) : (
                  <button
                    type="button"
                    onClick={() => setSelected(source)}
                    className="rounded-lg border border-line px-3 py-1.5 text-xs font-medium text-mist-300 transition hover:border-line-strong hover:text-mist-100"
                  >
                    View scan
                  </button>
                )}
              </div>
            </div>
          </Reveal>
        ))}
      </div>

      {/* Mock scan modal (unchanged landing-page behavior) */}
      <Modal
        open={selected !== null}
        onClose={() => setSelected(null)}
        title={selected ? `${selected.name} — mock scan` : 'Mock scan'}
        subtitle="Simulated discovery results. No real system was scanned."
      >
        {selected ? (
          <div className="space-y-3 text-sm">
            {[
              ['Category', selected.category],
              ['Records', selected.records],
              ['Sensitive assets', selected.sensitiveAssets],
              ['Last scan', selected.lastScan],
              ['Risk', selected.risk],
            ].map(([label, value]) => (
              <div key={label} className="flex items-center justify-between gap-4 rounded-xl border border-line bg-ink-950/60 px-4 py-3">
                <span className="text-mist-500">{label}</span>
                <span className="text-right text-mist-100">{value}</span>
              </div>
            ))}
          </div>
        ) : null}
      </Modal>

      {/* Connect modal */}
      <Modal
        open={connectOpen}
        onClose={() => setConnectOpen(false)}
        title="Connect PostgreSQL"
        subtitle="The connection is tested over TLS. Only non-secret details are saved — your password is used once and never stored."
      >
        <form onSubmit={(e) => void submitConnect(e)} className="space-y-4">
          <div>
            <label htmlFor="pg-name" className={labelClass}>Connection name</label>
            <input id="pg-name" value={connName} onChange={(e) => setConnName(e.target.value)} placeholder="Production analytics DB" required maxLength={80} className={inputClass} />
          </div>
          <div className="grid grid-cols-3 gap-3">
            <div className="col-span-2">
              <label htmlFor="pg-host" className={labelClass}>Host</label>
              <input id="pg-host" value={connHost} onChange={(e) => setConnHost(e.target.value)} placeholder="db.example.com" required className={inputClass} />
            </div>
            <div>
              <label htmlFor="pg-port" className={labelClass}>Port</label>
              <input id="pg-port" value={connPort} onChange={(e) => setConnPort(e.target.value)} placeholder="5432" inputMode="numeric" className={inputClass} />
            </div>
          </div>
          <div>
            <label htmlFor="pg-database" className={labelClass}>Database</label>
            <input id="pg-database" value={connDatabase} onChange={(e) => setConnDatabase(e.target.value)} placeholder="analytics" required className={inputClass} />
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label htmlFor="pg-username" className={labelClass}>Username</label>
              <input id="pg-username" value={connUsername} onChange={(e) => setConnUsername(e.target.value)} placeholder="readonly_user" required autoComplete="off" className={inputClass} />
            </div>
            <div>
              <label htmlFor="pg-password" className={labelClass}>Password</label>
              <input id="pg-password" type="password" value={connPassword} onChange={(e) => setConnPassword(e.target.value)} required autoComplete="new-password" className={inputClass} />
            </div>
          </div>
          <p className="text-xs text-mist-500">
            Use a read-only database user. Only table and column names are ever read — no row data leaves your database.
          </p>
          <p className="text-xs text-mist-500">
            The first run after deploying can take up to a minute while the server warms up. Please wait.
          </p>
          {connectError ? <p className="text-sm text-rose-400">{connectError}</p> : null}
          {connectSuccess ? <p className="text-sm text-mint-400">{connectSuccess}</p> : null}
          <button type="submit" disabled={connecting} className={primaryButtonClass}>
            {connecting ? 'Testing connection…' : 'Test & connect'}
          </button>
        </form>
      </Modal>

      {/* Discovery modal */}
      <Modal
        open={discoverSource !== null}
        onClose={() => setDiscoverSource(null)}
        title={discoverSource ? `Discover — ${discoverSource.name}` : 'Discover'}
        subtitle="Enter the database password to run discovery. It is used once for this run and never stored."
      >
        <form onSubmit={(e) => void submitDiscover(e)} className="space-y-4">
          <div>
            <label htmlFor="pg-discover-password" className={labelClass}>Database password</label>
            <input
              id="pg-discover-password"
              type="password"
              value={discoverPassword}
              onChange={(e) => setDiscoverPassword(e.target.value)}
              required
              autoComplete="new-password"
              className={inputClass}
            />
          </div>
          {discoverError ? <p className="text-sm text-rose-400">{discoverError}</p> : null}
          <p className="text-xs text-mist-500">
            The first run after deploying can take up to a minute while the server warms up. Please wait.
          </p>
          {discoverResult ? (
            <div className="rounded-xl border border-mint-400/30 bg-mint-400/10 px-4 py-3 text-sm text-mint-300">
              Discovered {discoverResult.tables} tables and {discoverResult.columns} columns —{' '}
              {discoverResult.inserted} new, {discoverResult.updated} updated in your catalog.
              {discoverResult.findings != null && discoverResult.findings > 0
                ? ` ${discoverResult.findings} sensitive-data finding${discoverResult.findings === 1 ? '' : 's'} recorded.`
                : ''}
              {discoverResult.columns_need_review != null && discoverResult.columns_need_review > 0
                ? ` ${discoverResult.columns_need_review} column${discoverResult.columns_need_review === 1 ? '' : 's'} need${discoverResult.columns_need_review === 1 ? 's' : ''} your review in the catalog.`
                : ''}
              {discoverResult.truncated ? ' (Results were capped; narrow the schemas if you need more.)' : ''}
            </div>
          ) : null}
          <button type="submit" disabled={discovering} className={primaryButtonClass}>
            {discovering ? 'Discovering…' : 'Run discovery'}
          </button>
        </form>
      </Modal>

      {/* Catalog modal */}
      <Modal
        open={catalogSource !== null}
        onClose={() => setCatalogSource(null)}
        title={catalogSource ? `${catalogSource.name} — discovered catalog` : 'Discovered catalog'}
        subtitle="Real table metadata from your database. Columns are labeled by deterministic rules — your manual labels always win."
      >
        <div className="mb-4 flex flex-wrap items-center gap-2">
          <button
            type="button"
            onClick={() => void runClassify()}
            disabled={classifying || catalogLoading}
            className="rounded-lg border border-line px-3 py-1.5 text-xs font-medium text-mist-300 transition hover:border-line-strong hover:text-mist-100 disabled:cursor-not-allowed disabled:opacity-60"
          >
            {classifying ? 'Classifying…' : 'Re-run classification'}
          </button>
          {findingsLoading ? (
            <span className="text-xs text-mist-500">Loading findings…</span>
          ) : (
            <span className="text-xs text-mist-500">
              {findings.length} open finding{findings.length === 1 ? '' : 's'}
            </span>
          )}
        </div>
        {classifyError ? <p className="mb-3 text-sm text-rose-400">{classifyError}</p> : null}
        {classifyResult ? (
          <div className="mb-3 rounded-xl border border-mint-400/30 bg-mint-400/10 px-4 py-3 text-sm text-mint-300">
            Classified {classifyResult.columns_classified} columns across {classifyResult.assets_processed}{' '}
            tables — {classifyResult.findings} findings
            {classifyResult.columns_need_review > 0
              ? `, ${classifyResult.columns_need_review} need${classifyResult.columns_need_review === 1 ? 's' : ''} your review.`
              : '.'}
          </div>
        ) : null}
        {findings.length > 0 ? (
          <div className="mb-4 space-y-2">
            {findings.slice(0, 5).map((f) => (
              <div key={f.id} className="flex items-start justify-between gap-3 rounded-xl border border-line bg-ink-950/60 px-4 py-2.5">
                <div className="text-xs">
                  <p className="font-medium text-mist-100">
                    {f.field_name ? `${f.asset_name}.${f.field_name}` : f.asset_name}
                  </p>
                  <p className="mt-0.5 text-mist-500">{f.description}</p>
                </div>
                <span className={`shrink-0 rounded-full border px-2 py-0.5 text-[10px] font-bold uppercase tracking-[0.12em] ${severityTone[f.severity] ?? severityTone.medium}`}>
                  {f.severity}
                </span>
              </div>
            ))}
            {findings.length > 5 ? (
              <p className="text-xs text-mist-500">+ {findings.length - 5} more findings</p>
            ) : null}
          </div>
        ) : null}
        {catalogLoading ? (
          <p className="text-sm text-mist-500">Loading catalog…</p>
        ) : catalogError ? (
          <p className="text-sm text-rose-400">{catalogError}</p>
        ) : catalogAssets.length === 0 ? (
          <p className="text-sm text-mist-500">No tables discovered yet. Run discovery first.</p>
        ) : (
          <div className="space-y-2">
            {catalogAssets.map((asset) => {
              const columns = assetColumns(asset);
              const rowEstimate = assetRowEstimate(asset);
              const expanded = expandedTable === asset.id;
              const needReview = columns.filter((c) => c.needs_review).length;
              return (
                <div key={asset.id} className="overflow-hidden rounded-xl border border-line bg-ink-950/60">
                  <button
                    type="button"
                    onClick={() => setExpandedTable(expanded ? null : asset.id)}
                    className="flex w-full items-center justify-between gap-3 px-4 py-3 text-left"
                  >
                    <span className="flex items-center gap-2 text-sm font-medium text-mist-100">
                      {asset.name}
                      <span className={`rounded-full border px-2 py-0.5 text-[10px] font-bold uppercase tracking-[0.12em] ${classificationTone[asset.classification] ?? classificationTone.internal}`}>
                        {asset.classification}
                      </span>
                    </span>
                    <span className="shrink-0 text-xs text-mist-500">
                      {columns.length} cols{rowEstimate != null ? ` · ~${rowEstimate.toLocaleString()} rows` : ''}
                      {needReview > 0 ? ` · ${needReview} to review` : ''}
                    </span>
                  </button>
                  {expanded ? (
                    <div className="border-t border-line px-4 py-3">
                      <dl className="space-y-2">
                        {columns.map((col) => {
                          const chip = classificationTone[col.classification ?? 'internal'] ?? classificationTone.internal;
                          const pendingKey = `${asset.id}:${col.name}`;
                          return (
                            <div key={col.position} className="flex items-center justify-between gap-3 text-xs">
                              <div className="min-w-0">
                                <dt className="truncate font-mono text-mist-200">{col.name}</dt>
                                <dd className="mt-0.5 text-mist-500">
                                  {col.type}
                                  {col.nullable ? '' : ' · not null'}
                                  {col.rule ? ` · ${col.rule}` : ''}
                                  {typeof col.confidence === 'number' ? ` · ${Math.round(col.confidence * 100)}%` : ''}
                                  {col.classified_by === 'manual' ? ' · yours' : ''}
                                </dd>
                              </div>
                              <div className="flex shrink-0 items-center gap-2">
                                {col.needs_review ? (
                                  <span className="rounded-full border border-amber-400/30 bg-amber-400/10 px-2 py-0.5 text-[10px] font-bold uppercase tracking-[0.12em] text-amber-300">
                                    Review
                                  </span>
                                ) : null}
                                <span className={`rounded-full border px-2 py-0.5 text-[10px] font-bold uppercase tracking-[0.12em] ${chip}`}>
                                  {col.classification ?? 'internal'}
                                </span>
                                <select
                                  aria-label={`Set classification for ${col.name}`}
                                  value=""
                                  disabled={overridePending === pendingKey}
                                  onChange={(e) => {
                                    if (e.target.value) void overrideColumn(asset, col.name, e.target.value);
                                    e.target.value = '';
                                  }}
                                  className="rounded-lg border border-line bg-ink-900 px-2 py-1 text-[11px] text-mist-400 focus:border-accent-400/60 focus:outline-none disabled:opacity-60"
                                >
                                  <option value="">Label…</option>
                                  {CLASSIFICATION_OPTIONS.map((opt) => (
                                    <option key={opt} value={opt}>
                                      {opt}
                                    </option>
                                  ))}
                                </select>
                              </div>
                            </div>
                          );
                        })}
                      </dl>
                    </div>
                  ) : null}
                </div>
              );
            })}
          </div>
        )}
      </Modal>
    </section>
  );
}
