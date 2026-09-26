import { useState } from 'react';
import type { Policy, RequestExample } from '../types';
import { Modal } from './Modal';

interface InfoModalProps {
  open: boolean;
  kind: 'policy' | 'data' | 'audit' | null;
  request: RequestExample | null;
  onClose: () => void;
}

export function InfoModal({ open, kind, request, onClose }: InfoModalProps) {
  if (!kind || !request) return null;

  const title = kind === 'policy' ? 'Policy detail' : kind === 'data' ? 'Data detail' : 'Audit log entry';

  return (
    <Modal open={open} onClose={onClose} title={title} subtitle="Mock detail view for this prototype.">
      {kind === 'policy' ? (
        <div className="space-y-4">
          <p className="text-sm text-mist-200">{request.policy}</p>
          <div className="rounded-xl border border-line bg-ink-950/60 p-4 text-sm">
            <p className="text-mist-400">Enforcement</p>
            <p className="mt-1 text-mist-100">
              {request.decision === 'BLOCK'
                ? 'Block the request, notify the data owner, and create a sensitive event.'
                : 'Allow the request with full audit logging.'}
            </p>
          </div>
          <p className="text-xs text-mist-600">Decision: {request.decision} · Reason: {request.reason}</p>
        </div>
      ) : null}

      {kind === 'data' ? (
        <div className="space-y-4">
          <div className="grid grid-cols-2 gap-3 text-sm">
            <div className="rounded-xl border border-line bg-ink-950/60 p-4">
              <p className="text-xs text-mist-500">Dataset</p>
              <p className="mt-1 text-mist-100">{request.data}</p>
            </div>
            <div className="rounded-xl border border-line bg-ink-950/60 p-4">
              <p className="text-xs text-mist-500">Purpose</p>
              <p className="mt-1 text-mist-100">{request.purpose}</p>
            </div>
          </div>
          <div>
            <p className="text-xs uppercase tracking-[0.16em] text-mist-500">Detected</p>
            <div className="mt-2 flex flex-wrap gap-2">
              {request.detected.map((item) => (
                <span key={item} className="rounded-full border border-line bg-ink-950/70 px-2.5 py-1 text-xs text-mist-300">
                  {item}
                </span>
              ))}
            </div>
          </div>
          <p className="text-xs text-mist-600">Classification is simulated. No real data was inspected.</p>
        </div>
      ) : null}

      {kind === 'audit' ? (
        <div className="space-y-3 text-sm">
          {[
            ['Who', request.user],
            ['What', `${request.data} → ${request.ai}`],
            ['When', 'Just now (simulated)'],
            ['Which AI', request.ai],
            ['Purpose', request.purpose],
            ['Decision', request.decision],
          ].map(([label, value]) => (
            <div key={label} className="flex items-center justify-between gap-4 rounded-xl border border-line bg-ink-950/60 px-4 py-3">
              <span className="text-mist-500">{label}</span>
              <span className="text-right text-mist-100">{value}</span>
            </div>
          ))}
          <p className="text-xs text-mist-600">Audit ID: audit_demo_9f32c1 · Immutable in a production deployment.</p>
        </div>
      ) : null}
    </Modal>
  );
}

interface CreatePolicyModalProps {
  open: boolean;
  onClose: () => void;
  onCreate: (policy: Policy) => void;
}

export function CreatePolicyModal({ open, onClose, onCreate }: CreatePolicyModalProps) {
  const [name, setName] = useState('New AI data policy');
  const [dataType, setDataType] = useState('PII');
  const [destination, setDestination] = useState('External AI');
  const [effect, setEffect] = useState<'ALLOW' | 'BLOCK' | 'REDACT'>('BLOCK');

  const save = () => {
    onCreate({
      id: `pol-${Date.now()}`,
      name: name.trim() || 'Untitled policy',
      description: 'Created in the prototype policy builder.',
      conditions: [
        { field: 'Data', operator: '=', value: dataType },
        { field: 'Destination', operator: '=', value: destination },
      ],
      action: effect === 'ALLOW' ? 'Allow matching requests with audit logging.' : effect === 'BLOCK' ? 'Block matching requests and notify the owner.' : 'Redact sensitive fields before allowing.',
      effect,
      updated: 'Just now',
    });
    onClose();
  };

  return (
    <Modal open={open} onClose={onClose} title="Create policy" subtitle="Demo builder. Policies are stored only in this browser session.">
      <div className="space-y-4">
        <div>
          <label htmlFor="policy-name" className="text-xs font-semibold uppercase tracking-[0.16em] text-mist-500">
            Policy name
          </label>
          <input
            id="policy-name"
            value={name}
            onChange={(event) => setName(event.target.value)}
            className="mt-2 w-full rounded-xl border border-line bg-ink-950/70 px-3 py-2.5 text-sm text-mist-100 focus:border-accent-400/60 focus:outline-none"
          />
        </div>
        <div className="grid gap-4 sm:grid-cols-2">
          <div>
            <label htmlFor="policy-data" className="text-xs font-semibold uppercase tracking-[0.16em] text-mist-500">
              Data
            </label>
            <select
              id="policy-data"
              value={dataType}
              onChange={(event) => setDataType(event.target.value)}
              className="mt-2 w-full rounded-xl border border-line bg-ink-950/70 px-3 py-2.5 text-sm text-mist-100 focus:border-accent-400/60 focus:outline-none"
            >
              {['PII', 'Financial', 'Credentials', 'Source Code', 'Confidential'].map((option) => (
                <option key={option}>{option}</option>
              ))}
            </select>
          </div>
          <div>
            <label htmlFor="policy-destination" className="text-xs font-semibold uppercase tracking-[0.16em] text-mist-500">
              Destination
            </label>
            <select
              id="policy-destination"
              value={destination}
              onChange={(event) => setDestination(event.target.value)}
              className="mt-2 w-full rounded-xl border border-line bg-ink-950/70 px-3 py-2.5 text-sm text-mist-100 focus:border-accent-400/60 focus:outline-none"
            >
              {['External AI', 'Internal AI', 'Approved Internal Agent'].map((option) => (
                <option key={option}>{option}</option>
              ))}
            </select>
          </div>
        </div>
        <div>
          <span className="text-xs font-semibold uppercase tracking-[0.16em] text-mist-500">Then</span>
          <div className="mt-2 grid grid-cols-3 gap-2">
            {(['ALLOW', 'BLOCK', 'REDACT'] as const).map((option) => (
              <button
                key={option}
                type="button"
                onClick={() => setEffect(option)}
                aria-pressed={effect === option}
                className={`rounded-xl border px-3 py-2.5 text-xs font-bold tracking-[0.12em] transition ${
                  effect === option
                    ? 'border-accent-400/60 bg-accent-500/15 text-accent-600'
                    : 'border-line text-mist-400 hover:text-mist-100'
                }`}
              >
                {option}
              </button>
            ))}
          </div>
        </div>
        <button
          type="button"
          onClick={save}
          className="w-full rounded-xl bg-accent-500 px-4 py-3 text-sm font-semibold text-accent-ink transition hover:bg-accent-400"
        >
          Save demo policy
        </button>
      </div>
    </Modal>
  );
}
