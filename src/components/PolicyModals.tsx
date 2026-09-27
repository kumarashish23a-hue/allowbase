import { Plus, Trash2 } from 'lucide-react';
import { useState } from 'react';
import type { RequestExample } from '../types';
import type {
  PolicyAction,
  PolicyConditionDraft,
  PolicyDraft,
  PolicyOperator,
} from '../services/policyService';
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

interface PolicyBuilderModalProps {
  open: boolean;
  onClose: () => void;
  onCreate: (draft: PolicyDraft) => Promise<void>;
}

interface FieldDef {
  value: string;
  label: string;
  kind: 'multi' | 'boolean' | 'text';
  options?: string[];
  operators: PolicyOperator[];
  hint: string;
}

/** The exact condition vocabulary the enforcement engine understands. */
const FIELDS: FieldDef[] = [
  {
    value: 'data.classification',
    label: 'Data classification',
    kind: 'multi',
    options: ['public', 'internal', 'confidential', 'restricted'],
    operators: ['in', 'not_in', 'equals', 'not_equals'],
    hint: 'How the data asset is classified.',
  },
  {
    value: 'data.sensitivity_level',
    label: 'Data sensitivity',
    kind: 'multi',
    options: ['none', 'low', 'medium', 'high', 'critical'],
    operators: ['in', 'not_in', 'equals', 'not_equals'],
    hint: 'Sensitivity level of the data asset.',
  },
  {
    value: 'content.category',
    label: 'Detected in content',
    kind: 'multi',
    options: ['email', 'phone', 'credit_card', 'gov_id', 'api_key', 'private_key', 'jwt', 'secret'],
    operators: ['in', 'not_in', 'equals', 'not_equals'],
    hint: 'What the scanner found in the request text.',
  },
  {
    value: 'ai.is_external',
    label: 'AI is external',
    kind: 'boolean',
    operators: ['equals', 'not_equals'],
    hint: 'Whether the AI system lives outside your boundary.',
  },
  {
    value: 'ai.is_approved',
    label: 'AI is approved',
    kind: 'boolean',
    operators: ['equals', 'not_equals'],
    hint: 'Whether the AI system is on your approved list.',
  },
  {
    value: 'ai.provider',
    label: 'AI provider',
    kind: 'multi',
    options: ['openai', 'anthropic', 'google', 'azure', 'internal', 'custom'],
    operators: ['in', 'not_in', 'equals', 'not_equals'],
    hint: 'Who provides the AI — openai targets ChatGPT.',
  },
  {
    value: 'purpose',
    label: 'Purpose',
    kind: 'text',
    operators: ['equals', 'not_equals', 'in'],
    hint: 'Why the AI is being asked, e.g. Customer Analysis.',
  },
];

const OPERATOR_LABELS: Record<PolicyOperator, string> = {
  equals: 'is',
  not_equals: 'is not',
  in: 'is one of',
  not_in: 'is none of',
};

const ACTIONS: { value: PolicyAction; label: string; desc: string }[] = [
  { value: 'allow', label: 'ALLOW', desc: 'Let it through, logged for audit.' },
  { value: 'block', label: 'BLOCK', desc: 'Stop it. The AI never sees the data.' },
  { value: 'mask', label: 'MASK', desc: 'Hide detected secrets, then allow.' },
  { value: 'redact', label: 'REDACT', desc: 'Remove sensitive parts, then allow.' },
  { value: 'require_approval', label: 'REQUIRE APPROVAL', desc: 'Hold it until someone approves.' },
];

interface ConditionRow {
  field: string;
  operator: PolicyOperator;
  value: string | string[] | boolean;
}

function newRow(): ConditionRow {
  return { field: 'data.classification', operator: 'in', value: ['confidential', 'restricted'] };
}

function fieldDef(value: string): FieldDef {
  return FIELDS.find((f) => f.value === value) ?? FIELDS[0];
}

function describeCondition(row: ConditionRow): string {
  const def = fieldDef(row.field);
  const op = OPERATOR_LABELS[row.operator];
  let val: string;
  if (def.kind === 'boolean') {
    val = row.value === true ? 'true' : 'false';
  } else if (def.kind === 'text') {
    val = `“${String(row.value)}”`;
  } else {
    val = Array.isArray(row.value) ? row.value.join(', ') : String(row.value);
  }
  return `${def.label.toLowerCase()} ${op} ${val}`;
}

const inputCls =
  'mt-2 w-full rounded-xl border border-line bg-ink-950/70 px-3 py-2.5 text-sm text-mist-100 focus:border-accent-400/60 focus:outline-none';
const labelCls = 'text-xs font-semibold uppercase tracking-[0.16em] text-mist-500';

export function PolicyBuilderModal({ open, onClose, onCreate }: PolicyBuilderModalProps) {
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [rows, setRows] = useState<ConditionRow[]>([newRow()]);
  const [action, setAction] = useState<PolicyAction>('block');
  const [priority, setPriority] = useState('10');
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);

  const updateRow = (index: number, patch: Partial<ConditionRow>) => {
    setRows((current) => current.map((row, i) => (i === index ? { ...row, ...patch } : row)));
  };

  const setField = (index: number, field: string) => {
    const def = fieldDef(field);
    const operator = def.operators[0];
    const value =
      def.kind === 'multi'
        ? (def.options ?? []).filter((o) => o === 'confidential' || o === 'restricted')
        : def.kind === 'boolean'
          ? true
          : '';
    const normalized: string[] =
      def.kind === 'multi'
        ? ((value as string[]).length > 0 ? (value as string[]) : [def.options![0]])
        : [];
    updateRow(index, {
      field,
      operator,
      value: def.kind === 'multi' ? normalized : (value as string | boolean),
    });
  };

  const addRow = () => setRows((current) => [...current, newRow()]);
  const removeRow = (index: number) =>
    setRows((current) => (current.length > 1 ? current.filter((_, i) => i !== index) : current));

  const validate = (): string | null => {
    if (!name.trim()) return 'Give the policy a name.';
    for (const row of rows) {
      const def = fieldDef(row.field);
      if (def.kind === 'multi') {
        const selected = Array.isArray(row.value) ? row.value : [];
        if (selected.length === 0) return `Pick at least one value for “${def.label}”.`;
      } else if (def.kind === 'text') {
        if (!String(row.value).trim()) return `Type a value for “${def.label}”.`;
      }
    }
    const p = Number(priority);
    if (!Number.isFinite(p) || p < 0) return 'Priority must be a number, 0 or higher.';
    return null;
  };

  const save = async () => {
    const problem = validate();
    if (problem) {
      setError(problem);
      return;
    }
    setError(null);
    setSaving(true);
    try {
      const draft: PolicyDraft = {
        name: name.trim(),
        description: description.trim(),
        action,
        priority: Math.floor(Number(priority)),
        conditions: rows.map(
          (row): PolicyConditionDraft => ({
            field: row.field,
            operator: row.operator,
            value: row.value,
          }),
        ),
      };
      await onCreate(draft);
      onClose();
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Could not save the policy.');
    } finally {
      setSaving(false);
    }
  };

  const actionLabel = ACTIONS.find((a) => a.value === action)?.label ?? action;
  const preview =
    rows.length > 0
      ? `IF ${rows.map(describeCondition).join(' AND ')} THEN ${actionLabel.toLowerCase()} (priority ${priority || '10'})`
      : '';

  return (
    <Modal open={open} onClose={onClose} title="Create policy" subtitle="Real policy. Saved to your workspace and enforced on every AI request.">
      <div className="space-y-4">
        <div>
          <label htmlFor="policy-name" className={labelCls}>
            Policy name
          </label>
          <input
            id="policy-name"
            value={name}
            onChange={(event) => setName(event.target.value)}
            placeholder="e.g. Block student records from external AI"
            className={inputCls}
          />
        </div>
        <div>
          <label htmlFor="policy-desc" className={labelCls}>
            Description <span className="normal-case tracking-normal text-mist-600">(optional)</span>
          </label>
          <input
            id="policy-desc"
            value={description}
            onChange={(event) => setDescription(event.target.value)}
            placeholder="Why this rule exists"
            className={inputCls}
          />
        </div>

        <div>
          <span className={labelCls}>If — all of these must match</span>
          <div className="mt-2 space-y-3">
            {rows.map((row, index) => {
              const def = fieldDef(row.field);
              const multi = def.kind === 'multi';
              const useCheckboxes = multi && (row.operator === 'in' || row.operator === 'not_in');
              const selected = Array.isArray(row.value) ? row.value : [];
              return (
                <div key={index} className="rounded-xl border border-line bg-ink-950/40 p-3">
                  {index > 0 ? (
                    <p className="mb-2 text-[11px] font-bold text-accent-600">AND</p>
                  ) : null}
                  <div className="grid gap-2 sm:grid-cols-2">
                    <div>
                      <label htmlFor={`cond-field-${index}`} className={labelCls}>
                        Field
                      </label>
                      <select
                        id={`cond-field-${index}`}
                        value={row.field}
                        onChange={(event) => setField(index, event.target.value)}
                        className={inputCls}
                      >
                        {FIELDS.map((f) => (
                          <option key={f.value} value={f.value}>
                            {f.label}
                          </option>
                        ))}
                      </select>
                    </div>
                    <div>
                      <label htmlFor={`cond-op-${index}`} className={labelCls}>
                        Operator
                      </label>
                      <select
                        id={`cond-op-${index}`}
                        value={row.operator}
                        onChange={(event) =>
                          updateRow(index, { operator: event.target.value as PolicyOperator })
                        }
                        className={inputCls}
                      >
                        {def.operators.map((op) => (
                          <option key={op} value={op}>
                            {OPERATOR_LABELS[op]}
                          </option>
                        ))}
                      </select>
                    </div>
                  </div>
                  <div className="mt-2">
                    <span className={labelCls}>Value</span>
                    {def.kind === 'boolean' ? (
                      <div className="mt-2 flex gap-2">
                        {[true, false].map((b) => (
                          <button
                            key={String(b)}
                            type="button"
                            onClick={() => updateRow(index, { value: b })}
                            aria-pressed={row.value === b}
                            className={`flex-1 rounded-xl border px-3 py-2 text-xs font-bold tracking-[0.1em] transition ${
                              row.value === b
                                ? 'border-accent-400/60 bg-accent-500/15 text-accent-600'
                                : 'border-line text-mist-400 hover:text-mist-100'
                            }`}
                          >
                            {b ? 'TRUE' : 'FALSE'}
                          </button>
                        ))}
                      </div>
                    ) : def.kind === 'text' ? (
                      <input
                        id={`cond-value-${index}`}
                        value={String(row.value)}
                        onChange={(event) => updateRow(index, { value: event.target.value })}
                        placeholder={
                          row.operator === 'in' ? 'Comma-separated, e.g. Support, Analysis' : 'e.g. Customer Analysis'
                        }
                        className={inputCls}
                      />
                    ) : useCheckboxes ? (
                      <div className="mt-2 flex flex-wrap gap-2">
                        {def.options!.map((option) => {
                          const checked = selected.includes(option);
                          return (
                            <button
                              key={option}
                              type="button"
                              onClick={() =>
                                updateRow(index, {
                                  value: checked
                                    ? selected.filter((s) => s !== option)
                                    : [...selected, option],
                                })
                              }
                              aria-pressed={checked}
                              className={`rounded-lg border px-2.5 py-1.5 text-xs transition ${
                                checked
                                  ? 'border-accent-400/60 bg-accent-500/15 text-accent-600'
                                  : 'border-line text-mist-400 hover:text-mist-100'
                              }`}
                            >
                              {option}
                            </button>
                          );
                        })}
                      </div>
                    ) : (
                      <select
                        id={`cond-value-${index}`}
                        value={selected[0] ?? ''}
                        onChange={(event) => updateRow(index, { value: [event.target.value] })}
                        className={inputCls}
                      >
                        {def.options!.map((option) => (
                          <option key={option} value={option}>
                            {option}
                          </option>
                        ))}
                      </select>
                    )}
                    <p className="mt-1 text-[11px] text-mist-600">{def.hint}</p>
                  </div>
                  {rows.length > 1 ? (
                    <button
                      type="button"
                      onClick={() => removeRow(index)}
                      className="mt-2 inline-flex items-center gap-1 text-xs text-mist-500 transition hover:text-rose-400"
                    >
                      <Trash2 size={12} /> Remove condition
                    </button>
                  ) : null}
                </div>
              );
            })}
          </div>
          <button
            type="button"
            onClick={addRow}
            className="mt-2 inline-flex items-center gap-1.5 text-sm text-accent-600 transition hover:text-accent-500"
          >
            <Plus size={14} /> Add condition
          </button>
        </div>

        <div>
          <span className={labelCls}>Then</span>
          <div className="mt-2 grid grid-cols-2 gap-2 sm:grid-cols-3">
            {ACTIONS.map((a) => (
              <button
                key={a.value}
                type="button"
                onClick={() => setAction(a.value)}
                aria-pressed={action === a.value}
                title={a.desc}
                className={`rounded-xl border px-3 py-2.5 text-xs font-bold tracking-[0.1em] transition ${
                  action === a.value
                    ? 'border-accent-400/60 bg-accent-500/15 text-accent-600'
                    : 'border-line text-mist-400 hover:text-mist-100'
                }`}
              >
                {a.label}
              </button>
            ))}
          </div>
          <p className="mt-1 text-[11px] text-mist-600">
            {ACTIONS.find((a) => a.value === action)?.desc}
          </p>
        </div>

        <div>
          <label htmlFor="policy-priority" className={labelCls}>
            Priority
          </label>
          <input
            id="policy-priority"
            type="number"
            min={0}
            value={priority}
            onChange={(event) => setPriority(event.target.value)}
            className={inputCls}
          />
          <p className="mt-1 text-[11px] text-mist-600">
            Lower numbers are checked first. The first matching policy wins.
          </p>
        </div>

        {preview ? (
          <p className="rounded-xl border border-line bg-ink-950/60 px-3 py-2.5 text-xs leading-relaxed text-mist-300">
            {preview}
          </p>
        ) : null}
        {error ? <p className="text-sm text-rose-400">{error}</p> : null}

        <button
          type="button"
          onClick={() => void save()}
          disabled={saving}
          className="w-full rounded-xl bg-accent-500 px-4 py-3 text-sm font-semibold text-accent-ink transition hover:bg-accent-400 disabled:opacity-50"
        >
          {saving ? 'Saving…' : 'Save policy'}
        </button>
      </div>
    </Modal>
  );
}
