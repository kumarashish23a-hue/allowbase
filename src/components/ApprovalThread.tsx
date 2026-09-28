import { MessageSquare, Send } from 'lucide-react';
import { useEffect, useState, type KeyboardEvent } from 'react';
import { addApprovalComment, getApprovalTimeline, type TimelineItem } from '../services/approvalService';

const actionLabel: Record<string, string> = {
  approval_approved: 'approved the request',
  approval_rejected: 'rejected the request',
  approval_expired: 'Request expired without a decision',
  approval_escalated: 'escalated the request',
  approval_delegated: 'delegated the review',
  approval_unassigned: 'removed the assigned reviewer',
};

function describe(item: TimelineItem): string {
  if (item.action === 'approval_escalated' && item.metadata?.automatic === true) {
    return `Auto-escalated to level ${String(item.metadata.level ?? 1)} (waiting over 24h)`;
  }
  const who = item.actor_type === 'system' ? '' : `${item.actor_name ?? 'A teammate'} `;
  const label = actionLabel[item.action ?? ''] ?? (item.action ?? 'updated').replace(/_/g, ' ');
  if (item.action === 'approval_escalated') return `${who}${label} to level ${String(item.metadata?.level ?? '')}`;
  return `${who}${label}`;
}

/** Audit timeline + discussion for one approval request. */
export function ApprovalThread({ approvalId, canComment }: { approvalId: string; canComment: boolean }) {
  const [items, setItems] = useState<TimelineItem[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [draft, setDraft] = useState('');
  const [posting, setPosting] = useState(false);
  const [reloadKey, setReloadKey] = useState(0);

  useEffect(() => {
    let cancelled = false;
    getApprovalTimeline(approvalId)
      .then((loaded) => {
        if (!cancelled) setItems(loaded);
      })
      .catch((err) => {
        if (!cancelled) setError(err instanceof Error ? err.message : 'Could not load history.');
      });
    return () => {
      cancelled = true;
    };
  }, [approvalId, reloadKey]);

  const post = async () => {
    if (!draft.trim() || posting) return;
    setPosting(true);
    setError(null);
    try {
      await addApprovalComment(approvalId, draft);
      setDraft('');
      setReloadKey((k) => k + 1);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not add the comment.');
    } finally {
      setPosting(false);
    }
  };

  const onKeyDown = (event: KeyboardEvent<HTMLTextAreaElement>) => {
    if (event.key === 'Enter' && (event.metaKey || event.ctrlKey)) {
      if (event.nativeEvent.isComposing || event.keyCode === 229) return;
      event.preventDefault();
      void post();
    }
  };

  return (
    <div className="mt-4 rounded-xl border border-line bg-ink-900/50 p-4">
      <p className="flex items-center gap-1.5 text-xs font-semibold uppercase tracking-[0.16em] text-mist-500">
        <MessageSquare size={12} aria-hidden="true" /> Activity
      </p>
      {error ? <p className="mt-2 text-xs text-rose-400">{error}</p> : null}
      {items === null && !error ? (
        <p className="mt-3 text-xs text-mist-500">Loading…</p>
      ) : items && items.length === 0 ? (
        <p className="mt-3 text-xs text-mist-500">No activity yet.</p>
      ) : (
        <ol className="mt-3 space-y-2.5">
          {(items ?? []).map((item) => (
            <li key={`${item.kind}-${item.id}`} className="text-xs">
              {item.kind === 'comment' ? (
                <div className="rounded-lg border border-line bg-ink-950/70 px-3 py-2">
                  <p className="font-semibold text-mist-200">{item.actor_name ?? 'Teammate'}</p>
                  <p className="mt-0.5 whitespace-pre-wrap break-words text-mist-300">{item.body}</p>
                </div>
              ) : (
                <p className="text-mist-400">
                  {describe(item)}
                  {item.note ? <span className="text-mist-500">{` — “${item.note}”`}</span> : null}
                </p>
              )}
              <p className="mt-0.5 text-[10px] text-mist-600">{new Date(item.at).toLocaleString()}</p>
            </li>
          ))}
        </ol>
      )}
      {canComment ? (
        <div className="mt-3 flex items-end gap-2">
          <label htmlFor={`comment-${approvalId}`} className="sr-only">
            Add a comment
          </label>
          <textarea
            id={`comment-${approvalId}`}
            value={draft}
            onChange={(e) => setDraft(e.target.value)}
            onKeyDown={onKeyDown}
            rows={2}
            maxLength={2000}
            placeholder="Add context for reviewers (Ctrl/Cmd + Enter to post)"
            className="min-w-0 flex-1 resize-none rounded-lg border border-line bg-ink-950/70 px-3 py-2 text-xs text-mist-100 placeholder:text-mist-600 focus:border-accent-400/60 focus:outline-none"
          />
          <button
            type="button"
            onClick={() => void post()}
            disabled={!draft.trim() || posting}
            aria-label="Post comment"
            className="rounded-lg border border-line p-2 text-mist-300 transition hover:border-line-strong hover:text-mist-100 disabled:opacity-40"
          >
            <Send size={14} />
          </button>
        </div>
      ) : null}
    </div>
  );
}
