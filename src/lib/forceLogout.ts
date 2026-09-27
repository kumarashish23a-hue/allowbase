import { getLocalUserId, getSupabase } from './supabase';

/**
 * Remote sign-out enforcement.
 *
 * When an owner/admin force-logs-out a member, the admin's app sets
 * `organization_members.force_logout_at`. This module watches that flag and
 * signs the member out of the app:
 *   - immediately on boot,
 *   - every minute while the app is open,
 *   - when the window regains focus.
 *
 * Ack tracking (so a fresh sign-in is never killed by an old flag):
 *   - `dcp-logout-ack:<userId>` = the newest force_logout_at this browser has
 *     already honored.
 *   - `dcp-ever-signed-in:<userId>` = this browser has completed a sign-in
 *     here before. A browser without it acknowledges the current state
 *     instead of enforcing (covers brand-new devices).
 *   - A fresh SIGNED_IN event acknowledges everything up to now: only
 *     force-logouts issued *after* that sign-in can kick the session.
 *
 * This is app-level enforcement. It signs the member out of the Data Control
 * Plane app promptly, but their API access token remains valid until it
 * expires. Clearing browser storage bypasses it — for hard revocation,
 * remove the member as well.
 */

const ACK_PREFIX = 'dcp-logout-ack:';
const SEEN_PREFIX = 'dcp-ever-signed-in:';
export const FORCE_LOGOUT_NOTICE_KEY = 'dcp-force-logout-notice';

function ackKey(userId: string): string {
  return `${ACK_PREFIX}${userId}`;
}

function seenKey(userId: string): string {
  return `${SEEN_PREFIX}${userId}`;
}

function readAck(userId: string): string | null {
  try {
    return localStorage.getItem(ackKey(userId));
  } catch {
    return null;
  }
}

function writeAck(userId: string, value: string): void {
  try {
    localStorage.setItem(ackKey(userId), value);
  } catch {
    /* storage unavailable — enforcement simply retries next tick */
  }
}

/** Newest force_logout_at across my memberships, or null when none (or when the column is missing). */
async function latestForceLogoutAt(userId: string): Promise<string | null> {
  const supabase = getSupabase();
  if (!supabase) return null;
  const { data, error } = await supabase
    .from('organization_members')
    .select('force_logout_at')
    .eq('user_id', userId)
    .not('force_logout_at', 'is', null)
    .order('force_logout_at', { ascending: false })
    .limit(1);
  if (error || !data || data.length === 0) return null;
  return (data[0] as { force_logout_at: string | null }).force_logout_at;
}

/** Acknowledge everything up to now (used on fresh sign-in / first run in a browser). */
async function acknowledgeCurrentMax(userId: string): Promise<void> {
  const latest = await latestForceLogoutAt(userId).catch(() => null);
  writeAck(userId, latest ?? '');
  try {
    localStorage.setItem(seenKey(userId), '1');
  } catch {
    /* ignore */
  }
}

/** Sign out now if a force-logout was issued after the last ack. */
async function enforce(): Promise<void> {
  const supabase = getSupabase();
  if (!supabase) return;
  const userId = await getLocalUserId().catch(() => null);
  if (!userId) return;
  const latest = await latestForceLogoutAt(userId).catch(() => null);
  if (!latest) return;

  let seen = false;
  try {
    seen = localStorage.getItem(seenKey(userId)) === '1';
  } catch {
    seen = false;
  }
  if (!seen) {
    // First run in this browser (e.g. a new device): acknowledge, don't punish.
    await acknowledgeCurrentMax(userId);
    return;
  }

  const ack = readAck(userId);
  if (ack && latest <= ack) return;

  // Force-logged out during this browser's lifetime: sign out.
  writeAck(userId, latest);
  try {
    sessionStorage.setItem(FORCE_LOGOUT_NOTICE_KEY, '1');
  } catch {
    /* ignore */
  }
  await supabase.auth.signOut().catch(() => {});
  window.location.reload();
}

/**
 * Start watching for remote sign-outs. Returns a stop function.
 * Safe to call once at app boot.
 */
export function initForceLogoutWatch(): () => void {
  const supabase = getSupabase();
  if (!supabase) return () => {};
  let stopped = false;

  const { data: { subscription } } = supabase.auth.onAuthStateChange((event) => {
    if (stopped || event !== 'SIGNED_IN') return;
    // A fresh sign-in starts clean: only later force-logouts apply.
    void getLocalUserId()
      .then((userId) => {
        if (userId) void acknowledgeCurrentMax(userId);
      })
      .catch(() => {});
  });

  const tick = () => {
    if (!stopped) void enforce();
  };
  const timer = window.setInterval(tick, 60_000);
  window.addEventListener('focus', tick);
  void enforce();

  return () => {
    stopped = true;
    subscription.unsubscribe();
    window.clearInterval(timer);
    window.removeEventListener('focus', tick);
  };
}

/** True when the last sign-out was forced by a workspace admin. Consumes the flag. */
export function consumeForceLogoutNotice(): boolean {
  try {
    if (sessionStorage.getItem(FORCE_LOGOUT_NOTICE_KEY) === '1') {
      sessionStorage.removeItem(FORCE_LOGOUT_NOTICE_KEY);
      return true;
    }
  } catch {
    /* ignore */
  }
  return false;
}
