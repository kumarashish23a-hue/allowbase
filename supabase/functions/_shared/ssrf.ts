// SSRF protection for custom AI provider URLs.
//
// A custom provider's base_url is caller-supplied at connect time and later
// fetched by ai-gateway with the decrypted provider key attached. Without
// validation that fetch becomes server-side request forgery: an attacker
// could point it at169.254.169.254 (cloud metadata), localhost, or internal
// services.
//
// isSafeProviderUrl enforces: https only, no credentials in the URL, and a
// host that is not a private/loopback/link-local/reserved IP literal and not
// a known metadata/local hostname. It is checked BOTH when a provider is
// connected (ai-provider) and on every gateway call (ai-gateway), so stored
// URLs that predate the check are still rejected.
//
// isSafeProviderUrlAsync adds resolve-then-check: the hostname is resolved at
// request time and EVERY resolved IP must pass the blocklist. This closes the
// "DNS changed since connect time" hole.
//
// Residual risk (documented, not fixed here): true DNS rebinding in the tiny
// window between this resolution and fetch() — fetch() has no dialer override
// to pin the resolved IP while keeping TLS SNI for the original hostname, so
// a hostile DNS server that answers differently per query can still slip a
// private IP into the actual connection. When Deno.resolveDns is unavailable
// in the runtime, the async check falls back to the sync verdict (same
// residual, explicitly).

function ipv4ToInt(ip: string): number | null {
  const parts = ip.split('.');
  if (parts.length !== 4) return null;
  let n = 0;
  for (const p of parts) {
    if (!/^\d{1,3}$/.test(p)) return null;
    const v = parseInt(p, 10);
    if (v > 255) return null;
    n = n * 256 + v;
  }
  return n >>> 0;
}

function inRange(ip: number, base: string, bits: number): boolean {
  const b = ipv4ToInt(base);
  if (b === null) return false;
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
  return (ip & mask) === (b & mask);
}

// IPv4 ranges that must never be a provider target.
const BLOCKED_V4: Array<[string, number]> = [
  ['0.0.0.0', 8], // "this network"
  ['10.0.0.0', 8], // private
  ['100.64.0.0', 10], // carrier-grade NAT
  ['127.0.0.0', 8], // loopback
  ['169.254.0.0', 16], // link-local (cloud metadata lives here)
  ['172.16.0.0', 12], // private
  ['192.0.2.0', 24], // TEST-NET-1 (documentation)
  ['192.88.99.0', 24], // 6to4 relay (deprecated)
  ['192.168.0.0', 16], // private
  ['198.18.0.0', 15], // benchmark testing
  ['198.51.100.0', 24], // TEST-NET-2 (documentation)
  ['203.0.113.0', 24], // TEST-NET-3 (documentation)
  ['224.0.0.0', 4], // multicast
  ['240.0.0.0', 4], // reserved
];

function isBlockedIpLiteral(host: string): boolean {
  const v4 = ipv4ToInt(host);
  if (v4 !== null) {
    return BLOCKED_V4.some(([base, bits]) => inRange(v4, base, bits));
  }
  if (host.includes(':')) {
    // IPv6 literal (the URL parser strips the brackets).
    const h = host.toLowerCase();
    if (h === '::1' || h === '::') return true; // loopback / unspecified
    const first = h.split(':')[0];
    const group = parseInt(first || '0', 16);
    if (Number.isNaN(group)) return true; // unparseable -> refuse
    if ((group & 0xfe00) === 0xfc00) return true; // unique local, fc00::/7
    if ((group & 0xffc0) === 0xfe80) return true; // link-local, fe80::/10
  }
  return false;
}

// Hostnames that are never valid provider targets.
const BLOCKED_HOSTS = new Set([
  'localhost',
  'metadata.google.internal', // GCE metadata
  'metadata.goog', // GCE metadata (short)
  'instance-data', // EC2 metadata (short)
  'instance-data.compute.internal',
]);

/**
 * True when a custom provider base URL is safe to fetch: https, no embedded
 * credentials, public host. Pure function — safe to call on every request.
 */
export function isSafeProviderUrl(raw: string): boolean {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return false;
  }
  if (url.protocol !== 'https:') return false;
  if (url.username || url.password) return false;
  const host = url.hostname.toLowerCase();
  if (!host || BLOCKED_HOSTS.has(host) || host.endsWith('.localhost')) return false;
  if (isBlockedIpLiteral(host)) return false;
  return true;
}

type DenoWithDns = {
  resolveDns?: (query: string, recordType: 'A' | 'AAAA') => Promise<string[]>;
};

/**
 * Resolve a hostname to its A/AAAA records. Returns null when DNS resolution
 * is unavailable in this runtime (Deno.resolveDns missing) or fails, so
 * callers can fall back to the sync check instead of failing open or closed
 * on a platform limitation. Bounded by DNS_TIMEOUT_MS so a hanging resolver
 * can never stall the gateway.
 */
const DNS_TIMEOUT_MS = 2500;

async function resolveHostIps(host: string): Promise<string[] | null> {
  try {
    const deno = (globalThis as unknown as { Deno?: DenoWithDns }).Deno;
    const resolveDns = deno?.resolveDns;
    if (typeof resolveDns !== 'function') return null;
    const lookup = (async () => {
      const [a, aaaa] = await Promise.all([
        resolveDns(host, 'A').catch(() => [] as string[]),
        resolveDns(host, 'AAAA').catch(() => [] as string[]),
      ]);
      return [...a, ...aaaa];
    })();
    const timeout = new Promise<null>((resolve) => setTimeout(() => resolve(null), DNS_TIMEOUT_MS));
    return await Promise.race([lookup, timeout]);
  } catch {
    return null;
  }
}

/**
 * Async SSRF check: the sync verdict PLUS resolve-then-check — every IP the
 * hostname currently resolves to must pass the blocklist. IP literals need
 * no resolution (the sync pass already judged them).
 *
 * When DNS is unavailable in the runtime, the sync verdict stands and the
 * DNS-rebinding residual documented at the top of this module applies.
 */
export async function isSafeProviderUrlAsync(raw: string): Promise<boolean> {
  if (!isSafeProviderUrl(raw)) return false;
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return false;
  }
  const host = url.hostname.toLowerCase();
  if (ipv4ToInt(host) !== null || host.includes(':')) return true; // literal, already judged
  const ips = await resolveHostIps(host);
  if (ips === null) return true; // no DNS in this runtime — sync verdict stands
  if (ips.length === 0) return false; // unresolvable host — refuse
  return ips.every((ip) => !isBlockedIpLiteral(ip));
}
