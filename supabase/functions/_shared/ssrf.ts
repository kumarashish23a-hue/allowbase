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
// Residual risk (documented, not fixed here): DNS rebinding — a hostname that
// resolves to a public IP at connect time but a private IP at fetch time.
// Fully closing that needs resolve-then-pin per request.

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
