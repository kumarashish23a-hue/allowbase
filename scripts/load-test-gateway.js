// load-test-gateway.js — k6 load test for the AllowBase AI gateway.
//
// What it proves:
//   1. The per-key rate limiter on ingest-event (600 req/min, migration 020)
//      actually engages under real load: we push ~800 req/min and expect
//      HTTP 429s carrying a Retry-After header and {error:"rate_limited"}.
//   2. No unexpected failures under load (no 5xx, no malformed 429s).
//   3. Latency stays sane while being rate-limited (p95 of allowed requests).
//
// WARNING: this writes real rows into your production org (one ai_request +
// audit row per allowed event, tagged purpose="load-test"). Run it, read the
// report, then filter those out in the console's Requests tab if you want.
//
// Run (macOS):
//   brew install k6            # once
//   export ALLOWBASE_API_KEY="dcp_live_..."   # your AllowBase API key (shown once at creation)
//   k6 run scripts/load-test-gateway.js
//
// Optional env:
//   BASE_URL    default https://xusjrmruvzfwyaxtxylw.supabase.co/functions/v1
//   TARGET_RPM  default 800 (must stay above 600 to trip the limiter)
//
// NOTE: evaluate-ai-request and ai-gateway need a signed-in user JWT, so they
// are not covered here — ingest-event is the API-key endpoint and the right
// one to hammer for the rate-limiter proof.

import http from 'k6/http';
import { check } from 'k6';
import { Counter, Trend } from 'k6/metrics';

const API_KEY = __ENV.ALLOWBASE_API_KEY;
const BASE_URL =
  __ENV.BASE_URL || 'https://xusjrmruvzfwyaxtxylw.supabase.co/functions/v1';
const TARGET_RPM = parseInt(__ENV.TARGET_RPM || '800', 10);

if (!API_KEY) {
  throw new Error(
    'Set ALLOWBASE_API_KEY first: export ALLOWBASE_API_KEY="dcp_live_..."'
  );
}

const allowed = new Counter('allowed_requests');
const limited = new Counter('rate_limited_requests');
const unexpected = new Counter('unexpected_requests');
const allowedLatency = new Trend('allowed_latency_ms');

export const options = {
  scenarios: {
    flood: {
      executor: 'constant-arrival-rate',
      rate: TARGET_RPM,
      timeUnit: '1m',
      duration: '2m',
      preAllocatedVUs: 30,
      maxVUs: 100,
    },
  },
  thresholds: {
    // Zero surprises: no 5xx, no malformed 429s.
    unexpected_requests: ['count==0'],
    // The limiter MUST engage — tripping it is the whole point of the test.
    rate_limited_requests: ['count>0'],
  },
};

export default function () {
  // Unique event_id per iteration so every request is a fresh event
  // (replays would hit the idempotency path instead of the limiter).
  const body = JSON.stringify({
    event_id: `loadtest-${Date.now()}-${__VU}-${__ITER}`,
    purpose: 'load-test',
    model_name: 'k6-load-tester',
    request_type: 'data_access',
    content: 'ping', // also exercises the content scanner
  });

  const res = http.post(`${BASE_URL}/ingest-event`, body, {
    headers: { 'Content-Type': 'application/json', 'x-api-key': API_KEY },
    tags: { endpoint: 'ingest-event' },
  });

  if (res.status === 429) {
    limited.add(1);
    const ok = check(res, {
      '429 has Retry-After header': (r) => !!r.headers['Retry-After'],
      '429 body is rate_limited': (r) => {
        try {
          return JSON.parse(r.body).error === 'rate_limited';
        } catch {
          return false;
        }
      },
    });
    if (!ok) unexpected.add(1);
  } else if (res.status >= 200 && res.status < 300) {
    allowed.add(1);
    allowedLatency.add(res.timings.duration);
  } else {
    unexpected.add(1);
    console.error(`unexpected status ${res.status}: ${String(res.body).slice(0, 200)}`);
  }
}

export function handleSummary(data) {
  const okCount = data.metrics.allowed_requests.values.count;
  const limitedCount = data.metrics.rate_limited_requests.values.count;
  const badCount = data.metrics.unexpected_requests.values.count;
  const p95 = data.metrics.allowed_latency_ms.values['p(95)'];
  const pass = badCount === 0 && limitedCount > 0;
  return {
    stdout: [
      '',
      '===== AllowBase gateway load test =====',
      `target rate : ${TARGET_RPM} req/min (limiter trips at 600)`,
      `allowed     : ${okCount}`,
      `rate-limited: ${limitedCount} (429s — limiter engaged)`,
      `unexpected  : ${badCount} (want 0)`,
      `p95 latency (allowed requests): ${p95 !== undefined ? p95.toFixed(0) : '?'} ms`,
      pass
        ? 'RESULT: PASS — limiter holds, no unexpected failures.'
        : 'RESULT: INVESTIGATE — see counters above.',
      '',
    ].join('\n'),
  };
}
