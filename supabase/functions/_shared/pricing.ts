// List-price estimates (USD per 1M tokens) used for cost tracking.
// These are estimates for dashboards and budgeting, not invoices — providers
// change prices, apply discounts, and bill cached tokens differently.
// Matching is by longest model-name prefix, so dated snapshots
// (e.g. gpt-4o-mini-2024-07-18) resolve to their family.

export interface ModelPrice {
  input: number;
  output: number;
}

export const PRICE_TABLE: Record<string, Record<string, ModelPrice>> = {
  openai: {
    'gpt-4o-mini': { input: 0.15, output: 0.6 },
    'gpt-4o': { input: 2.5, output: 10 },
    'gpt-4.1-nano': { input: 0.1, output: 0.4 },
    'gpt-4.1-mini': { input: 0.4, output: 1.6 },
    'gpt-4.1': { input: 2, output: 8 },
    'gpt-4-turbo': { input: 10, output: 30 },
    'gpt-3.5-turbo': { input: 0.5, output: 1.5 },
    'o4-mini': { input: 1.1, output: 4.4 },
    'o3-mini': { input: 1.1, output: 4.4 },
    o3: { input: 2, output: 8 },
    'o1-mini': { input: 1.1, output: 4.4 },
    o1: { input: 15, output: 60 },
  },
  anthropic: {
    'claude-3-haiku': { input: 0.25, output: 1.25 },
    'claude-3-5-haiku': { input: 0.8, output: 4 },
    'claude-haiku-4': { input: 1, output: 5 },
    'claude-3-5-sonnet': { input: 3, output: 15 },
    'claude-3-7-sonnet': { input: 3, output: 15 },
    'claude-sonnet-4': { input: 3, output: 15 },
    'claude-3-opus': { input: 15, output: 75 },
    'claude-opus-4': { input: 15, output: 75 },
  },
  gemini: {
    'gemini-1.5-flash': { input: 0.075, output: 0.3 },
    'gemini-1.5-pro': { input: 1.25, output: 5 },
    'gemini-2.0-flash-lite': { input: 0.075, output: 0.3 },
    'gemini-2.0-flash': { input: 0.1, output: 0.4 },
    'gemini-2.5-flash-lite': { input: 0.1, output: 0.4 },
    'gemini-2.5-flash': { input: 0.3, output: 2.5 },
    'gemini-2.5-pro': { input: 1.25, output: 10 },
  },
};

export function lookupPrice(provider: string, model: string): ModelPrice | null {
  // Custom (OpenAI-compatible) endpoints often proxy OpenAI model names.
  const table = PRICE_TABLE[provider === 'custom' ? 'openai' : provider];
  if (!table) return null;
  const name = model.toLowerCase().replace(/^models\//, '');
  let best: string | null = null;
  for (const prefix of Object.keys(table)) {
    if (name.startsWith(prefix) && (best === null || prefix.length > best.length)) best = prefix;
  }
  return best ? table[best] : null;
}

/** Estimated cost in USD, rounded to 6 decimals; null when the model or usage is unknown. */
export function estimateCostUsd(
  provider: string,
  model: string,
  inputTokens: number | null,
  outputTokens: number | null,
): number | null {
  const price = lookupPrice(provider, model);
  if (!price || (inputTokens === null && outputTokens === null)) return null;
  const cost = ((inputTokens ?? 0) * price.input + (outputTokens ?? 0) * price.output) / 1_000_000;
  return Math.round(cost * 1_000_000) / 1_000_000;
}
