export type Decision = 'ALLOW' | 'BLOCK' | 'MASK' | 'REDACT';
export type RiskLevel = 'Low' | 'Medium' | 'High';

export interface NavItem {
  label: string;
  href: string;
}

export interface Problem {
  title: string;
  description: string;
}

export interface HowStep {
  index: string;
  title: string;
  description: string;
  items: string[];
  example?: string;
}

export interface Metric {
  label: string;
  value: string;
  delta: string;
  tone: 'neutral' | 'good' | 'bad' | 'warn';
}

export interface TimePoint {
  label: string;
  requests: number;
  allowed: number;
  blocked: number;
}

export interface RiskSlice {
  name: string;
  value: number;
}

export interface ModelUsage {
  model: string;
  requests: number;
}

export interface SourceUsage {
  source: string;
  requests: number;
}

export interface RequestExample {
  id: string;
  user: string;
  ai: string;
  data: string;
  purpose: string;
  detected: string[];
  policy: string;
  decision: Decision;
  reason: string;
}

export interface PolicyCondition {
  field: string;
  operator: string;
  value: string;
}

export interface Policy {
  id: string;
  name: string;
  description: string;
  /** 'active' | 'paused' | 'archived' — a paused policy is skipped by the engine. */
  status: string;
  conditions: PolicyCondition[];
  action: string;
  effect: Decision;
  updated: string;
}

export interface Agent {
  id: string;
  name: string;
  owner: string;
  model: string;
  allowed: string[];
  denied: string[];
  risk: RiskLevel;
  status: 'Active' | 'Paused';
  requests: string;
}

export interface DataSource {
  id: string;
  name: string;
  category: string;
  records: string;
  sensitiveAssets: string;
  lastScan: string;
  risk: RiskLevel;
  /** Present for sources loaded from the backend. */
  sourceType?: string;
  /** True for a real connected PostgreSQL source (vs the landing-page mock). */
  isLive?: boolean;
  /** Number of discovered tables, for live PostgreSQL sources. */
  tableCount?: number | null;
}

export interface SecurityFeature {
  title: string;
  description: string;
}

export interface UseCase {
  title: string;
  description: string;
  points: string[];
}

export interface Faq {
  question: string;
  answer: string;
}

export interface PricingTier {
  name: string;
  price: string;
  description: string;
  features: string[];
  cta: string;
  featured?: boolean;
}

export interface SimulationStep {
  id: string;
  label: string;
  detail: string;
}
