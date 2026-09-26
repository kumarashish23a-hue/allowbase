import type {
  Agent,
  DataSource,
  Faq,
  HowStep,
  Metric,
  ModelUsage,
  NavItem,
  Policy,
  PricingTier,
  Problem,
  RequestExample,
  RiskSlice,
  SecurityFeature,
  SimulationStep,
  SourceUsage,
  TimePoint,
  UseCase,
} from '../types';

export const navItems: NavItem[] = [
  { label: 'Product', href: '#platform' },
  { label: 'Solutions', href: '#solutions' },
  { label: 'How It Works', href: '#how' },
  { label: 'Developers', href: '#developers' },
  { label: 'Security', href: '#security' },
  { label: 'Pricing', href: '#pricing' },
];

export const aiStack = ['GPT', 'Claude', 'Gemini', 'Llama', 'Internal AI', 'AI Agents'];

export const dataSources = ['Database', 'GitHub', 'Slack', 'Google Drive', 'CRM', 'Cloud Storage'];

export const aiSystems = ['GPT', 'Claude', 'Gemini', 'Internal Models', 'AI Agents'];

export const problems: Problem[] = [
  {
    title: 'Data Sprawl',
    description: 'Data lives across hundreds of systems: databases, drives, chat tools, code repos, SaaS apps, and cloud buckets.',
  },
  {
    title: 'AI Access',
    description: 'Employees and agents can reach that data through many AI systems, often outside the visibility of security teams.',
  },
  {
    title: 'Sensitive Information',
    description: 'PII, financial records, credentials, source code, and confidential documents can be exposed in a single prompt.',
  },
  {
    title: 'No Clear Control Layer',
    description: 'Companies need to know who accessed what, why it happened, and whether it should have been allowed.',
  },
];

export const howSteps: HowStep[] = [
  {
    index: '01',
    title: 'Discover',
    description: 'Find where organizational data exists before AI touches it.',
    items: ['Databases', 'Documents', 'Cloud Storage', 'GitHub', 'SaaS applications'],
  },
  {
    index: '02',
    title: 'Understand',
    description: 'Automatically classify what the data contains.',
    items: ['PII', 'Financial', 'Credentials', 'Source Code', 'Confidential'],
  },
  {
    index: '03',
    title: 'Govern',
    description: 'Turn security intent into enforceable AI policy.',
    items: ['Data rules', 'Destination rules', 'Department scope', 'Risk thresholds'],
    example: '“Customer PII cannot be sent to external AI.”',
  },
  {
    index: '04',
    title: 'Control',
    description: 'Allow, block, redact, or restrict AI requests in real time.',
    items: ['Allow', 'Block', 'Redact', 'Step-up approval'],
  },
  {
    index: '05',
    title: 'Audit',
    description: 'Understand exactly what happened, every time.',
    items: ['Who', 'What', 'When', 'Which AI', 'Purpose', 'Decision'],
  },
];

export const metrics: Metric[] = [
  { label: 'AI Requests', value: '24,821', delta: '+12.4% this week', tone: 'neutral' },
  { label: 'Allowed', value: '23,914', delta: '96.3% allow rate', tone: 'good' },
  { label: 'Blocked', value: '907', delta: '3.7% blocked', tone: 'bad' },
  { label: 'Sensitive Events', value: '342', delta: '18 need review', tone: 'warn' },
  { label: 'Active AI Agents', value: '18', delta: '4 new this month', tone: 'neutral' },
  { label: 'High Risk', value: '27', delta: 'Down from 41', tone: 'warn' },
];

const dayLabels = ['00:00', '04:00', '08:00', '12:00', '16:00', '20:00', '24:00'];
const weekLabels = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];
const monthLabels = ['W1', 'W2', 'W3', 'W4'];

function buildSeries(labels: string[], base: number, variance: number): TimePoint[] {
  return labels.map((label, i) => {
    const wave = Math.sin(i / Math.max(labels.length - 1, 1) * Math.PI) * variance;
    const requests = Math.round(base + wave + (i % 3) * (variance / 6));
    const blocked = Math.round(requests * (0.028 + (i % 4) * 0.004));
    return { label, requests, blocked, allowed: requests - blocked };
  });
}

export const requestSeries: Record<'24h' | '7d' | '30d', TimePoint[]> = {
  '24h': buildSeries(dayLabels, 980, 260),
  '7d': buildSeries(weekLabels, 3450, 720),
  '30d': buildSeries(monthLabels, 23800, 3200),
};

export const riskDistribution: RiskSlice[] = [
  { name: 'Low', value: 78 },
  { name: 'Medium', value: 16 },
  { name: 'High', value: 6 },
];

export const modelUsage: ModelUsage[] = [
  { model: 'Claude', requests: 8420 },
  { model: 'GPT', requests: 7310 },
  { model: 'Internal Models', requests: 4180 },
  { model: 'Gemini', requests: 2860 },
  { model: 'AI Agents', requests: 2051 },
];

export const sourceUsage: SourceUsage[] = [
  { source: 'Customer Database', requests: 6120 },
  { source: 'Google Drive', requests: 4980 },
  { source: 'Slack', requests: 4210 },
  { source: 'GitHub', requests: 3560 },
  { source: 'CRM', requests: 2980 },
  { source: 'Cloud Storage', requests: 2971 },
];

export const requestExamples: RequestExample[] = [
  {
    id: 'req-blocked',
    user: 'Alex Kim',
    ai: 'Claude',
    data: 'Customer Database',
    purpose: 'Customer Analysis',
    detected: ['PII', 'Customer IDs', 'Email addresses', 'Phone numbers'],
    policy: 'Customer PII cannot be sent to external AI.',
    decision: 'BLOCK',
    reason: 'Customer PII cannot be sent to external AI systems.',
  },
  {
    id: 'req-allowed',
    user: 'Sarah Chen',
    ai: 'Internal Support Agent',
    data: 'Product Documentation',
    purpose: 'Customer Support',
    detected: ['No sensitive data detected'],
    policy: 'Internal documentation may be used by approved support agents.',
    decision: 'ALLOW',
    reason: 'No sensitive data detected. Destination is an approved internal agent.',
  },
];

export const policies: Policy[] = [
  {
    id: 'pol-pii',
    name: 'Customer PII',
    description: 'Prevent customer personal data from leaving approved boundaries.',
    conditions: [
      { field: 'Data', operator: '=', value: 'PII' },
      { field: 'Destination', operator: '=', value: 'External AI' },
    ],
    action: 'Block the request and notify the data owner.',
    effect: 'BLOCK',
    updated: '2 days ago',
  },
  {
    id: 'pol-eng',
    name: 'Engineering Data',
    description: 'Allow approved internal agents to work with source code safely.',
    conditions: [
      { field: 'Department', operator: '=', value: 'Engineering' },
      { field: 'AI', operator: '=', value: 'Approved Internal Agent' },
    ],
    action: 'Allow source-code access with full audit logging.',
    effect: 'ALLOW',
    updated: '5 days ago',
  },
  {
    id: 'pol-fin',
    name: 'Financial Data',
    description: 'Restrict financial records to the finance organization.',
    conditions: [
      { field: 'Data', operator: '=', value: 'Financial' },
      { field: 'Department', operator: '≠', value: 'Finance' },
    ],
    action: 'Block the request and create a sensitive event.',
    effect: 'BLOCK',
    updated: '1 week ago',
  },
];

export const agents: Agent[] = [
  {
    id: 'agent-support',
    name: 'Customer Support Agent',
    owner: 'Support Ops',
    model: 'Claude',
    allowed: ['Customer CRM', 'Support tickets', 'Product documentation'],
    denied: ['Employee records', 'Financial database'],
    risk: 'Low',
    status: 'Active',
    requests: '6,412 requests',
  },
  {
    id: 'agent-research',
    name: 'Internal Research Agent',
    owner: 'Data Science',
    model: 'Internal Models',
    allowed: ['Research docs', 'Anonymized datasets'],
    denied: ['Raw customer PII', 'Production credentials'],
    risk: 'Medium',
    status: 'Active',
    requests: '3,208 requests',
  },
  {
    id: 'agent-code',
    name: 'Code Agent',
    owner: 'Engineering',
    model: 'GPT',
    allowed: ['Engineering repos', 'CI logs'],
    denied: ['Customer database', 'Billing systems'],
    risk: 'Medium',
    status: 'Paused',
    requests: '1,904 requests',
  },
  {
    id: 'agent-finance',
    name: 'Finance Assistant',
    owner: 'Finance',
    model: 'Internal Models',
    allowed: ['Finance reports', 'Approved ledgers'],
    denied: ['HR records', 'External AI destinations'],
    risk: 'High',
    status: 'Active',
    requests: '986 requests',
  },
];

export const connectedSources: DataSource[] = [
  { id: 'src-drive', name: 'Google Drive', category: 'Documents', records: '184,220 files', sensitiveAssets: '2,418 sensitive', lastScan: '12 min ago', risk: 'Medium' },
  { id: 'src-github', name: 'GitHub', category: 'Code', records: '312 repositories', sensitiveAssets: '486 sensitive', lastScan: '34 min ago', risk: 'Medium' },
  { id: 'src-postgres', name: 'PostgreSQL', category: 'Database', records: '42 schemas', sensitiveAssets: '1,204 sensitive', lastScan: '8 min ago', risk: 'High' },
  { id: 'src-slack', name: 'Slack', category: 'Communication', records: '96 channels', sensitiveAssets: '312 sensitive', lastScan: '21 min ago', risk: 'Low' },
  { id: 'src-notion', name: 'Notion', category: 'Documents', records: '18,402 pages', sensitiveAssets: '198 sensitive', lastScan: '47 min ago', risk: 'Low' },
  { id: 'src-s3', name: 'AWS S3', category: 'Cloud Storage', records: '64 buckets', sensitiveAssets: '742 sensitive', lastScan: '1 hr ago', risk: 'High' },
  { id: 'src-crm', name: 'CRM', category: 'Business System', records: '128,940 records', sensitiveAssets: '3,120 sensitive', lastScan: '16 min ago', risk: 'High' },
];

export const securityFeatures: SecurityFeature[] = [
  { title: 'Data Discovery', description: 'Continuously map databases, warehouses, files, and SaaS — down to the column, from metadata alone.' },
  { title: 'Sensitive Data Detection', description: 'Deterministic classification of PII, financial records, credentials, and secrets. Low-confidence fields are flagged for human review — never guessed.' },
  { title: 'AI Access Control', description: 'Grant models and agents read access per dataset. Everything else is denied by default.' },
  { title: 'Policy Enforcement', description: 'Every request is evaluated against versioned policy before any data flows.' },
  { title: 'Data Redaction', description: 'Mask or drop sensitive fields before they ever reach the model.' },
  { title: 'AI Agent Permissions', description: 'Scope each agent to explicit datasets and actions. Least privilege, enforced.' },
  { title: 'Audit Logs', description: 'An append-only record of who accessed what, when, why — and the decision made.' },
  { title: 'Risk Detection', description: 'Early signals on anomalous access patterns and risky agent behavior.' },
  { title: 'Data Provenance', description: 'Trace sensitive fields from the source system to the AI destination.' },
];

export const useCases: UseCase[] = [
  {
    title: 'Enterprise AI',
    description: 'Control internal AI usage across teams and tools.',
    points: ['Central visibility', 'Consistent policy', 'Faster safe adoption'],
  },
  {
    title: 'AI Agents',
    description: 'Control what autonomous agents can access and do.',
    points: ['Explicit permissions', 'Action boundaries', 'Continuous monitoring'],
  },
  {
    title: 'Data Security',
    description: 'Detect sensitive data exposure before it becomes an incident.',
    points: ['Classification', 'Real-time detection', 'Redaction'],
  },
  {
    title: 'Developer Platforms',
    description: 'Add policy enforcement to AI applications with one API.',
    points: ['Simple integration', 'Deterministic decisions', 'Audit-ready logs'],
  },
  {
    title: 'Regulated Organizations',
    description: 'Monitor sensitive-data access and maintain audit trails.',
    points: ['Evidence on demand', 'Purpose tracking', 'Decision explanations'],
  },
];

export const faqs: Faq[] = [
  {
    question: 'Is this a real security enforcement product?',
    answer: 'No. This is a frontend-only prototype. It simulates discovery, policy checks, monitoring, and audit logs with mock data.',
  },
  {
    question: 'Does it connect to my real Google Drive, Slack, or GitHub?',
    answer: 'No. All connections shown here are mock connections for demonstration. No OAuth, credentials, or production integrations are implemented.',
  },
  {
    question: 'Can it actually block an AI model?',
    answer: 'Not in this prototype. Allow and block decisions are simulated so teams can evaluate the product concept and UX.',
  },
  {
    question: 'What does the demo AI request simulator do?',
    answer: 'It walks through a realistic evaluation flow—identifying the user, inspecting data, detecting sensitive information, checking policy, and returning a mock decision.',
  },
  {
    question: 'Is any data sent anywhere?',
    answer: 'No. Everything runs locally in your browser with static mock data. There is no backend, analytics, or external API in this prototype.',
  },
];

export const pricingTiers: PricingTier[] = [
  {
    name: 'Starter',
    price: '$0',
    description: 'For teams evaluating AI data controls.',
    features: ['Up to 3 mock data sources', '10 demo policies', 'Basic audit simulation', 'Community support'],
    cta: 'Start prototype tour',
  },
  {
    name: 'Team',
    price: '$499',
    description: 'For companies piloting AI governance.',
    features: ['Unlimited mock sources', 'Advanced policy simulation', 'Agent permission modeling', 'Priority support'],
    cta: 'Request demo',
    featured: true,
  },
  {
    name: 'Enterprise',
    price: 'Custom',
    description: 'For regulated and global organizations.',
    features: ['Custom data classification', 'Audit exports', 'SSO and SCIM concepts', 'Dedicated success manager'],
    cta: 'Contact sales',
  },
];

export const simulationSteps: SimulationStep[] = [
  { id: 'identify', label: 'Identifying user', detail: 'Resolving identity, department, and role context.' },
  { id: 'inspect', label: 'Inspecting data', detail: 'Locating the requested dataset and its classification.' },
  { id: 'detect', label: 'Detecting sensitive information', detail: 'Scanning for PII, financial data, credentials, and secrets.' },
  { id: 'policy', label: 'Checking policy', detail: 'Matching request context against enforceable AI policies.' },
  { id: 'destination', label: 'Evaluating destination', detail: 'Checking whether the AI system is internal or external.' },
];

export const developerRequest = `POST /functions/v1/ingest-event
x-api-key: dcp_live_...

{
  "event_id": "evt_9f32c1",
  "model_name": "support-copilot",
  "purpose": "customer-support",
  "data_asset_ids": ["<asset-uuid>"],
  "agent_name": "triage-bot"
}`;

export const developerResponse = `{
  "request_id": "88d025e7-a65e-4598-a84c-96d2c7893619",
  "decision": "allow",
  "risk": "low",
  "reasons": [],
  "policies_triggered": [],
  "checks": {
    "identity": true,
    "permission": true,
    "data_classification": true,
    "ai_destination": true,
    "purpose": true
  },
  "event_id": "evt_9f32c1",
  "idempotent_replay": false
}`;
