export type SeverityLabel = "critical" | "high" | "medium" | "low" | "info";
export type EventOrigin = "live" | "demo";
export const SYSLOG_TRANSPORTS = ["udp", "tcp", "tls", "relp"] as const;
export const LOG_TRANSPORTS = ["udp", "tcp", "tls", "relp", "host"] as const;
export type SyslogTransport = (typeof SYSLOG_TRANSPORTS)[number];
export type LogTransport = (typeof LOG_TRANSPORTS)[number];

export function isLogTransport(value: unknown): value is LogTransport {
  return (
    value === "udp" ||
    value === "tcp" ||
    value === "tls" ||
    value === "relp" ||
    value === "host"
  );
}

export interface LogEvent {
  id: number;
  receivedAt: string;
  eventTime: string;
  facility: number | null;
  severity: number | null;
  severityLabel: SeverityLabel;
  hostname: string | null;
  appName: string | null;
  procId: string | null;
  message: string;
  raw: string;
  sourceIp: string | null;
  srcIp: string | null;
  userName: string | null;
  category: string | null;
  action: string | null;
  parsed: Record<string, unknown>;
  hash: string;
  origin: EventOrigin;
  transport: LogTransport;
}

export interface Incident {
  id: number;
  createdAt: string;
  title: string;
  ruleName: string;
  severity: SeverityLabel;
  status: "open" | "ack" | "closed";
  eventIds: number[];
  evidence: string;
  aiSummary: string | null;
  containmentCommands: string | null;
  riskScore: number;
  origin: EventOrigin;
  mitre: Array<{ id: string; tactic: string; technique: string }>;
  occurrenceCount?: number;
  assignee?: string | null;
  closeReason?: string | null;
}

export interface CaseNote {
  id: number;
  incidentId: number;
  createdAt: string;
  author: string;
  body: string;
}

export interface IocRecord {
  id: number;
  kind: string;
  value: string;
  note: string | null;
  createdAt: string;
  expiresAt?: string | null;
}

export interface HuntQuery {
  q?: string;
  from?: string;
  to?: string;
  transport?: string;
  app?: string;
  user?: string;
  srcIp?: string;
  category?: string;
  origin?: EventOrigin;
  limit?: number;
}

export interface SourceLink {
  label: string;
  url: string;
}

export interface NewsItem {
  id: number;
  source: "xml" | "kev";
  title: string;
  url: string | null;
  publishedAt: string | null;
  summary: string | null;
  cveIds: string[];
  vendor: string | null;
  product: string | null;
  content: string | null;
  hash: string;
  aiSummary: string | null;
  fetchedAt: string;
  severity: SeverityLabel;
  sourceLinks: SourceLink[];
}

export interface AiReport {
  id: number;
  createdAt: string;
  kind: "news" | "incident" | "event";
  targetId: number;
  markdown: string;
}

export type LlmMode = "local" | "cloud";
export type LlmProvider = "local" | "openai" | "anthropic" | "google" | "xai";
export type LlmRuntime = "gguf" | "mlx";

export interface LlmOption {
  id: string;
  mode: LlmMode;
  provider: LlmProvider;
  label: string;
  model: string;
  hfRepo?: string;
  hfFile?: string;
  hfUri?: string;
  family?: string;
  runtime?: LlmRuntime;
  cached?: boolean;
}

export interface LlmProviderStatus {
  configured: boolean;
  hint: string | null;
}

export interface LlmStatus {
  state: "idle" | "downloading" | "compiling" | "loading" | "ready" | "error";
  gpu: string | null;
  gpuLayers: number | string | null;
  model: string;
  message: string;
  metal: boolean;
  mode: LlmMode;
  selectedId: string;
  options: LlmOption[];
  cloudConfigured: boolean;
  providers: Record<"openai" | "anthropic" | "google" | "xai", LlmProviderStatus>;
  downloadingId?: string | null;
  downloadPercent?: number | null;
}

export interface FimRecord {
  id: number;
  path: string;
  hash: string;
  status: "ok" | "changed" | "new";
  previousHash: string | null;
  updatedAt: string;
  origin: EventOrigin;
  size?: number | null;
  mode?: string | null;
  mtime?: string | null;
}

export interface InventoryItem {
  id: number;
  name: string;
  version: string | null;
  path: string | null;
  collectedAt: string;
}

export interface InventoryHit {
  id: number;
  inventoryId: number;
  name: string;
  cve: string;
  title: string;
  collectedAt: string;
  confidence?: "high" | "medium";
  installedVersion?: string | null;
}

export interface AuditRecord {
  id: number;
  createdAt: string;
  actor: string;
  action: string;
  detail: string | null;
}

export interface ResponseAction {
  id: number;
  createdAt: string;
  incidentId: number | null;
  action: "block_ip" | "kill_pid" | "quarantine";
  target: string;
  command: string;
  status: "pending" | "executed" | "failed" | "denied" | "undone";
  output: string | null;
  origin: EventOrigin;
}

export interface PlatformStats {
  events: number;
  incidents: number;
  news: number;
  udpPort: number | null;
  tcpPort: number | null;
  tlsPort: number | null;
  relpPort: number | null;
  llm: LlmStatus;
  eps: number;
  fimChanges?: number;
  inventoryHits?: number;
  pendingResponses?: number;
}

export type WsMessage =
  | { type: "hello"; payload: { stats: PlatformStats } }
  | { type: "event"; payload: LogEvent }
  | { type: "incident"; payload: Incident }
  | { type: "news"; payload: NewsItem }
  | { type: "ai_report"; payload: AiReport }
  | { type: "llm_status"; payload: LlmStatus }
  | { type: "stats"; payload: PlatformStats }
  | { type: "fim"; payload: FimRecord }
  | { type: "inventory_hit"; payload: InventoryHit }
  | { type: "response"; payload: ResponseAction };
