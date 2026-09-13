import type {
  EventOrigin,
  FimRecord,
  Incident,
  InventoryHit,
  LlmStatus,
  LogEvent,
  LogTransport,
  NewsItem,
  PlatformStats,
  ResponseAction,
  IocRecord,
  ReportSummary
} from "../types";

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(path, {
    ...init,
    headers: {
      "Content-Type": "application/json",
      ...(init?.headers ?? {})
    }
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(text || res.statusText);
  }
  return (await res.json()) as T;
}

export const api = {
  health: () => request<{ ok: boolean; udpPort: number; llm: PlatformStats["llm"] }>("/api/health"),
  stats: () => request<PlatformStats>("/api/stats"),
  hunt: (opts: {
    q?: string;
    from?: string;
    to?: string;
    transport?: string;
    app?: string;
    limit?: number;
  }) => {
    const p = new URLSearchParams();
    p.set("limit", String(opts.limit ?? 500));
    if (opts.q) p.set("q", opts.q);
    if (opts.from) p.set("from", opts.from);
    if (opts.to) p.set("to", opts.to);
    if (opts.transport) p.set("transport", opts.transport);
    if (opts.app) p.set("app", opts.app);
    return request<LogEvent[]>(`/api/hunt?${p.toString()}`);
  },
  iocs: () => request<IocRecord[]>("/api/iocs"),
  addIoc: (body: { kind: string; value: string; note: string | null }) =>
    request<IocRecord[]>("/api/iocs", { method: "POST", body: JSON.stringify(body) }),
  deleteIoc: (id: number) => request<IocRecord[]>(`/api/iocs/${id}`, { method: "DELETE" }),
  customRules: () => request<unknown[]>("/api/rules"),
  saveCustomRules: (rules: unknown) =>
    request<unknown[]>("/api/rules", { method: "PUT", body: JSON.stringify(rules) }),
  reportSummary: (hours = 24) => request<ReportSummary>(`/api/reports/summary?hours=${hours}`),
  events: (q?: string, origin: EventOrigin = "live") =>
    request<LogEvent[]>(
      `/api/events?limit=250&origin=${origin}${q ? `&q=${encodeURIComponent(q)}` : ""}`
    ),
  incidents: (origin: EventOrigin = "live") =>
    request<Incident[]>(`/api/incidents?origin=${origin}`),
  news: () => request<NewsItem[]>("/api/news?limit=80"),
  newsByCves: (cves: string[]) =>
    request<NewsItem[]>(
      `/api/news?limit=40&cves=${encodeURIComponent(cves.join(","))}`
    ),
  sync: () => request<{ inserted: number; scanned: number }>("/api/sync", { method: "POST" }),
  inject: (count = 12, transport?: LogTransport) =>
    request<{ injected: number; origin: string; transport: string }>("/api/demo/inject", {
      method: "POST",
      body: JSON.stringify({ count, transport })
    }),
  demoStream: (enabled: boolean, transport?: LogTransport) =>
    request<{ streaming: Record<LogTransport, boolean> }>("/api/demo/stream", {
      method: "POST",
      body: JSON.stringify({ enabled, transport })
    }),
  demoStreamStatus: () =>
    request<{ streaming: Record<LogTransport, boolean> | boolean }>("/api/demo/stream"),
  summarize: (id: number) =>
    request<NewsItem>(`/api/summarize/${id}`, { method: "POST" }),
  triage: (id: number) =>
    request<Incident>(`/api/triage/${id}`, { method: "POST" }),
  llm: () => request<LlmStatus>("/api/llm"),
  setLlm: (id: string) =>
    request<LlmStatus>("/api/llm", {
      method: "POST",
      body: JSON.stringify({ id })
    }),
  downloadLlm: (id: string) =>
    request<LlmStatus>("/api/llm/download", {
      method: "POST",
      body: JSON.stringify({ id })
    }),
  saveLlmKeys: (
    keys: Partial<
      Record<
        | "openai"
        | "anthropic"
        | "google"
        | "xai"
        | "openaiModel"
        | "anthropicModel"
        | "googleModel"
        | "xaiModel",
        string
      >
    >
  ) =>
    request<LlmStatus>("/api/llm/keys", {
      method: "POST",
      body: JSON.stringify(keys)
    }),
  setIncidentStatus: (id: number, status: Incident["status"]) =>
    request<Incident>(`/api/incidents/${id}/status`, {
      method: "POST",
      body: JSON.stringify({ status })
    }),
  fim: (origin: EventOrigin = "live") => request<FimRecord[]>(`/api/fim?origin=${origin}`),
  inventoryHits: () => request<InventoryHit[]>("/api/inventory/hits"),
  scanInventory: () => request<{ items: number; hits: number }>("/api/inventory/scan", { method: "POST" }),
  responses: (origin: EventOrigin = "live") =>
    request<ResponseAction[]>(`/api/response?origin=${origin}`),
  confirmResponse: (id: number, confirm: boolean) =>
    request<ResponseAction>(`/api/response/${id}/confirm`, {
      method: "POST",
      body: JSON.stringify({ confirm })
    }),
  undoResponse: (id: number) =>
    request<ResponseAction>(`/api/response/${id}/undo`, { method: "POST" })
};
