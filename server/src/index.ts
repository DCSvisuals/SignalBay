import "dotenv/config";
import http from "node:http";
import express from "express";
import { WebSocketServer } from "ws";
import { ThreatAggregator } from "./aggregator.js";
import { backupDatabase, latestBackupAgeMs } from "./backup.js";
import { hub } from "./bus.js";
import { UdpCollector } from "./collector.js";
import { loadCustomRules, saveCustomRules, type CustomRule } from "./customRules.js";
import { SiemDatabase } from "./database.js";
import { randomSyslog, startDemoStream } from "./demo.js";
import { startFimWatch } from "./fim.js";
import { detectDashboardUrl, renderHealthPage, wantsHealthHtml } from "./healthPage.js";
import { computerName } from "./host.js";
import { startInventoryLoop } from "./inventory.js";
import { invalidateIocCache, validateIoc } from "./iocs.js";
import { LlmEngine } from "./llm.js";
import { saveKeys } from "./llmKeys.js";
import { isLoopback } from "./netguard.js";
import { DB_PATH } from "./paths.js";
import { executeResponse, pfTableStatus, undoResponse } from "./response.js";
import { BUILTIN_DETECTIONS } from "./rules.js";
import { startMacSensor } from "./sensor.js";
import { ensureLanToken, getSettings, saveSettings } from "./settings.js";
import { peerIp } from "./syslogNet.js";
import type { EventOrigin, InventoryHit, LogTransport, PlatformStats } from "./types.js";
import { isLogTransport, LOG_TRANSPORTS, SYSLOG_TRANSPORTS } from "./types.js";

const HTTP_PORT = Number(process.env.PORT || 3001);
const HTTP_BIND = process.env.SIEM_BIND === "0.0.0.0" ? "0.0.0.0" : "127.0.0.1";
const UDP_PREFERRED = Number(process.env.UDP_PORT || 514);
const UDP_FALLBACK = Number(process.env.UDP_FALLBACK_PORT || 1514);
const TCP_PREFERRED = Number(process.env.TCP_PORT || 601);
const TCP_FALLBACK = Number(process.env.TCP_FALLBACK_PORT || 1601);
const TLS_PREFERRED = Number(process.env.TLS_PORT || 6514);
const TLS_FALLBACK = Number(process.env.TLS_FALLBACK_PORT || 16514);
const RELP_PREFERRED = Number(process.env.RELP_PORT || 2514);
const RELP_FALLBACK = Number(process.env.RELP_FALLBACK_PORT || 12514);
const AGG_INTERVAL = Number(process.env.AGGREGATOR_INTERVAL_MS || 900_000);
const demoStops: Record<LogTransport, () => void> = {
  udp: () => undefined,
  tcp: () => undefined,
  tls: () => undefined,
  relp: () => undefined,
  host: () => undefined
};
const demoStreaming: Record<LogTransport, boolean> = {
  udp: false,
  tcp: false,
  tls: false,
  relp: false,
  host: false
};

function highConfidenceCves(hits: InventoryHit[]): string[] {
  return hits.filter((hit) => hit.confidence === "high").map((hit) => hit.cve);
}

function stopDemo(transport?: LogTransport): void {
  const keys = transport ? [transport] : LOG_TRANSPORTS;
  for (const key of keys) {
    demoStops[key]();
    demoStops[key] = () => undefined;
    demoStreaming[key] = false;
  }
}

const db = new SiemDatabase();
const llm = new LlmEngine();

function audit(actor: string, action: string, detail: string): void {
  void db.insertAudit(actor, action, detail).catch((err) => console.warn("[audit]", err));
}
const collector = new UdpCollector(db);
const aggregator = new ThreatAggregator(db, llm, (cves) => collector.refreshKev(cves));

let eventWindow = 0;
const eventTimes: number[] = [];

hub.on("event", () => {
  const now = Date.now();
  eventTimes.push(now);
  while (eventTimes.length && now - eventTimes[0] > 10_000) eventTimes.shift();
  eventWindow = eventTimes.length / 10;
});

async function snapshot(): Promise<PlatformStats> {
  const counts = await db.counts();
  return {
    ...counts,
    udpPort: collector.ports.udp,
    tcpPort: collector.ports.tcp,
    tlsPort: collector.ports.tls,
    relpPort: collector.ports.relp,
    llm: llm.listedStatus(),
    eps: Number(eventWindow.toFixed(2)),
    fimChanges: counts.fimChanges,
    inventoryHits: counts.inventoryHits,
    pendingResponses: counts.pendingResponses
  };
}

async function main(): Promise<void> {
  await db.init();
  console.log(`[database] sqlite ready at ${DB_PATH}`);
  const closedNoise = await db.closeNoiseIncidents();
  if (closedNoise > 0) {
    console.log(`[siem] closed ${closedNoise} OCSP/trustd false-positive incidents`);
  }

  const udpPort = await collector.start(UDP_PREFERRED, UDP_FALLBACK);
  const tcpPort = await collector.startTcp(TCP_PREFERRED, TCP_FALLBACK);
  const tlsPort = await collector.startTls(TLS_PREFERRED, TLS_FALLBACK);
  const relpPort = await collector.startRelp(RELP_PREFERRED, RELP_FALLBACK);

  const app = express();
  app.use(express.json({ limit: "1mb" }));
  app.use((req, res, next) => {
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type, X-SIEM-Token");
    res.setHeader("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS");
    if (HTTP_BIND !== "0.0.0.0") return next();
    if (isLoopback(peerIp(req.socket.remoteAddress))) return next();
    const token = req.header("x-siem-token") || "";
    if (token && token === getSettings().lanToken) return next();
    res.status(401).json({ error: "LAN token required" });
  });
  app.options("*", (_req, res) => res.sendStatus(204));

  app.get("/api/health", async (req, res) => {
    const dashboardUrl = await detectDashboardUrl();
    const payload = {
      ok: true,
      platform: "Signalbay",
      arch: process.arch,
      udpPort,
      tcpPort,
      tlsPort,
      relpPort,
      db: DB_PATH,
      llm: llm.listedStatus(),
      clients: hub.size,
      dashboardUrl,
      tlsClientAuth: Boolean(process.env.TLS_CLIENT_CA)
    };
    if (wantsHealthHtml(req)) {
      const counts = await db.counts();
      res.type("html").send(
        renderHealthPage({
          ...payload,
          ...counts,
          eps: Number(eventWindow.toFixed(2))
        })
      );
      return;
    }
    res.json(payload);
  });

  app.get("/api/stats", async (_req, res) => {
    res.json(await snapshot());
  });

  app.get("/api/llm", (_req, res) => {
    res.json(llm.listedStatus());
  });

  app.post("/api/llm", async (req, res) => {
    const id = typeof req.body?.id === "string" ? req.body.id : "local-qwen";
    const status = await llm.select(id);
    res.json(status);
  });

  app.post("/api/llm/import", async (req, res) => {
    const source = typeof req.body?.source === "string" ? req.body.source : "";
    try {
      res.json(await llm.importLocal(source));
    } catch (err) {
      const message = err instanceof Error ? err.message : "Could not add that model";
      res.status(400).json({ error: message });
    }
  });

  app.post("/api/llm/download", async (req, res) => {
    const id = typeof req.body?.id === "string" ? req.body.id : "";
    const status = await llm.prefetch(id);
    res.json(status);
  });

  app.post("/api/llm/keys", async (req, res) => {
    const body = (req.body ?? {}) as Record<string, unknown>;
    const patch: Record<string, string> = {};
    for (const field of [
      "openai",
      "anthropic",
      "google",
      "xai",
      "openaiModel",
      "anthropicModel",
      "googleModel",
      "xaiModel"
    ]) {
      if (typeof body[field] === "string") patch[field] = body[field];
    }
    saveKeys(patch);
    const status = await llm.refreshAfterKeys();
    res.json(status);
  });

  app.get("/api/events", async (req, res) => {
    const limit = Number(req.query.limit || 200);
    const q = typeof req.query.q === "string" ? req.query.q : undefined;
    const before = typeof req.query.before === "string" ? req.query.before : undefined;
    const origin = req.query.origin === "demo" ? "demo" : "live";
    res.json(await db.listEvents({ limit, q, before, origin }));
  });

  app.get("/api/hunt", async (req, res) => {
    const origin = req.query.origin === "demo" ? "demo" : "live";
    res.json(
      await db.listEvents({
        limit: Number(req.query.limit || 500),
        q: typeof req.query.q === "string" ? req.query.q : undefined,
        from: typeof req.query.from === "string" ? req.query.from : undefined,
        to: typeof req.query.to === "string" ? req.query.to : undefined,
        transport: typeof req.query.transport === "string" ? req.query.transport : undefined,
        app: typeof req.query.app === "string" ? req.query.app : undefined,
        user: typeof req.query.user === "string" ? req.query.user : undefined,
        srcIp: typeof req.query.src === "string" ? req.query.src : undefined,
        category: typeof req.query.category === "string" ? req.query.category : undefined,
        origin
      })
    );
  });

  app.post("/api/ingest", async (req, res) => {
    const message = typeof req.body?.message === "string" ? req.body.message : "";
    if (!message.trim()) return res.status(400).json({ error: "message required" });
    const host = typeof req.body?.hostname === "string" ? req.body.hostname : computerName();
    const app = typeof req.body?.appName === "string" ? req.body.appName : "json-ingest";
    const transport = isLogTransport(req.body?.transport) ? req.body.transport : "host";
    const raw = `<14>1 ${new Date().toISOString()} ${host} ${app} - - - ${message.trim()}`;
    const event = await collector.ingestLive(raw, transport === "udp" || transport === "tcp" || transport === "tls" || transport === "relp" || transport === "host" ? transport : "host", "127.0.0.1");
    await db.insertAudit("api", "ingest", message.slice(0, 200));
    res.json({ ok: Boolean(event), event });
  });

  app.get("/api/iocs", async (_req, res) => {
    res.json(await db.listIocs());
  });

  app.post("/api/iocs", async (req, res) => {
    const value = typeof req.body?.value === "string" ? req.body.value.trim() : "";
    if (!value) return res.status(400).json({ error: "value required" });
    const kind = typeof req.body?.kind === "string" ? req.body.kind : "ip";
    const note = typeof req.body?.note === "string" ? req.body.note : null;
    const problem = validateIoc(kind, value);
    if (problem) return res.status(400).json({ error: problem });
    const days = Number(req.body?.expiresInDays);
    const expiresAt = Number.isFinite(days) && days > 0 ? new Date(Date.now() + days * 86_400_000).toISOString() : null;
    await db.upsertIoc(kind, value, note, expiresAt);
    invalidateIocCache();
    audit("operator", "ioc-add", `${kind} ${value}`);
    res.json(await db.listIocs());
  });

  app.delete("/api/iocs/:id", async (req, res) => {
    await db.deleteIoc(Number(req.params.id));
    invalidateIocCache();
    audit("operator", "ioc-delete", String(req.params.id));
    res.json(await db.listIocs());
  });

  app.get("/api/rules", (_req, res) => {
    res.json(loadCustomRules());
  });

  app.put("/api/rules", (req, res) => {
    try {
      const rules = Array.isArray(req.body) ? (req.body as CustomRule[]) : [];
      const saved = saveCustomRules(rules);
      audit("operator", "rules-save", `${saved.length} rules`);
      res.json(saved);
    } catch (err) {
      res.status(400).json({ error: err instanceof Error ? err.message : "invalid rules" });
    }
  });

  app.get("/api/detections", (_req, res) => {
    const disabled = new Set(getSettings().disabledRules);
    res.json(BUILTIN_DETECTIONS.map((rule) => ({ ...rule, enabled: !disabled.has(rule.id) })));
  });

  app.put("/api/detections/:id", (req, res) => {
    const id = req.params.id;
    if (!BUILTIN_DETECTIONS.some((rule) => rule.id === id)) {
      return res.status(404).json({ error: "unknown detection" });
    }
    const enabled = req.body?.enabled !== false;
    const disabled = new Set(getSettings().disabledRules);
    if (enabled) disabled.delete(id);
    else disabled.add(id);
    saveSettings({ disabledRules: [...disabled] });
    audit("operator", "detection", `${id} ${enabled ? "enabled" : "disabled"}`);
    res.json({ id, enabled });
  });

  app.get("/api/exceptions", (_req, res) => {
    res.json(getSettings().exceptions);
  });

  app.put("/api/exceptions", (req, res) => {
    try {
      const saved = saveSettings({ exceptions: Array.isArray(req.body) ? req.body : [] });
      audit("operator", "exceptions", `${saved.exceptions.length} rules`);
      res.json(saved.exceptions);
    } catch (err) {
      res.status(400).json({ error: err instanceof Error ? err.message : "invalid exceptions" });
    }
  });

  app.get("/api/settings", (_req, res) => {
    const settings = getSettings();
    res.json({
      retentionDays: settings.retentionDays,
      maxEvents: settings.maxEvents,
      webhookUrl: settings.webhookUrl,
      tlsClientAuth: Boolean(process.env.TLS_CLIENT_CA)
    });
  });

  app.put("/api/settings", (req, res) => {
    try {
      const saved = saveSettings({
        retentionDays: req.body?.retentionDays,
        maxEvents: req.body?.maxEvents,
        webhookUrl: typeof req.body?.webhookUrl === "string" ? req.body.webhookUrl : undefined
      });
      audit("operator", "settings", `retention ${saved.retentionDays}d`);
      res.json({
        retentionDays: saved.retentionDays,
        maxEvents: saved.maxEvents,
        webhookUrl: saved.webhookUrl
      });
    } catch (err) {
      res.status(400).json({ error: err instanceof Error ? err.message : "invalid settings" });
    }
  });

  app.post("/api/backup", async (_req, res) => {
    const file = await backupDatabase(db);
    audit("operator", "backup", file);
    res.json({ ok: true, file });
  });

  app.get("/api/audit", async (req, res) => {
    res.json(await db.listAudit(Number(req.query.limit || 40)));
  });

  app.get("/api/entity", async (req, res) => {
    const kind = req.query.kind === "user" || req.query.kind === "ip" ? req.query.kind : "host";
    const value = typeof req.query.value === "string" ? req.query.value.trim() : "";
    if (!value) return res.status(400).json({ error: "value required" });
    const origin = req.query.origin === "demo" ? "demo" : "live";
    res.json(await db.entityView(kind, value, origin));
  });

  app.get("/api/reports/series", async (req, res) => {
    res.json(await db.reportSeries(Number(req.query.hours || 24)));
  });

  app.get("/api/reports/summary", async (req, res) => {
    const hours = Number(req.query.hours || 24);
    const settings = getSettings();
    const summary = await db.reportSummary(hours, settings.retentionDays);
    res.json({
      ...summary,
      capabilities: {
        logCollection: true,
        dashboard: true,
        correlation: true,
        threatIntel: true,
        uebaLite: true,
        soarConfirm: true,
        riskScoring: true,
        complianceExport: true,
        rbacOptional: false,
        retention: true,
        jsonIngest: true,
        customRules: true,
        enrichment: true,
        historicalHunt: true,
        localLlm: llm.status.state === "ready" || llm.status.cloudConfigured,
        cases: true,
        webhook: Boolean(settings.webhookUrl),
        fimWatch: true,
        versionedKev: true
      }
    });
  });

  app.get("/api/compliance", async (_req, res) => {
    const summary = await db.reportSummary(24);
    const html = `<!DOCTYPE html><html><head><meta charset="utf-8"><title>Signalbay compliance snapshot</title>
      <style>body{font-family:sans-serif;background:#111;color:#ddd;padding:24px} table{border-collapse:collapse} td,th{border:1px solid #444;padding:6px 10px}</style></head>
      <body><h1>Signalbay lab compliance snapshot</h1>
      <p>Not a PCI/HIPAA certification. Evidence pack for a home-lab control set (ISO 27001-inspired logging).</p>
      <table>
      <tr><th>Control</th><th>Status</th></tr>
      <tr><td>A.12.4 Logging</td><td>Events retained ${summary.retentionDays} days · ${summary.events} in last 24h</td></tr>
      <tr><td>A.16 Incident management</td><td>${summary.openIncidents} open · ${summary.highOpen} high/crit</td></tr>
      <tr><td>A.12.2 Malware / KEV</td><td>CISA KEV + inventory matching enabled</td></tr>
      <tr><td>A.9 Access</td><td>Localhost trust. LAN bind requires the X-SIEM-Token header. No role system.</td></tr>
      </table>
      <p>Generated ${summary.generatedAt}</p></body></html>`;
    if (String(_req.headers.accept || "").startsWith("text/html")) {
      res.type("html").send(html);
      return;
    }
    res.json(summary);
  });

  app.get("/api/incidents", async (req, res) => {
    const status = typeof req.query.status === "string" ? req.query.status : undefined;
    const origin = req.query.origin === "demo" ? "demo" : "live";
    res.json(await db.listIncidents({ status, origin }));
  });

  app.get("/api/incidents/:id", async (req, res) => {
    const item = await db.getIncident(Number(req.params.id));
    if (!item) return res.status(404).json({ error: "not found" });
    res.json(item);
  });

  app.get("/api/news", async (req, res) => {
    const cves =
      typeof req.query.cves === "string"
        ? req.query.cves.split(",").map((cve) => cve.trim()).filter(Boolean)
        : [];
    const limit = Number(req.query.limit || 80);
    if (cves.length) {
      res.json(await db.listNewsByCves(cves, Math.min(limit, 60)));
      return;
    }
    res.json(await db.listNews(limit));
  });

  app.get("/api/news/:id", async (req, res) => {
    const item = await db.getNews(Number(req.params.id));
    if (!item) return res.status(404).json({ error: "not found" });
    res.json(item);
  });

  app.post("/api/sync", async (_req, res) => {
    const result = await aggregator.sync("manual");
    res.json(result);
  });

  app.post("/api/demo/inject", async (req, res) => {
    const count = Math.min(Number(req.body?.count || 12), 80);
    const requested = req.body?.transport;
    const transport = isLogTransport(requested) ? requested : undefined;
    const messages: string[] = [];
    for (let i = 0; i < count; i += 1) {
      const msg = typeof req.body?.message === "string" ? req.body.message : randomSyslog();
      const lane = transport ?? SYSLOG_TRANSPORTS[i % SYSLOG_TRANSPORTS.length];
      await collector.ingestSynthetic(msg, lane);
      messages.push(msg);
    }
    res.json({
      injected: count,
      origin: "demo",
      transport: transport ?? "all",
      sample: messages.slice(0, 3)
    });
  });

  app.post("/api/demo/stream", (req, res) => {
    const enabled = Boolean(req.body?.enabled);
    const requested = req.body?.transport;
    const transport = isLogTransport(requested) ? requested : undefined;
    stopDemo(transport);
    if (enabled) {
      const lanes = transport ? [transport] : [...SYSLOG_TRANSPORTS];
      for (const lane of lanes) {
        demoStops[lane] = startDemoStream((msg) => collector.ingestSynthetic(msg, lane));
        demoStreaming[lane] = true;
      }
    }
    res.json({ streaming: { ...demoStreaming } });
  });

  app.get("/api/demo/stream", (_req, res) => {
    res.json({ streaming: { ...demoStreaming } });
  });

  app.post("/api/summarize/:id", async (req, res) => {
    const item = await db.getNews(Number(req.params.id));
    if (!item) return res.status(404).json({ error: "not found" });
    const updated = await aggregator.summarize(item);
    res.json(updated ?? item);
  });

  app.post("/api/incidents/:id/status", async (req, res) => {
    const status = req.body?.status;
    if (status !== "open" && status !== "ack" && status !== "closed") {
      res.status(400).json({ error: "status must be open, ack, or closed" });
      return;
    }
    const assignee = typeof req.body?.assignee === "string" ? req.body.assignee.slice(0, 80) : undefined;
    const closeReason = typeof req.body?.closeReason === "string" ? req.body.closeReason.slice(0, 500) : undefined;
    const updated = await db.updateIncidentCase(Number(req.params.id), { status, assignee, closeReason });
    if (!updated) return res.status(404).json({ error: "not found" });
    audit("operator", "case-status", `${updated.id} ${status}`);
    hub.broadcast({ type: "incident", payload: updated });
    res.json(updated);
  });

  app.get("/api/incidents/:id/notes", async (req, res) => {
    res.json(await db.listCaseNotes(Number(req.params.id)));
  });

  app.post("/api/incidents/:id/notes", async (req, res) => {
    const body = typeof req.body?.body === "string" ? req.body.body.trim() : "";
    if (!body) return res.status(400).json({ error: "note required" });
    const incident = await db.getIncident(Number(req.params.id));
    if (!incident) return res.status(404).json({ error: "not found" });
    const note = await db.addCaseNote(incident.id, "operator", body.slice(0, 2000));
    audit("operator", "case-note", `${incident.id}`);
    res.json(note);
  });

  app.get("/api/fim", async (req, res) => {
    const origin: EventOrigin = req.query.origin === "demo" ? "demo" : "live";
    res.json(await db.listFim(origin, true));
  });

  app.get("/api/inventory/hits", async (_req, res) => {
    res.json(await db.listInventoryHits());
  });

  app.post("/api/inventory/scan", async (_req, res) => {
    const { collectInventory } = await import("./inventory.js");
    const result = await collectInventory(db);
    collector.refreshInventoryCves(highConfidenceCves(result.hits));
    for (const hit of result.hits) hub.broadcast({ type: "inventory_hit", payload: hit });
    res.json({ items: result.items.length, hits: result.hits.length });
  });

  app.get("/api/response/pf", async (_req, res) => {
    res.json(await pfTableStatus());
  });

  app.get("/api/response", async (req, res) => {
    const origin: EventOrigin = req.query.origin === "demo" ? "demo" : "live";
    res.json(await db.listResponses(origin));
  });

  app.post("/api/response/:id/confirm", async (req, res) => {
    const item = await db.getResponse(Number(req.params.id));
    if (!item) return res.status(404).json({ error: "not found" });
    if (item.status !== "pending") return res.status(409).json({ error: "already decided" });
    if (req.body?.confirm !== true) {
      const denied = await db.updateResponse(item.id, "denied", "Operator denied");
      audit("operator", "response-deny", `${item.action} ${item.target}`);
      if (denied) hub.broadcast({ type: "response", payload: denied });
      res.json(denied);
      return;
    }
    const result = await executeResponse(item);
    audit("operator", "response-confirm", `${item.action} ${item.target} ${result.status}`);
    const updated = await db.updateResponse(item.id, result.status, result.output);
    if (updated) hub.broadcast({ type: "response", payload: updated });
    res.json(updated);
  });

  app.post("/api/response/:id/undo", async (req, res) => {
    const item = await db.getResponse(Number(req.params.id));
    if (!item) return res.status(404).json({ error: "not found" });
    if (item.status !== "executed") return res.status(409).json({ error: "only executed actions can be undone" });
    const result = await undoResponse(item);
    audit("operator", "response-undo", `${item.action} ${item.target} ${result.status}`);
    const updated = await db.updateResponse(item.id, result.status, result.output);
    if (updated) hub.broadcast({ type: "response", payload: updated });
    res.json(updated);
  });

  app.post("/api/triage/:id", async (req, res) => {
    const incident = await db.getIncident(Number(req.params.id));
    if (!incident) return res.status(404).json({ error: "not found" });
    const snippets: string[] = [];
    for (const eventId of incident.eventIds.slice(0, 8)) {
      const event = await db.getEvent(eventId);
      if (event) snippets.push(`[${event.receivedAt}] ${event.appName ?? "-"} ${event.message}`);
    }
    const markdown = await llm.triageIncident(incident, snippets);
    if (!markdown) {
      return res.status(503).json({ error: "llm not ready", status: llm.status });
    }
    const commands = extractCommands(markdown);
    const updated = await db.updateIncidentAi(incident.id, markdown, commands);
    const report = await db.insertAiReport("incident", incident.id, markdown);
    hub.broadcast({ type: "ai_report", payload: report });
    if (updated) hub.broadcast({ type: "incident", payload: updated });
    res.json(updated);
  });

  const server = http.createServer(app);
  const wss = new WebSocketServer({ server, path: "/ws" });
  wss.on("connection", (socket, req) => {
    if (HTTP_BIND === "0.0.0.0" && !isLoopback(peerIp(req.socket.remoteAddress))) {
      const token = new URL(req.url ?? "", "http://127.0.0.1").searchParams.get("token") || "";
      if (token !== getSettings().lanToken) {
        socket.close(1008, "token");
        return;
      }
    }
    hub.add(socket);
    void snapshot().then((stats) => {
      if (socket.readyState === 1) {
        socket.send(JSON.stringify({ type: "hello", payload: { stats } }));
      }
    });
  });

  server.listen(HTTP_PORT, HTTP_BIND, () => {
    console.log(`[http] REST + WebSocket on http://${HTTP_BIND}:${HTTP_PORT}`);
    console.log(`[ws]   ws://${HTTP_BIND}:${HTTP_PORT}/ws`);
    if (HTTP_BIND === "0.0.0.0") {
      const token = ensureLanToken();
      console.log("[http] lab mode: API reachable on this Mac's LAN IPv4");
      console.log(`[http] LAN token: ${token}`);
    }
  });

  let upkeep: Promise<void> = Promise.resolve();
  const queueUpkeep = (job: () => Promise<void>) => {
    upkeep = upkeep.then(job).catch((err) => console.warn("[siem] upkeep failed", err));
  };
  const retain = async () => {
    const settings = getSettings();
    try {
      const n = await db.pruneEvents(settings.maxEvents, settings.retentionDays);
      if (n > 0) console.log(`[siem] pruned ${n} old events`);
    } catch (err) {
      console.warn("[siem] retention failed", err);
    }
    try {
      await db.expirePendingResponses(24);
    } catch (err) {
      console.warn("[siem] response expiry failed", err);
    }
  };
  const backup = async () => {
    const age = latestBackupAgeMs();
    if (age !== null && age < 20 * 60 * 60 * 1000) return;
    try {
      const file = await backupDatabase(db);
      console.log(`[siem] backup ${file}`);
    } catch (err) {
      console.warn("[siem] backup failed", err);
    }
  };
  const retention = setInterval(() => queueUpkeep(retain), 60 * 60 * 1000);
  const backups = setInterval(() => queueUpkeep(backup), 6 * 60 * 60 * 1000);
  queueUpkeep(async () => {
    await retain();
    await backup();
  });

  aggregator.start(AGG_INTERVAL);
  void llm.start();
  const stopSensor = startMacSensor(collector);
  const stopFim = startFimWatch(db, (records) => {
    for (const rec of records) {
      hub.broadcast({ type: "fim", payload: rec });
      void collector.ingestLive(
        `<4>1 ${new Date().toISOString()} ${computerName()} fim - - - file changed ${rec.path} size=${rec.size ?? "?"} mode=${rec.mode ?? "?"}`,
        "host",
        "127.0.0.1"
      );
    }
  });
  const stopInventory = startInventoryLoop(db, (result) => {
    collector.refreshInventoryCves(highConfidenceCves(result.hits));
    for (const hit of result.hits) hub.broadcast({ type: "inventory_hit", payload: hit });
  });

  const shutdown = async () => {
    console.log("\n[siem] shutting down");
    stopDemo();
    stopSensor();
    stopFim();
    stopInventory();
    clearInterval(retention);
    clearInterval(backups);
    aggregator.stop();
    await collector.stop();
    await llm.stop();
    wss.close();
    server.close();
    await db.close();
    process.exit(0);
  };
  process.on("SIGINT", () => void shutdown());
  process.on("SIGTERM", () => void shutdown());
}

function extractCommands(markdown: string): string | null {
  const match = markdown.match(/```(?:bash|zsh|sh)?\n([\s\S]*?)```/i);
  return match ? match[1].trim() : null;
}

main().catch((err) => {
  console.error("[siem] fatal", err);
  process.exit(1);
});
