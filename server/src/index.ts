import "dotenv/config";
import http from "node:http";
import express from "express";
import { WebSocketServer } from "ws";
import { ThreatAggregator } from "./aggregator.js";
import { hub } from "./bus.js";
import { UdpCollector } from "./collector.js";
import { SiemDatabase } from "./database.js";
import { randomSyslog, startDemoStream } from "./demo.js";
import { startFimWatch } from "./fim.js";
import { startInventoryLoop } from "./inventory.js";
import { LlmEngine } from "./llm.js";
import { saveKeys, type CloudProvider } from "./llmKeys.js";
import { DB_PATH } from "./paths.js";
import { computerName } from "./host.js";
import { executeResponse, undoResponse } from "./response.js";
import { startMacSensor } from "./sensor.js";
import { detectDashboardUrl, renderHealthPage, wantsHealthHtml } from "./healthPage.js";
import type { EventOrigin, LogTransport, PlatformStats } from "./types.js";
import { loadCustomRules, saveCustomRules, type CustomRule } from "./customRules.js";
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
    llm: llm.status,
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
  app.use((_req, res, next) => {
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type");
    res.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
    next();
  });
  app.options("*", (_req, res) => res.sendStatus(204));

  app.get("/api/health", async (req, res) => {
    const dashboardUrl = await detectDashboardUrl();
    const payload = {
      ok: true,
      platform: "LocalSIEM",
      arch: process.arch,
      udpPort,
      tcpPort,
      tlsPort,
      relpPort,
      db: DB_PATH,
      llm: llm.status,
      clients: hub.size,
      dashboardUrl
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
    res.json(llm.status);
  });

  app.post("/api/llm", async (req, res) => {
    const id = typeof req.body?.id === "string" ? req.body.id : "local-qwen";
    const status = await llm.select(id);
    res.json(status);
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
    await db.upsertIoc(kind, value, note);
    await db.insertAudit("operator", "ioc-add", `${kind} ${value}`);
    res.json(await db.listIocs());
  });

  app.delete("/api/iocs/:id", async (req, res) => {
    await db.deleteIoc(Number(req.params.id));
    res.json(await db.listIocs());
  });

  app.get("/api/rules", (_req, res) => {
    res.json(loadCustomRules());
  });

  app.put("/api/rules", (req, res) => {
    const rules = Array.isArray(req.body) ? (req.body as CustomRule[]) : [];
    res.json(saveCustomRules(rules));
  });

  app.get("/api/reports/summary", async (req, res) => {
    const hours = Number(req.query.hours || 24);
    const summary = await db.reportSummary(hours);
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
        rbacOptional: process.env.SIEM_AUTH === "1",
        retention: true,
        jsonIngest: true,
        customRules: true,
        enrichment: true,
        historicalHunt: true,
        localLlm: true
      }
    });
  });

  app.get("/api/compliance", async (_req, res) => {
    const summary = await db.reportSummary(24);
    const html = `<!DOCTYPE html><html><head><meta charset="utf-8"><title>LocalSIEM compliance snapshot</title>
      <style>body{font-family:sans-serif;background:#111;color:#ddd;padding:24px} table{border-collapse:collapse} td,th{border:1px solid #444;padding:6px 10px}</style></head>
      <body><h1>LocalSIEM lab compliance snapshot</h1>
      <p>Not a PCI/HIPAA certification. Evidence pack for a home-lab control set (ISO 27001-inspired logging).</p>
      <table>
      <tr><th>Control</th><th>Status</th></tr>
      <tr><td>A.12.4 Logging</td><td>Events retained ${summary.retentionDays} days · ${summary.events} in last 24h</td></tr>
      <tr><td>A.16 Incident management</td><td>${summary.openIncidents} open · ${summary.highOpen} high/crit</td></tr>
      <tr><td>A.12.2 Malware / KEV</td><td>CISA KEV + inventory matching enabled</td></tr>
      <tr><td>A.9 Access</td><td>${process.env.SIEM_AUTH === "1" ? "SIEM_AUTH on" : "localhost trust (set SIEM_AUTH=1 for login)"}</td></tr>
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
    const updated = await db.updateIncidentStatus(Number(req.params.id), status);
    if (!updated) return res.status(404).json({ error: "not found" });
    hub.broadcast({ type: "incident", payload: updated });
    res.json(updated);
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
    collector.refreshInventoryCves(result.hits.map((hit) => hit.cve));
    for (const hit of result.hits) hub.broadcast({ type: "inventory_hit", payload: hit });
    res.json({ items: result.items.length, hits: result.hits.length });
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
      if (denied) hub.broadcast({ type: "response", payload: denied });
      res.json(denied);
      return;
    }
    const result = await executeResponse(item);
    const updated = await db.updateResponse(item.id, result.status, result.output);
    if (updated) hub.broadcast({ type: "response", payload: updated });
    res.json(updated);
  });

  app.post("/api/response/:id/undo", async (req, res) => {
    const item = await db.getResponse(Number(req.params.id));
    if (!item) return res.status(404).json({ error: "not found" });
    if (item.status !== "executed") return res.status(409).json({ error: "only executed actions can be undone" });
    const result = await undoResponse(item);
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
  wss.on("connection", (socket) => {
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
      console.log("[http] lab mode: API reachable on this Mac's LAN IPv4");
    }
  });

  const retention = setInterval(() => {
    void db.pruneEvents(200_000, 7).then((n) => {
      if (n > 0) console.log(`[siem] pruned ${n} old events`);
    });
    void db.expirePendingResponses(24);
  }, 60 * 60 * 1000);
  void db.pruneEvents(200_000, 7);
  void db.expirePendingResponses(24);

  aggregator.start(AGG_INTERVAL);
  void llm.start();
  const stopSensor = startMacSensor(collector);
  const stopFim = startFimWatch(db, (records) => {
    for (const rec of records) {
      hub.broadcast({ type: "fim", payload: rec });
      void collector.ingestLive(
        `<4>1 ${new Date().toISOString()} ${computerName()} fim - - - file changed ${rec.path}`,
        "host",
        "127.0.0.1"
      );
    }
  });
  const stopInventory = startInventoryLoop(db, (result) => {
    collector.refreshInventoryCves(result.hits.map((hit) => hit.cve));
    for (const hit of result.hits) hub.broadcast({ type: "inventory_hit", payload: hit });
  });

  const shutdown = async () => {
    console.log("\n[siem] shutting down");
    stopDemo();
    stopSensor();
    stopFim();
    stopInventory();
    clearInterval(retention);
    aggregator.stop();
    await collector.stop();
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
