import net from "node:net";
import type { Request } from "express";
import type { LlmStatus } from "./types.js";

function portOpen(port: number): Promise<boolean> {
  return new Promise((resolve) => {
    const socket = net.connect({ host: "127.0.0.1", port }, () => {
      socket.end();
      resolve(true);
    });
    socket.setTimeout(200);
    socket.on("timeout", () => {
      socket.destroy();
      resolve(false);
    });
    socket.on("error", () => resolve(false));
  });
}

export async function detectDashboardUrl(): Promise<string> {
  if (process.env.UI_URL) return process.env.UI_URL;
  const ordered = [process.env.UI_PORT, "5173", "5174"].filter(Boolean) as string[];
  const seen = new Set<string>();
  for (const raw of ordered) {
    if (seen.has(raw)) continue;
    seen.add(raw);
    const port = Number(raw);
    if (!Number.isInteger(port)) continue;
    if (await portOpen(port)) return dashboardHref(port);
  }
  return dashboardHref(Number(process.env.UI_PORT || "5173"));
}

function dashboardHref(port: number): string {
  const lan = (process.env.HOST_IPV4 || "").trim();
  const host =
    process.env.SIEM_BIND === "0.0.0.0" && lan && lan !== "none" && lan !== "127.0.0.1"
      ? lan
      : "127.0.0.1";
  return `http://${host}:${port}`;
}

export function wantsHealthHtml(req: Request): boolean {
  const format = typeof req.query.format === "string" ? req.query.format.toLowerCase() : "";
  if (format === "json") return false;
  if (format === "html") return true;
  const accept = (req.get("accept") ?? "").toLowerCase();
  return accept.startsWith("text/html");
}

export function renderHealthPage(input: {
  ok: boolean;
  platform: string;
  arch: string;
  udpPort: number | null;
  tcpPort: number | null;
  tlsPort: number | null;
  relpPort: number | null;
  db: string;
  llm: LlmStatus;
  clients: number;
  events?: number;
  incidents?: number;
  news?: number;
  fimChanges?: number;
  inventoryHits?: number;
  pendingResponses?: number;
  eps?: number;
  dashboardUrl?: string;
}): string {
  const llmEnglish = describeLlm(input.llm);
  const arch = input.arch === "arm64" ? "Apple Silicon (arm64)" : input.arch;
  const status = input.ok ? "Signalbay is running." : "Signalbay reported a problem.";
  const dashboard = input.dashboardUrl || "http://127.0.0.1:5173";

  const rows: Array<[string, string]> = [
    ["Status", status],
    ["Platform", `${escapeHtml(input.platform)} on ${escapeHtml(arch)}`],
    ["Dashboard", `<a href="${escapeHtml(dashboard)}">${escapeHtml(dashboard)}</a>`],
    ["UDP syslog", portEnglish("UDP collector (RFC 5426)", input.udpPort)],
    ["TCP syslog", portEnglish("TCP collector (RFC 6587)", input.tcpPort)],
    ["TLS syslog", portEnglish("TLS collector (RFC 5425)", input.tlsPort)],
    ["RELP", portEnglish("RELP collector", input.relpPort)],
    ["Live dashboard clients", `${input.clients} connected`],
    ["AI engine", llmEnglish.title],
    ["AI detail", escapeHtml(llmEnglish.detail)],
    ["Database", `<code>${escapeHtml(input.db)}</code>`]
  ];
  if (input.events != null) rows.push(["Stored events", String(input.events)]);
  if (input.incidents != null) rows.push(["Incidents", String(input.incidents)]);
  if (input.news != null) rows.push(["Threat intel items", String(input.news)]);
  if (input.fimChanges != null) rows.push(["File integrity changes", String(input.fimChanges)]);
  if (input.inventoryHits != null) rows.push(["Inventory / KEV matches", String(input.inventoryHits)]);
  if (input.pendingResponses != null) {
    rows.push(["Pending active responses", String(input.pendingResponses)]);
  }
  if (input.eps != null) rows.push(["Events per second (window)", String(input.eps)]);

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Signalbay status</title>
  <style>
    :root {
      --bg: #070b10;
      --panel: #101822;
      --line: rgba(120, 170, 210, 0.16);
      --text: #d7e4f2;
      --muted: #7d8ea3;
      --cyan: #3cefff;
      --ok: #3ddc97;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      min-height: 100vh;
      font-family: "IBM Plex Sans", "Avenir Next", sans-serif;
      background:
        radial-gradient(900px 420px at 10% -10%, rgba(60, 239, 255, 0.08), transparent 50%),
        var(--bg);
      color: var(--text);
      padding: 32px 18px 48px;
    }
    main {
      max-width: 760px;
      margin: 0 auto;
      background: linear-gradient(180deg, var(--panel), #141e2b);
      border: 1px solid var(--line);
      border-radius: 16px;
      padding: 22px 24px 20px;
      box-shadow: 0 18px 50px rgba(0,0,0,0.35);
    }
    .kicker {
      color: var(--muted);
      font-size: 11px;
      letter-spacing: 0.14em;
      text-transform: uppercase;
      margin: 0 0 6px;
    }
    h1 { margin: 0 0 8px; font-size: 26px; }
    .lede { color: var(--muted); margin: 0 0 18px; line-height: 1.5; }
    .pill {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      border: 1px solid rgba(61, 220, 151, 0.35);
      color: var(--ok);
      border-radius: 999px;
      padding: 4px 10px;
      font-size: 12px;
      margin-bottom: 16px;
    }
    .pill.down { color: #ff4d6d; border-color: rgba(255, 77, 109, 0.4); }
    dl { margin: 0; display: grid; gap: 0; }
    .row {
      display: grid;
      grid-template-columns: 200px 1fr;
      gap: 12px;
      padding: 10px 0;
      border-top: 1px solid var(--line);
      font-size: 14px;
    }
    dt { color: var(--muted); }
    dd { margin: 0; line-height: 1.45; }
    code, a { color: var(--cyan); }
    code { font-family: "IBM Plex Mono", ui-monospace, monospace; font-size: 12px; word-break: break-all; }
    a { text-decoration: none; }
    a:hover { text-decoration: underline; }
    footer { margin-top: 18px; color: var(--muted); font-size: 12px; }
    @media (max-width: 640px) {
      .row { grid-template-columns: 1fr; gap: 4px; }
    }
  </style>
</head>
<body>
  <main>
    <p class="kicker">Signalbay · health check</p>
    <h1>System status</h1>
    <p class="lede">This page is the same health check the dashboard uses, written in plain English. Programs can still read the raw JSON.</p>
    <div class="pill ${input.ok ? "" : "down"}">${input.ok ? "Healthy" : "Unhealthy"}</div>
    <dl>
      ${rows
        .map(
          ([label, value]) =>
            `<div class="row"><dt>${escapeHtml(label)}</dt><dd>${value}</dd></div>`
        )
        .join("")}
    </dl>
    <footer>
      Raw machine-readable copy:
      <a href="/api/health?format=json">/api/health?format=json</a>
    </footer>
  </main>
</body>
</html>`;
}

function portEnglish(kind: string, port: number | null): string {
  if (port == null) return `${kind} is not listening.`;
  return `${kind} is listening on port ${port}.`;
}

function describeLlm(llm: LlmStatus): { title: string; detail: string } {
  const stateMap: Record<LlmStatus["state"], string> = {
    idle: "Idle — not loaded yet",
    downloading: "Downloading the local model",
    compiling: "Compiling the local model",
    loading: "Loading the local model",
    ready: "Ready",
    error: "Error"
  };
  const mode = llm.mode === "cloud" ? "cloud model" : "local model";
  const gpu = llm.metal
    ? "Apple Metal GPU"
    : llm.gpu
      ? `GPU (${llm.gpu})`
      : "CPU";
  const title = `${stateMap[llm.state] ?? llm.state} · ${mode} · ${gpu}`;
  const detail = llm.message || `${llm.model || "no model selected"}`;
  return { title, detail };
}

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}
