import dgram from "node:dgram";
import type { RemoteInfo } from "node:dgram";
import type net from "node:net";
import type tls from "node:tls";
import { hub } from "./bus.js";
import { SiemDatabase, sha256 } from "./database.js";
import { matchCustomRule } from "./customRules.js";
import { enrichParsed } from "./enrich.js";
import { matchIoc } from "./iocs.js";
import { evaluateRules, isAuthFailure, isNoise } from "./rules.js";
import { ingestAllowed, isBlockableIp } from "./netguard.js";
import { notifyHigh } from "./notify.js";

import {
  RelpBuffer,
  SyslogFrameBuffer,
  bindNet,
  bindTls,
  closeServer,
  ensureTlsMaterial,
  listenPort,
  peerIp,
  relpReply
} from "./syslogNet.js";
import type { EventOrigin, Incident, LogEvent, LogTransport, SeverityLabel } from "./types.js";

const SYSLOG_PRI = /^<(\d{1,3})>/;
const RFC5424 =
  /^<(\d{1,3})>(\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(-|(?:\[.*?\]\s*)+)\s*(.*)$/s;
const RFC3164 =
  /^<(\d{1,3})>([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+([^:\s]+)(?:\[([^\]]+)\])?:\s*(.*)$/s;

export class UdpCollector {
  private socket: dgram.Socket | null = null;
  private tcpServer: net.Server | null = null;
  private tlsServer: tls.Server | null = null;
  private relpServer: net.Server | null = null;
  ports: { udp: number | null; tcp: number | null; tls: number | null; relp: number | null } = {
    udp: null,
    tcp: null,
    tls: null,
    relp: null
  };
  private kevCache = new Set<string>();
  private inventoryCves = new Set<string>();

  constructor(private db: SiemDatabase) {}

  get port(): number | null {
    return this.ports.udp;
  }

  async start(preferred = 514, fallback = 1514): Promise<number> {
    this.kevCache = new Set(await this.db.listKevCves());
    const bound = await listenPort(preferred, fallback, "UDP syslog", (port) =>
      this.bindUdp(port)
    );
    this.socket = bound.server;
    this.ports.udp = bound.port;
    return bound.port;
  }

  async startTcp(preferred = 601, fallback = 1601): Promise<number> {
    const bound = await listenPort(preferred, fallback, "TCP syslog", (port) =>
      bindNet(port, (socket) => this.attachSyslogSocket(socket, "tcp"))
    );
    this.tcpServer = bound.server;
    this.ports.tcp = bound.port;
    return bound.port;
  }

  async startTls(preferred = 6514, fallback = 16514): Promise<number> {
    const material = ensureTlsMaterial();
    const bound = await listenPort(preferred, fallback, "TLS syslog", (port) =>
      bindTls(port, material, (socket) => this.attachSyslogSocket(socket, "tls"))
    );
    this.tlsServer = bound.server;
    this.ports.tls = bound.port;
    return bound.port;
  }

  async startRelp(preferred = 2514, fallback = 12514): Promise<number> {
    const bound = await listenPort(preferred, fallback, "RELP", (port) =>
      bindNet(port, (socket) => this.attachRelpSocket(socket))
    );
    this.relpServer = bound.server;
    this.ports.relp = bound.port;
    return bound.port;
  }

  refreshKev(cves: string[]): void {
    this.kevCache = new Set(cves.map((c) => c.toUpperCase()));
  }

  refreshInventoryCves(cves: string[]): void {
    this.inventoryCves = new Set(cves.map((c) => c.toUpperCase()));
  }

  ingestBuffer(buf: Buffer, rinfo: RemoteInfo): Promise<LogEvent | null> {
    return this.handleDatagram(buf, rinfo, "live", "udp");
  }

  ingestLive(
    raw: string,
    transport: LogTransport = "udp",
    sourceIp = "127.0.0.1"
  ): Promise<LogEvent | null> {
    const buf = Buffer.from(raw, "utf8");
    return this.handleDatagram(
      buf,
      { address: sourceIp, family: "IPv4", port: 0, size: buf.length },
      "live",
      transport
    );
  }

  ingestSynthetic(raw: string, transport: LogTransport = "udp"): Promise<LogEvent | null> {
    const buf = Buffer.from(raw, "utf8");
    return this.handleDatagram(
      buf,
      { address: "demo", family: "IPv4", port: 0, size: buf.length },
      "demo",
      transport
    );
  }

  async stop(): Promise<void> {
    await Promise.all([
      new Promise<void>((resolve) => {
        if (!this.socket) return resolve();
        this.socket.close(() => resolve());
      }),
      closeServer(this.tcpServer),
      closeServer(this.tlsServer),
      closeServer(this.relpServer)
    ]);
    this.socket = null;
    this.tcpServer = null;
    this.tlsServer = null;
    this.relpServer = null;
  }

  private bindUdp(port: number): Promise<dgram.Socket> {
    return new Promise((resolve, reject) => {
      const socket = dgram.createSocket("udp4");
      const onError = (err: Error) => {
        socket.close();
        reject(err);
      };
      socket.once("error", onError);
      socket.bind(port, "0.0.0.0", () => {
        socket.off("error", onError);
        socket.on("error", (err) => {
          console.error("[collector] UDP socket error", err);
        });
        socket.on("message", (msg, rinfo) => {
          void this.handleDatagram(msg, rinfo, "live", "udp");
        });
        resolve(socket);
      });
    });
  }

  private attachSyslogSocket(socket: net.Socket, transport: "tcp" | "tls"): void {
    const frames = new SyslogFrameBuffer();
    const ip = peerIp(socket.remoteAddress);
    socket.on("data", (chunk: Buffer) => {
      for (const msg of frames.push(chunk)) {
        void this.ingestLive(msg, transport, ip);
      }
    });
    socket.on("end", () => {
      for (const msg of frames.flush()) {
        void this.ingestLive(msg, transport, ip);
      }
    });
    socket.on("error", () => socket.destroy());
  }

  private attachRelpSocket(socket: net.Socket): void {
    const frames = new RelpBuffer();
    const ip = peerIp(socket.remoteAddress);
    const write = (txnr: string, body: string) => {
      if (!socket.destroyed) socket.write(relpReply(txnr, body));
    };
    socket.on("data", (chunk: Buffer) => {
      for (const frame of frames.push(chunk)) {
        if (frame.command === "open") {
          write(
            frame.txnr,
            "200 OK\nrelp_version=1\nrelp_software=LocalSIEM\ncommands=syslog"
          );
        } else if (frame.command === "syslog") {
          if (frame.data.trim()) void this.ingestLive(frame.data, "relp", ip);
          write(frame.txnr, "200 OK");
        } else if (frame.command === "close") {
          write(frame.txnr, "200 OK");
          socket.end();
        } else {
          write(frame.txnr, "200 OK");
        }
      }
    });
    socket.on("error", () => socket.destroy());
  }

  private async handleDatagram(
    buf: Buffer,
    rinfo: RemoteInfo,
    origin: EventOrigin,
    transport: LogTransport
  ): Promise<LogEvent | null> {
    const raw = buf.toString("utf8").replace(/\u0000/g, "").trim();
    if (!raw) return null;
    if (origin === "live" && !ingestAllowed(rinfo.address)) {
      return null;
    }
    const parsed = liftInnerProcess(parseEventPayload(raw, rinfo));
    if (origin === "live" && isNoise({ message: parsed.message, appName: parsed.appName })) {
      return null;
    }
    parsed.parsed = {
      ...parsed.parsed,
      ...enrichParsed({
        message: parsed.message,
        appName: parsed.appName,
        hostname: parsed.hostname,
        sourceIp: parsed.sourceIp
      }),
      transport
    };
    const hash = sha256(
      `${origin}|${transport}|${parsed.sourceIp}|${rinfo.port}|${parsed.raw}|${parsed.receivedAt}|${process.hrtime.bigint()}`
    );
    const event = await this.db.insertEvent({ ...parsed, hash, origin, transport });
    if (!event) return null;
    hub.broadcast({ type: "event", payload: event });
    const incident = await this.correlate(event);
    if (incident) {
      hub.broadcast({ type: "incident", payload: incident });
    }
    return event;
  }

  private async correlate(event: LogEvent): Promise<Incident | null> {
    let authFailures = 0;
    if (event.hostname && isAuthFailure(event.message, event.appName)) {
      const since = new Date(Date.now() - 2 * 60 * 1000).toISOString();
      const failures = await this.db.recentAuthFailures(event.hostname, since, event.origin);
      authFailures = failures.length;
    }
    let uebaNote = "";
    if (event.hostname && isAuthFailure(event.message, event.appName)) {
      const ueba = await this.db.bumpUeba(event.hostname, "auth_fail");
      if (ueba.baseline >= 1 && ueba.count > Math.max(5, ueba.baseline * 3)) {
        uebaNote = ` Unusual vs 7-day baseline (${ueba.count}/h vs avg ${ueba.baseline.toFixed(1)}).`;
      }
    }
    const ioc = await matchIoc(this.db, event);
    let hit = evaluateRules(event, {
      kev: this.kevCache,
      authFailures,
      inventoryCves: this.inventoryCves
    });
    if (!hit) {
      const custom = matchCustomRule(event);
      if (custom) {
        hit = {
          ruleId: custom.id,
          ruleName: `custom:${custom.id}`,
          title: custom.name,
          severity: custom.severity,
          riskScore: custom.riskScore,
          windowMinutes: 30,
          mitre: custom.mitre ? [custom.mitre] : []
        };
      }
    }
    if (!hit && ioc) {
      hit = {
        ruleId: "intel-ioc",
        ruleName: `ioc:${ioc.kind}:${ioc.value}`,
        title: `Threat intel match (${ioc.kind}) ${ioc.value}`,
        severity: "high",
        riskScore: 82,
        windowMinutes: 60,
        mitre: [{ id: "T1595", tactic: "Reconnaissance", technique: "Active Scanning" }]
      };
    }
    if (
      !hit &&
      event.hostname &&
      (/sudo:/.test(event.message) || event.appName === "sudo")
    ) {
      const opens = await this.db.listIncidents({ origin: event.origin });
      const prior = opens.find(
        (row) =>
          row.status === "open" &&
          row.ruleName.startsWith(`authburst:${event.hostname}`)
      );
      if (prior) {
        hit = {
          ruleId: "chain-priv",
          ruleName: `chain:auth-sudo:${event.hostname}`,
          title: `Kill chain: auth burst then sudo on ${event.hostname}`,
          severity: "critical",
          riskScore: 92,
          windowMinutes: 15,
          mitre: [{ id: "T1548", tactic: "Privilege Escalation", technique: "Abuse Elevation Control" }]
        };
      }
    }
    if (!hit) return null;
    if (ioc) hit = { ...hit, riskScore: Math.min(99, hit.riskScore + 12), title: `${hit.title} [IOC]` };
    if (uebaNote) hit = { ...hit, title: hit.title + uebaNote, riskScore: Math.min(99, hit.riskScore + 8) };
    const extraIds =
      event.hostname && isAuthFailure(event.message, event.appName)
        ? (await this.db.recentAuthFailures(
            event.hostname,
            new Date(Date.now() - 2 * 60 * 1000).toISOString(),
            event.origin
          )).map((row) => row.id)
        : [];
    const opened = await this.openIncident({
      title: hit.title,
      ruleName: hit.ruleName,
      severity: hit.severity,
      event,
      evidence: event.message,
      riskScore: hit.riskScore,
      windowMinutes: hit.windowMinutes,
      extraIds,
      mitre: hit.mitre
    });
    if (!opened) return null;
    const { incident, created } = opened;
    if (created && (incident.severity === "critical" || incident.severity === "high")) {
      notifyHigh(incident.title, incident.evidence.slice(0, 160));
    }
    if (created && hit.response) {
      if (hit.response.action !== "block_ip" || isBlockableIp(hit.response.target)) {
        const action = await this.db.insertResponse({
          incidentId: incident.id,
          action: hit.response.action,
          target: hit.response.target,
          command: hit.response.command,
          origin: event.origin
        });
        hub.broadcast({ type: "response", payload: action });
      }
    }
    return incident;
  }

  private async openIncident(opts: {
    title: string;
    ruleName: string;
    severity: SeverityLabel;
    event: LogEvent;
    evidence: string;
    riskScore: number;
    windowMinutes: number;
    extraIds?: number[];
    mitre?: Array<{ id: string; tactic: string; technique: string }>;
  }): Promise<{ incident: Incident; created: boolean } | null> {
    const since = new Date(Date.now() - opts.windowMinutes * 60 * 1000).toISOString();
    const existing = await this.db.openIncidentByRule(
      opts.ruleName,
      since,
      opts.event.origin
    );
    if (existing) {
      const incident = await this.db.touchIncident(existing.id, opts.event.id, opts.evidence, opts.riskScore);
      return incident ? { incident, created: false } : null;
    }
    const ids = Array.from(new Set([opts.event.id, ...(opts.extraIds ?? [])]));
    const incident = await this.db.insertIncident({
      title: opts.title,
      ruleName: opts.ruleName,
      severity: opts.severity,
      eventIds: ids,
      evidence: opts.evidence,
      riskScore: opts.riskScore,
      origin: opts.event.origin,
      mitre: opts.mitre ?? []
    });
    return { incident, created: true };
  }
}

export function parseEventPayload(
  raw: string,
  rinfo: { address: string; port: number }
): {
  receivedAt: string;
  facility: number | null;
  severity: number | null;
  hostname: string | null;
  appName: string | null;
  procId: string | null;
  message: string;
  raw: string;
  sourceIp: string | null;
  parsed: Record<string, unknown>;
} {
  const receivedAt = new Date().toISOString();
  const sourceIp = rinfo.address;
  const jsonAttempt = tryParseJson(raw);
  if (jsonAttempt) {
    const message =
      String(jsonAttempt.message ?? jsonAttempt.msg ?? jsonAttempt.event ?? raw);
    const severity =
      typeof jsonAttempt.severity === "number"
        ? jsonAttempt.severity
        : typeof jsonAttempt.level === "number"
          ? jsonAttempt.level
          : null;
    return {
      receivedAt,
      facility: numOrNull(jsonAttempt.facility),
      severity,
      hostname: strOrNull(jsonAttempt.hostname ?? jsonAttempt.host),
      appName: strOrNull(jsonAttempt.appName ?? jsonAttempt.app ?? jsonAttempt.program),
      procId: strOrNull(jsonAttempt.procId ?? jsonAttempt.pid),
      message,
      raw,
      sourceIp,
      parsed: {
        format: "json",
        sourceIp,
        sourcePort: rinfo.port,
        ...jsonAttempt
      }
    };
  }

  const rfc5424 = raw.match(RFC5424);
  if (rfc5424) {
    const pri = Number(rfc5424[1]);
    const facility = Math.floor(pri / 8);
    const severity = pri % 8;
    const hostname = dashToNull(rfc5424[4]);
    const appName = dashToNull(rfc5424[5]);
    const procId = dashToNull(rfc5424[6]);
    const message = rfc5424[9] || raw;
    return {
      receivedAt,
      facility,
      severity,
      hostname,
      appName,
      procId,
      message,
      raw,
      sourceIp,
      parsed: {
        format: "rfc5424",
        pri,
        version: rfc5424[2],
        timestamp: rfc5424[3],
        hostname,
        appName,
        procId,
        msgId: dashToNull(rfc5424[7]),
        structuredData: rfc5424[8],
        message,
        sourceIp,
        sourcePort: rinfo.port
      }
    };
  }

  const rfc3164 = raw.match(RFC3164);
  if (rfc3164) {
    const pri = Number(rfc3164[1]);
    const facility = Math.floor(pri / 8);
    const severity = pri % 8;
    return {
      receivedAt,
      facility,
      severity,
      hostname: rfc3164[3],
      appName: rfc3164[4],
      procId: rfc3164[5] ?? null,
      message: rfc3164[6] || raw,
      raw,
      sourceIp,
      parsed: {
        format: "rfc3164",
        pri,
        timestamp: rfc3164[2],
        hostname: rfc3164[3],
        appName: rfc3164[4],
        procId: rfc3164[5] ?? null,
        message: rfc3164[6],
        sourceIp,
        sourcePort: rinfo.port
      }
    };
  }

  const priMatch = raw.match(SYSLOG_PRI);
  const pri = priMatch ? Number(priMatch[1]) : null;
  const message = priMatch ? raw.slice(priMatch[0].length) : raw;
  return {
    receivedAt,
    facility: pri === null ? null : Math.floor(pri / 8),
    severity: pri === null ? 6 : pri % 8,
    hostname: null,
    appName: null,
    procId: null,
    message,
    raw,
    sourceIp,
    parsed: {
      format: "unstructured",
      pri,
      message,
      sourceIp,
      sourcePort: rinfo.port
    }
  };
}

function liftInnerProcess<T extends { appName: string | null; procId: string | null; message: string; parsed: Record<string, unknown> }>(
  parsed: T
): T {
  const inner = parsed.message.match(/\b([A-Za-z][\w.-]+)\[(\d+)\]:/);
  if (!inner) return parsed;
  const wrapper = /^(unifiedlog|syslogd|syslog|log)$/i;
  if (!parsed.appName || wrapper.test(parsed.appName)) {
    parsed.appName = inner[1];
    parsed.procId = inner[2];
    parsed.parsed = { ...parsed.parsed, innerApp: inner[1], innerPid: inner[2] };
  }
  return parsed;
}

function tryParseJson(raw: string): Record<string, unknown> | null {
  const trimmed = raw.trim();
  if (!trimmed.startsWith("{") && !trimmed.startsWith("[")) return null;
  try {
    const value = JSON.parse(trimmed) as unknown;
    if (Array.isArray(value)) {
      return { items: value, message: JSON.stringify(value) };
    }
    if (value && typeof value === "object") {
      return value as Record<string, unknown>;
    }
  } catch {
    return null;
  }
  return null;
}

function dashToNull(value: string | undefined): string | null {
  if (!value || value === "-") return null;
  return value;
}

function strOrNull(value: unknown): string | null {
  if (typeof value === "string" && value.trim()) return value;
  if (typeof value === "number") return String(value);
  return null;
}

function numOrNull(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}
