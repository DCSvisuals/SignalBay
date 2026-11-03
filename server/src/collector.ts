import dgram from "node:dgram";
import type { RemoteInfo } from "node:dgram";
import type net from "node:net";
import type tls from "node:tls";
import { hub } from "./bus.js";
import { SiemDatabase, sha256 } from "./database.js";
import { matchCustomRule } from "./customRules.js";
import { enrichParsed } from "./enrich.js";
import { matchIoc } from "./iocs.js";
import { liftInnerProcess, parseEventPayload } from "./parse.js";
import {
  evaluateRules,
  isAuthFailure,
  isAuthSuccess,
  isNoise,
  isSudoSuccess,
  responseForCustom,
  type RuleHit
} from "./rules.js";
import { ingestAllowed, isBlockableIp } from "./netguard.js";
import { notifyHigh } from "./notify.js";
import { isRuleEnabled, isSuppressed } from "./settings.js";

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
  private tail: Promise<void> = Promise.resolve();

  constructor(private db: SiemDatabase) {}

  private enqueue<T>(work: () => Promise<T>): Promise<T> {
    const run = this.tail.then(work, work);
    this.tail = run.then(
      () => undefined,
      () => undefined
    );
    return run;
  }

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
    return this.enqueue(() => this.handleDatagram(buf, rinfo, "live", "udp"));
  }

  ingestLive(
    raw: string,
    transport: LogTransport = "udp",
    sourceIp = "127.0.0.1"
  ): Promise<LogEvent | null> {
    const buf = Buffer.from(raw, "utf8");
    return this.enqueue(() =>
      this.handleDatagram(
        buf,
        { address: sourceIp, family: "IPv4", port: 0, size: buf.length },
        "live",
        transport
      )
    );
  }

  ingestSynthetic(raw: string, transport: LogTransport = "udp"): Promise<LogEvent | null> {
    const buf = Buffer.from(raw, "utf8");
    return this.enqueue(() =>
      this.handleDatagram(
        buf,
        { address: "demo", family: "IPv4", port: 0, size: buf.length },
        "demo",
        transport
      )
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
          void this.enqueue(() => this.handleDatagram(msg, rinfo, "live", "udp"));
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
            "200 OK\nrelp_version=1\nrelp_software=Signalbay\ncommands=syslog"
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
    const event = await this.db.insertEvent({
      ...parsed,
      eventTime: parsed.eventTime,
      hash,
      origin,
      transport
    });
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
    const src = event.srcIp;
    let firstSeenSrc = false;
    if (src && (isAuthSuccess(event.message) || isSudoSuccess(event.message, event.appName))) {
      const since = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString();
      const prior = await this.db.countPriorSource(event.origin, src, event.id, since);
      firstSeenSrc = prior === 0;
    }
    const ioc = await matchIoc(this.db, event);
    const usable = (candidate: RuleHit | null): RuleHit | null => {
      if (!candidate) return null;
      if (!isRuleEnabled(candidate.ruleId) || isSuppressed(event, candidate.ruleId)) return null;
      return candidate;
    };
    let hit = usable(
      evaluateRules(event, {
        kev: this.kevCache,
        authFailures,
        inventoryCves: this.inventoryCves,
        firstSeenSrc,
        authSuccessAfterFail: isAuthSuccess(event.message) && authFailures >= 1
      })
    );
    if (!hit) {
      const custom = matchCustomRule(event);
      if (custom) {
        hit = usable({
          ruleId: custom.id,
          ruleName: `custom:${custom.id}`,
          title: custom.name,
          severity: custom.severity,
          riskScore: custom.riskScore,
          windowMinutes: 30,
          mitre: custom.mitre ? [custom.mitre] : [],
          response: custom.response
            ? responseForCustom(custom.response.action, custom.response.target, event)
            : undefined
        });
      }
    }
    if (!hit && ioc) {
      hit = usable({
        ruleId: "intel-ioc",
        ruleName: `ioc:${ioc.kind}:${ioc.value}`,
        title: `Threat intel match (${ioc.kind}) ${ioc.value}`,
        severity: "high" as const,
        riskScore: 82,
        windowMinutes: 60,
        mitre: [{ id: "T1595", tactic: "Reconnaissance", technique: "Active Scanning" }]
      });
    }
    if (!hit && event.hostname && isSudoSuccess(event.message, event.appName)) {
      const opens = await this.db.listIncidents({ origin: event.origin });
      const prior = opens.find(
        (row) =>
          row.status === "open" &&
          row.ruleName.startsWith(`authburst:${event.hostname}`)
      );
      if (prior) {
        hit = usable({
          ruleId: "chain-priv",
          ruleName: `chain:auth-sudo:${event.hostname}`,
          title: `Kill chain: auth burst then sudo on ${event.hostname}`,
          severity: "critical" as const,
          riskScore: 92,
          windowMinutes: 15,
          mitre: [{ id: "T1548", tactic: "Privilege Escalation", technique: "Abuse Elevation Control" }]
        });
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
