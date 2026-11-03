import { parseSyslogTimestamp } from "./time.js";

const SYSLOG_PRI = /^<(\d{1,3})>/;
const RFC5424 =
  /^<(\d{1,3})>(\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(-|(?:\[.*?\]\s*)+)\s*(.*)$/s;
const RFC3164 =
  /^<(\d{1,3})>([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+([^:\s]+)(?:\[([^\]]+)\])?:\s*(.*)$/s;

export interface ParsedDraft {
  receivedAt: string;
  eventTime: string;
  facility: number | null;
  severity: number | null;
  hostname: string | null;
  appName: string | null;
  procId: string | null;
  message: string;
  raw: string;
  sourceIp: string | null;
  parsed: Record<string, unknown>;
}

export function parseEventPayload(
  raw: string,
  rinfo: { address: string; port: number },
  receivedAt = new Date()
): ParsedDraft {
  const receivedIso = receivedAt.toISOString();
  const sourceIp = rinfo.address;
  const jsonAttempt = tryParseJson(raw);
  if (jsonAttempt) {
    const message = String(jsonAttempt.message ?? jsonAttempt.msg ?? jsonAttempt.event ?? raw);
    const severity =
      typeof jsonAttempt.severity === "number"
        ? jsonAttempt.severity
        : typeof jsonAttempt.level === "number"
          ? jsonAttempt.level
          : null;
    const stamp = strOrNull(jsonAttempt.timestamp ?? jsonAttempt.time ?? jsonAttempt.ts);
    return {
      receivedAt: receivedIso,
      eventTime: parseSyslogTimestamp(stamp, receivedAt),
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
      receivedAt: receivedIso,
      eventTime: parseSyslogTimestamp(rfc5424[3], receivedAt),
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
      receivedAt: receivedIso,
      eventTime: parseSyslogTimestamp(rfc3164[2], receivedAt),
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
    receivedAt: receivedIso,
    eventTime: receivedIso,
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

export function liftInnerProcess<T extends ParsedDraft>(parsed: T): T {
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
