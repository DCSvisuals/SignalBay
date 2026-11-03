import type { SiemDatabase } from "./database.js";
import { isLoopback } from "./netguard.js";
import type { IocRecord, LogEvent } from "./types.js";

export interface IocLike {
  kind: string;
  value: string;
  expiresAt?: string | null;
}

let cache: IocRecord[] | null = null;

export function invalidateIocCache(): void {
  cache = null;
}

export function validateIoc(kind: string, value: string): string | null {
  const trimmed = value.trim();
  if (kind === "ip") {
    if (isLoopback(trimmed)) return "Loopback is not an IOC";
    if (!/^(?:\d{1,3}\.){3}\d{1,3}$/.test(trimmed)) return "Enter a dotted IPv4 address";
    if (trimmed.split(".").map(Number).some((n) => n > 255)) return "Invalid IPv4 address";
    return null;
  }
  if (kind === "domain") {
    if (!/^(?=.{4,253}$)(?:[a-z0-9-]+\.)+[a-z]{2,}$/i.test(trimmed)) {
      return "Enter a domain like evil.example";
    }
    return null;
  }
  if (kind === "hash") {
    if (!/^[a-f0-9]{32,128}$/i.test(trimmed)) return "Hash must be 32 to 128 hex characters";
    return null;
  }
  if (trimmed.length < 6) return "Value must be at least 6 characters";
  return null;
}

function escapeReg(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

export function findIoc(
  iocs: IocLike[],
  input: { sourceIp?: string | null; srcIp?: string | null; message: string; hostname?: string | null }
): IocLike | null {
  const now = Date.now();
  const message = input.message.toLowerCase();
  const ips = new Set(
    [input.sourceIp, input.srcIp].filter((ip): ip is string => Boolean(ip)).map((ip) => ip.toLowerCase())
  );
  for (const ioc of iocs) {
    if (ioc.expiresAt && Date.parse(ioc.expiresAt) < now) continue;
    const value = ioc.value.trim().toLowerCase();
    if (!value) continue;
    if (ioc.kind === "ip") {
      if (ips.has(value)) return ioc;
      const re = new RegExp(`(?:^|[^\\d])${escapeReg(value)}(?:[^\\d]|$)`);
      if (re.test(message)) return ioc;
      continue;
    }
    if (ioc.kind === "hash") {
      if (!/^[a-f0-9]{32,128}$/.test(value)) continue;
      if (message.includes(value)) return ioc;
      continue;
    }
    if (ioc.kind === "domain") {
      if (value.length < 4 || !value.includes(".")) continue;
      const re = new RegExp(`(^|[^a-z0-9.-])${escapeReg(value)}([^a-z0-9.-]|$)`, "i");
      if (re.test(input.message) || (input.hostname ?? "").toLowerCase() === value) return ioc;
      continue;
    }
    if (value.length < 6) continue;
    const re = new RegExp(`(^|[^a-z0-9])${escapeReg(value)}([^a-z0-9]|$)`, "i");
    if (re.test(input.message)) return ioc;
  }
  return null;
}

export async function matchIoc(
  db: SiemDatabase,
  event: LogEvent
): Promise<{ value: string; kind: string } | null> {
  if (!cache) cache = await db.listIocs();
  const hit = findIoc(cache, {
    sourceIp: event.sourceIp,
    srcIp: event.srcIp,
    message: event.message,
    hostname: event.hostname
  });
  return hit ? { value: hit.value, kind: hit.kind } : null;
}
