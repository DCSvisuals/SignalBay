import { localIpv4s } from "./host.js";
import { isLoopback } from "./netguard.js";

const IP = /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d{1,2})\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d{1,2})\b/;
const USER = /\b(?:user|for|account)[=: ]+([A-Za-z0-9._-]+)/i;

export function ipScope(ip: string | null | undefined): "loopback" | "self" | "private" | "public" | "unknown" {
  if (!ip) return "unknown";
  if (isLoopback(ip) || ip === "demo") return "loopback";
  if (localIpv4s().includes(ip)) return "self";
  const p = ip.split(".").map(Number);
  if (p.length === 4 && (p[0] === 10 || (p[0] === 192 && p[1] === 168) || (p[0] === 172 && p[1] >= 16 && p[1] <= 31))) {
    return "private";
  }
  if (p.length === 4) return "public";
  return "unknown";
}

export function eventCategory(message: string, appName: string | null): string {
  const blob = `${appName ?? ""} ${message}`.toLowerCase();
  if (/failed password|invalid user|sudo|authentication/.test(blob)) return "auth";
  if (/file changed|fim/.test(blob)) return "fim";
  if (/cve-|ransomware|exploit/.test(blob)) return "threat";
  if (/pf:|firewall|dropped/.test(blob)) return "network";
  return "host";
}

export function enrichParsed(input: {
  message: string;
  appName: string | null;
  hostname: string | null;
  sourceIp: string | null;
}): Record<string, unknown> {
  const extractedIp = input.message.match(IP)?.[0] ?? input.sourceIp;
  const user = input.message.match(USER)?.[1] ?? null;
  return {
    normalized: true,
    src_ip: extractedIp,
    ip_scope: ipScope(extractedIp),
    entity: input.hostname,
    user,
    category: eventCategory(input.message, input.appName),
    asset_criticality: input.hostname ? "lab-host" : "unknown"
  };
}
