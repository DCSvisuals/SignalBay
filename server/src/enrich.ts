import { localIpv4s } from "./host.js";
import { isLoopback } from "./netguard.js";

const IP = /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d{1,2})\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d{1,2})\b/;
const USER = /\b(?:user|for|account)[=: ]+([A-Za-z0-9._-]+)/i;
const UNTRUSTED_PATH = /(?:\/private\/tmp\/|\/tmp\/|\/Downloads\/|\/\.[A-Za-z0-9_-]+\/)/;

export function ipScope(ip: string | null | undefined): "loopback" | "self" | "private" | "public" | "unknown" {
  if (!ip) return "unknown";
  if (isLoopback(ip) || ip === "demo") return "loopback";
  if (localIpv4s().includes(ip)) return "self";
  const p = ip.split(".").map(Number);
  if (p.length === 4 && (p[0] === 10 || (p[0] === 192 && p[1] === 168) || (p[0] === 172 && p[1] >= 16 && p[1] <= 31))) {
    return "private";
  }
  if (p.length === 4 && p.every((n) => n <= 255)) return "public";
  return "unknown";
}

export function eventCategory(message: string, appName: string | null): string {
  const blob = `${appName ?? ""} ${message}`.toLowerCase();
  if (/failed password|invalid user|accepted (password|publickey)|sudo|authentication/.test(blob)) return "auth";
  if (/file changed|fim/.test(blob)) return "fim";
  if (/xprotect|gatekeeper|malware|ransomware|cve-|exploit/.test(blob)) return "threat";
  if (/pf:|firewall|dropped|socketfilterfw/.test(blob)) return "network";
  return "host";
}

export function eventAction(message: string, appName: string | null): string {
  const blob = `${appName ?? ""} ${message}`;
  if (/accepted (password|publickey)|session opened for user/i.test(message)) return "login_success";
  if (/failed password|invalid user|authentication failure|incorrect password|wrong password/i.test(message)) {
    return /sudo/i.test(blob) ? "sudo_failure" : "login_failure";
  }
  if (/sudo:/i.test(blob) && /COMMAND=/i.test(message) && !/incorrect|failure|sorry/i.test(message)) {
    return "sudo_success";
  }
  if (/xprotect|gatekeeper|malware detected|code signature invalid/i.test(blob)) return "malware_block";
  if (/(?:^|\s)pf:|firewall|socketfilterfw/i.test(blob) && /\b(dropped|deny|denied|blocked|block)\b/i.test(message)) {
    return "firewall_deny";
  }
  if (/file changed/i.test(message) || appName === "fim") return "fim_change";
  if (UNTRUSTED_PATH.test(message)) return "exec_untrusted";
  return "observe";
}

export function enrichParsed(input: {
  message: string;
  appName: string | null;
  hostname: string | null;
  sourceIp: string | null;
}): Record<string, unknown> {
  const extractedIp = input.message.match(IP)?.[0] ?? input.sourceIp;
  const user = input.message.match(USER)?.[1] ?? null;
  const action = eventAction(input.message, input.appName);
  return {
    normalized: true,
    src_ip: extractedIp,
    ip_scope: ipScope(extractedIp),
    entity: input.hostname,
    user,
    category: eventCategory(input.message, input.appName),
    action,
    asset_criticality: input.hostname ? "lab-host" : "unknown"
  };
}
