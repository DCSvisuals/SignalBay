import { localIpv4s } from "./host.js";

const V4 = /^(?:\d{1,3}\.){3}\d{1,3}$/;

export function isLoopback(ip: string): boolean {
  return ip === "127.0.0.1" || ip.startsWith("127.") || ip === "::1" || ip === "localhost";
}

export function isBlockableIp(ip: string | null | undefined): ip is string {
  if (!ip || ip === "demo" || ip === "0.0.0.0" || ip === "255.255.255.255") return false;
  if (!V4.test(ip)) return false;
  const parts = ip.split(".").map(Number);
  if (parts.some((n) => n > 255)) return false;
  if (isLoopback(ip)) return false;
  if (parts[0] === 169 && parts[1] === 254) return false;
  if (parts[0] >= 224) return false;
  if (localIpv4s().includes(ip)) return false;
  return true;
}

export function ingestAllowed(ip: string): boolean {
  const extra = (process.env.SYSLOG_ALLOW ?? "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
  if (extra.includes("*")) return true;
  if (extra.includes(ip)) return true;
  if (isLoopback(ip) || ip === "demo") return true;
  if (localIpv4s().includes(ip)) return true;
  const parts = ip.split(".").map(Number);
  if (parts.length === 4 && parts[0] === 10) return true;
  if (parts.length === 4 && parts[0] === 192 && parts[1] === 168) return true;
  if (parts.length === 4 && parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;
  return false;
}
