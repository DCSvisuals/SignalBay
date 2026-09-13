import { execFileSync } from "node:child_process";
import os from "node:os";

export function computerName(): string {
  try {
    const name = execFileSync("scutil", ["--get", "LocalHostName"], {
      encoding: "utf8"
    }).trim();
    if (name) return name;
  } catch {
    /* ignore */
  }
  return os.hostname().split(".")[0] || "localhost";
}

export function localIpv4s(): string[] {
  const found = new Set<string>(["127.0.0.1"]);
  const ifaces = os.networkInterfaces();
  for (const rows of Object.values(ifaces)) {
    for (const row of rows ?? []) {
      if (row.family === "IPv4" && row.address) found.add(row.address);
    }
  }
  return [...found];
}
