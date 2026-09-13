import fs from "node:fs";
import path from "node:path";
import { APP_SUPPORT, ensureAppSupport } from "./paths.js";
import type { LogEvent, SeverityLabel } from "./types.js";

export interface CustomRule {
  id: string;
  name: string;
  pattern: string;
  severity: SeverityLabel;
  riskScore: number;
  enabled: boolean;
  mitre?: { id: string; tactic: string; technique: string };
}

const FILE = path.join(APP_SUPPORT, "custom-rules.json");

const SAMPLE: CustomRule[] = [
  {
    id: "lab-nmap",
    name: "Scanner strings",
    pattern: "nmap|masscan|nuclei",
    severity: "medium",
    riskScore: 55,
    enabled: true,
    mitre: { id: "T1046", tactic: "Discovery", technique: "Network Service Discovery" }
  }
];

export function loadCustomRules(): CustomRule[] {
  ensureAppSupport();
  if (!fs.existsSync(FILE)) {
    fs.writeFileSync(FILE, `${JSON.stringify(SAMPLE, null, 2)}\n`);
    return SAMPLE;
  }
  try {
    const parsed = JSON.parse(fs.readFileSync(FILE, "utf8")) as CustomRule[];
    return Array.isArray(parsed) ? parsed : SAMPLE;
  } catch {
    return SAMPLE;
  }
}

export function saveCustomRules(rules: CustomRule[]): CustomRule[] {
  ensureAppSupport();
  fs.writeFileSync(FILE, `${JSON.stringify(rules, null, 2)}\n`);
  return loadCustomRules();
}

export function matchCustomRule(event: LogEvent): CustomRule | null {
  const blob = `${event.appName ?? ""} ${event.message} ${event.hostname ?? ""}`;
  for (const rule of loadCustomRules()) {
    if (!rule.enabled || !rule.pattern) continue;
    try {
      if (new RegExp(rule.pattern, "i").test(blob)) return rule;
    } catch {
      continue;
    }
  }
  return null;
}
