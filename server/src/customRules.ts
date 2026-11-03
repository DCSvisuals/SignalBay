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
  response?: {
    action: "block_ip" | "kill_pid" | "quarantine";
    target?: string;
  };
}

interface CompiledRule extends CustomRule {
  re: RegExp | null;
}

const FILE = path.join(APP_SUPPORT, "custom-rules.json");
const SEVERITIES = new Set(["critical", "high", "medium", "low", "info"]);

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

let cached: { mtimeMs: number; rules: CompiledRule[] } | null = null;

function compile(rule: CustomRule): CompiledRule {
  try {
    return { ...rule, re: new RegExp(rule.pattern, "i") };
  } catch {
    return { ...rule, re: null };
  }
}

export function invalidateCustomRules(): void {
  cached = null;
}

export function loadCustomRules(): CustomRule[] {
  ensureAppSupport();
  if (!fs.existsSync(FILE)) {
    fs.writeFileSync(FILE, `${JSON.stringify(SAMPLE, null, 2)}\n`);
    cached = { mtimeMs: fs.statSync(FILE).mtimeMs, rules: SAMPLE.map(compile) };
    return SAMPLE;
  }
  const mtimeMs = fs.statSync(FILE).mtimeMs;
  if (cached && cached.mtimeMs === mtimeMs) {
    return cached.rules.map(({ re: _re, ...rule }) => rule);
  }
  try {
    const parsed = JSON.parse(fs.readFileSync(FILE, "utf8")) as CustomRule[];
    const rules = Array.isArray(parsed) ? parsed : SAMPLE;
    cached = { mtimeMs, rules: rules.map(compile) };
    return rules;
  } catch {
    return SAMPLE;
  }
}

export function validateCustomRules(rules: CustomRule[]): string | null {
  if (!Array.isArray(rules)) return "Rules must be a JSON array";
  for (const rule of rules) {
    if (!rule || typeof rule.pattern !== "string" || !rule.pattern.trim()) return "Each rule needs a pattern";
    if (!SEVERITIES.has(rule.severity)) return `Unknown severity on ${rule.id || rule.name}`;
    try {
      new RegExp(rule.pattern, "i");
    } catch (err) {
      return `Bad regex on ${rule.name || rule.id}: ${err instanceof Error ? err.message : "invalid"}`;
    }
    if (rule.response && !["block_ip", "kill_pid", "quarantine"].includes(rule.response.action)) {
      return `Unknown response action on ${rule.name || rule.id}`;
    }
  }
  return null;
}

export function saveCustomRules(rules: CustomRule[]): CustomRule[] {
  const problem = validateCustomRules(rules);
  if (problem) throw new Error(problem);
  ensureAppSupport();
  fs.writeFileSync(FILE, `${JSON.stringify(rules, null, 2)}\n`);
  invalidateCustomRules();
  return loadCustomRules();
}

export function matchCustomRule(event: LogEvent): CustomRule | null {
  loadCustomRules();
  const blob = `${event.appName ?? ""} ${event.message} ${event.hostname ?? ""}`;
  for (const rule of cached?.rules ?? []) {
    if (!rule.enabled || !rule.re) continue;
    if (rule.re.test(blob)) {
      const { re: _re, ...plain } = rule;
      return plain;
    }
  }
  return null;
}
