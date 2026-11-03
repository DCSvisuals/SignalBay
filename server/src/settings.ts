import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { APP_SUPPORT, ensureAppSupport } from "./paths.js";

export interface ExceptionRule {
  id: string;
  kind: "host" | "process" | "src_ip" | "rule";
  value: string;
  note: string;
  enabled: boolean;
}

export interface SiemSettings {
  retentionDays: number;
  maxEvents: number;
  webhookUrl: string;
  disabledRules: string[];
  exceptions: ExceptionRule[];
  lanToken: string;
}

const FILE = path.join(APP_SUPPORT, "siem-settings.json");

const DEFAULTS: SiemSettings = {
  retentionDays: 7,
  maxEvents: 200_000,
  webhookUrl: "",
  disabledRules: [],
  exceptions: [],
  lanToken: ""
};

let cached: { mtimeMs: number; settings: SiemSettings } | null = null;

function clampInt(value: unknown, fallback: number, min: number, max: number): number {
  const n = typeof value === "number" ? value : Number(value);
  if (!Number.isFinite(n)) return fallback;
  return Math.min(max, Math.max(min, Math.round(n)));
}

function cleanException(value: unknown): ExceptionRule | null {
  if (!value || typeof value !== "object") return null;
  const row = value as Partial<ExceptionRule>;
  const kind = row.kind;
  if (kind !== "host" && kind !== "process" && kind !== "src_ip" && kind !== "rule") return null;
  const target = typeof row.value === "string" ? row.value.trim() : "";
  if (!target || target.length > 200) return null;
  return {
    id: typeof row.id === "string" && row.id.trim() ? row.id.trim().slice(0, 40) : crypto.randomBytes(6).toString("hex"),
    kind,
    value: target,
    note: typeof row.note === "string" ? row.note.slice(0, 240) : "",
    enabled: row.enabled !== false
  };
}

export function normalizeSettings(input: Partial<SiemSettings> | null | undefined): SiemSettings {
  const webhook = typeof input?.webhookUrl === "string" ? input.webhookUrl.trim() : "";
  if (webhook && !/^https?:\/\//i.test(webhook)) {
    throw new Error("Webhook must start with http:// or https://");
  }
  const disabled = Array.isArray(input?.disabledRules)
    ? input.disabledRules.filter((id): id is string => typeof id === "string" && id.trim().length > 0).map((id) => id.trim()).slice(0, 200)
    : [];
  const exceptions = Array.isArray(input?.exceptions)
    ? input.exceptions.map(cleanException).filter((row): row is ExceptionRule => Boolean(row)).slice(0, 200)
    : [];
  return {
    retentionDays: clampInt(input?.retentionDays, DEFAULTS.retentionDays, 1, 90),
    maxEvents: clampInt(input?.maxEvents, DEFAULTS.maxEvents, 1_000, 2_000_000),
    webhookUrl: webhook.slice(0, 500),
    disabledRules: disabled,
    exceptions,
    lanToken: typeof input?.lanToken === "string" && input.lanToken.trim() ? input.lanToken.trim() : ""
  };
}

export function getSettings(): SiemSettings {
  ensureAppSupport();
  if (!fs.existsSync(FILE)) {
    const settings = { ...DEFAULTS, exceptions: [], disabledRules: [] };
    fs.writeFileSync(FILE, `${JSON.stringify(settings, null, 2)}\n`);
    cached = { mtimeMs: fs.statSync(FILE).mtimeMs, settings };
    return settings;
  }
  const mtimeMs = fs.statSync(FILE).mtimeMs;
  if (cached && cached.mtimeMs === mtimeMs) return cached.settings;
  try {
    const settings = normalizeSettings(JSON.parse(fs.readFileSync(FILE, "utf8")) as Partial<SiemSettings>);
    cached = { mtimeMs, settings };
    return settings;
  } catch (err) {
    if (err instanceof Error && err.message.startsWith("Webhook")) throw err;
    return { ...DEFAULTS, exceptions: [], disabledRules: [] };
  }
}

export function saveSettings(patch: Partial<SiemSettings>): SiemSettings {
  const next = normalizeSettings({ ...getSettings(), ...patch });
  ensureAppSupport();
  fs.writeFileSync(FILE, `${JSON.stringify(next, null, 2)}\n`);
  cached = { mtimeMs: fs.statSync(FILE).mtimeMs, settings: next };
  return next;
}

export function ensureLanToken(): string {
  const current = getSettings();
  if (current.lanToken) return current.lanToken;
  const lanToken = crypto.randomBytes(18).toString("hex");
  saveSettings({ lanToken });
  return lanToken;
}

export function isRuleEnabled(ruleId: string): boolean {
  return !getSettings().disabledRules.includes(ruleId);
}

export function isSuppressed(
  event: {
    hostname?: string | null;
    appName?: string | null;
    sourceIp?: string | null;
    srcIp?: string | null;
  },
  ruleId: string,
  exceptions: ExceptionRule[] = getSettings().exceptions
): boolean {
  for (const rule of exceptions) {
    if (!rule.enabled || !rule.value) continue;
    const value = rule.value.trim().toLowerCase();
    if (rule.kind === "host" && (event.hostname ?? "").toLowerCase() === value) return true;
    if (rule.kind === "process" && (event.appName ?? "").toLowerCase() === value) return true;
    if (rule.kind === "src_ip") {
      const src = (event.srcIp || event.sourceIp || "").toLowerCase();
      if (src === value) return true;
    }
    if (rule.kind === "rule" && (ruleId.toLowerCase() === value || ruleId.toLowerCase().startsWith(`${value}:`))) {
      return true;
    }
  }
  return false;
}
