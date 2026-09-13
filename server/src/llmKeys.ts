import fs from "node:fs";
import path from "node:path";
import { APP_SUPPORT, ensureAppSupport } from "./paths.js";

export type CloudProvider = "openai" | "anthropic" | "google" | "xai";

export type KeyStore = Partial<Record<CloudProvider, string>> & {
  openaiModel?: string;
  anthropicModel?: string;
  googleModel?: string;
  xaiModel?: string;
};

const DEFAULT_MODELS: Record<CloudProvider, string> = {
  openai: "gpt-4o",
  anthropic: "claude-sonnet-4-5",
  google: "gemini-2.0-flash",
  xai: "grok-4.6"
};

export interface ProviderStatus {
  configured: boolean;
  hint: string | null;
}

const KEY_FILE = path.join(APP_SUPPORT, "llm-keys.json");

const ENV_MAP: Record<CloudProvider, string[]> = {
  openai: ["OPENAI_API_KEY"],
  anthropic: ["ANTHROPIC_API_KEY"],
  google: ["GEMINI_API_KEY", "GOOGLE_API_KEY"],
  xai: ["XAI_API_KEY"]
};

function mask(value: string): string {
  const trimmed = value.trim();
  if (trimmed.length < 8) return "••••";
  return `${trimmed.slice(0, 3)}…${trimmed.slice(-4)}`;
}

function readFileStore(): KeyStore {
  try {
    const raw = fs.readFileSync(KEY_FILE, "utf8");
    const parsed = JSON.parse(raw) as KeyStore;
    return parsed && typeof parsed === "object" ? parsed : {};
  } catch {
    return {};
  }
}

export function getCloudModel(provider: CloudProvider, fallback?: string): string {
  const store = readFileStore();
  if (provider === "openai" && store.openaiModel?.trim()) return store.openaiModel.trim();
  if (provider === "anthropic" && store.anthropicModel?.trim()) return store.anthropicModel.trim();
  if (provider === "google" && store.googleModel?.trim()) return store.googleModel.trim();
  if (provider === "xai" && store.xaiModel?.trim()) return store.xaiModel.trim();
  return fallback?.trim() || DEFAULT_MODELS[provider];
}

export function getKey(provider: CloudProvider): string | null {
  const stored = readFileStore()[provider]?.trim();
  if (stored) return stored;
  for (const envName of ENV_MAP[provider]) {
    const fromEnv = process.env[envName]?.trim();
    if (fromEnv) return fromEnv;
  }
  return null;
}

export function providerStatus(provider: CloudProvider): ProviderStatus {
  const key = getKey(provider);
  return {
    configured: Boolean(key),
    hint: key ? mask(key) : null
  };
}

export function allProviderStatus(): Record<CloudProvider, ProviderStatus> {
  return {
    openai: providerStatus("openai"),
    anthropic: providerStatus("anthropic"),
    google: providerStatus("google"),
    xai: providerStatus("xai")
  };
}

export function saveKeys(patch: KeyStore): Record<CloudProvider, ProviderStatus> {
  ensureAppSupport();
  const next: KeyStore = { ...readFileStore() };
  for (const provider of ["openai", "anthropic", "google", "xai"] as CloudProvider[]) {
    if (!(provider in patch)) continue;
    const value = patch[provider]?.trim() ?? "";
    if (!value) delete next[provider];
    else next[provider] = value;
  }
  for (const field of ["openaiModel", "anthropicModel", "googleModel", "xaiModel"] as const) {
    if (!(field in patch)) continue;
    const value = patch[field]?.trim() ?? "";
    if (!value) delete next[field];
    else next[field] = value;
  }
  fs.writeFileSync(KEY_FILE, `${JSON.stringify(next, null, 2)}\n`, { mode: 0o600 });
  try {
    fs.chmodSync(KEY_FILE, 0o600);
  } catch {
    /* ignore */
  }
  return allProviderStatus();
}
