import fs from "node:fs";
import os from "node:os";
import path from "node:path";

export const APP_SUPPORT = path.join(
  os.homedir(),
  "Library",
  "Application Support",
  "LocalSIEM"
);

export const DB_PATH = path.join(APP_SUPPORT, "siem_enterprise.db");
export const MODELS_DIR = path.join(APP_SUPPORT, "models");

export function ensureAppSupport(): void {
  fs.mkdirSync(APP_SUPPORT, { recursive: true });
  fs.mkdirSync(MODELS_DIR, { recursive: true });
}
