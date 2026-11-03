import fs from "node:fs";
import path from "node:path";
import type { SiemDatabase } from "./database.js";
import { APP_SUPPORT, ensureAppSupport } from "./paths.js";

function backupDir(): string {
  const dir = path.join(APP_SUPPORT, "backups");
  fs.mkdirSync(dir, { recursive: true });
  return dir;
}

export async function backupDatabase(db: SiemDatabase): Promise<string> {
  ensureAppSupport();
  const dir = backupDir();
  const stamp = new Date().toISOString().replace(/[:.]/g, "-");
  const dest = path.join(dir, `siem-${stamp}.db`);
  await db.checkpointCopy(dest);
  const names = fs
    .readdirSync(dir)
    .filter((name) => name.startsWith("siem-") && name.endsWith(".db"))
    .sort();
  while (names.length > 5) {
    const oldest = names.shift();
    if (oldest) fs.unlinkSync(path.join(dir, oldest));
  }
  return dest;
}

export function latestBackupAgeMs(): number | null {
  const dir = path.join(APP_SUPPORT, "backups");
  if (!fs.existsSync(dir)) return null;
  const names = fs
    .readdirSync(dir)
    .filter((name) => name.startsWith("siem-") && name.endsWith(".db"))
    .sort();
  const latest = names[names.length - 1];
  if (!latest) return null;
  return Date.now() - fs.statSync(path.join(dir, latest)).mtimeMs;
}
