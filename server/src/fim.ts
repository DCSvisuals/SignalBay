import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import type { SiemDatabase } from "./database.js";
import type { EventOrigin, FimRecord } from "./types.js";

function watchList(): string[] {
  const home = os.homedir();
  return [
    "/etc/hosts",
    "/etc/ssh/sshd_config",
    "/Library/LaunchDaemons",
    "/Library/LaunchAgents",
    path.join(home, "Library/LaunchAgents")
  ];
}

function hashFile(file: string): string | null {
  try {
    const st = fs.statSync(file);
    if (!st.isFile() || st.size > 8_000_000) return null;
    return crypto.createHash("sha256").update(fs.readFileSync(file)).digest("hex");
  } catch {
    return null;
  }
}

function listFiles(target: string): string[] {
  try {
    const st = fs.statSync(target);
    if (st.isFile()) return [target];
    if (!st.isDirectory()) return [];
    return fs
      .readdirSync(target)
      .slice(0, 80)
      .map((name) => path.join(target, name))
      .filter((file) => {
        try {
          return fs.statSync(file).isFile();
        } catch {
          return false;
        }
      });
  } catch {
    return [];
  }
}

export async function scanFim(db: SiemDatabase, origin: EventOrigin): Promise<FimRecord[]> {
  const changes: FimRecord[] = [];
  for (const root of watchList()) {
    for (const file of listFiles(root)) {
      const hash = hashFile(file);
      const prev = await db.getFimFile(file);
      if (!hash) continue;
      if (!prev) {
        const rec = await db.upsertFimFile({
          path: file,
          hash,
          status: "ok",
          origin
        });
        changes.push(rec);
        continue;
      }
      if (prev.hash !== hash) {
        const rec = await db.upsertFimFile({
          path: file,
          hash,
          status: "changed",
          origin,
          previousHash: prev.hash
        });
        changes.push(rec);
      }
    }
  }
  return changes.filter((row) => row.status === "changed");
}

export function startFimWatch(
  db: SiemDatabase,
  onChange: (records: FimRecord[]) => void
): () => void {
  const watchers: fs.FSWatcher[] = [];
  for (const root of watchList()) {
    try {
      const watcher = fs.watch(root, { persistent: false }, () => {
        void scanFim(db, "live").then(onChange).catch((err) => {
          console.warn("[fim] scan failed", err);
        });
      });
      watchers.push(watcher);
    } catch {
      /* path may be unreadable */
    }
  }
  const timer = setInterval(() => {
    void scanFim(db, "live").then(onChange).catch(() => undefined);
  }, 60_000);
  void scanFim(db, "live").then(onChange).catch(() => undefined);
  return () => {
    clearInterval(timer);
    for (const watcher of watchers) watcher.close();
  };
}
