import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import type { SiemDatabase } from "./database.js";
import type { EventOrigin, FimRecord } from "./types.js";

const MAX_FILES = 400;
const MAX_DEPTH = 3;
const MAX_BYTES = 8_000_000;

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

interface FileMeta {
  hash: string;
  size: number;
  mode: string;
  mtime: string;
}

function describe(file: string): FileMeta | null {
  try {
    const st = fs.statSync(file);
    if (!st.isFile() || st.size > MAX_BYTES) return null;
    return {
      hash: crypto.createHash("sha256").update(fs.readFileSync(file)).digest("hex"),
      size: st.size,
      mode: (st.mode & 0o777).toString(8),
      mtime: st.mtime.toISOString()
    };
  } catch {
    return null;
  }
}

function walk(target: string, depth: number, out: string[]): void {
  if (out.length >= MAX_FILES) return;
  let st: fs.Stats;
  try {
    st = fs.statSync(target);
  } catch {
    return;
  }
  if (st.isFile()) {
    out.push(target);
    return;
  }
  if (!st.isDirectory() || depth > MAX_DEPTH) return;
  let names: string[] = [];
  try {
    names = fs.readdirSync(target);
  } catch {
    return;
  }
  for (const name of names) {
    if (out.length >= MAX_FILES) return;
    walk(path.join(target, name), depth + 1, out);
  }
}

export async function scanFim(db: SiemDatabase, origin: EventOrigin): Promise<FimRecord[]> {
  const changes: FimRecord[] = [];
  for (const root of watchList()) {
    const files: string[] = [];
    walk(root, 0, files);
    for (const file of files) {
      const meta = describe(file);
      if (!meta) continue;
      const prev = await db.getFimFile(file);
      if (!prev) {
        await db.upsertFimFile({
          path: file,
          hash: meta.hash,
          status: "ok",
          origin,
          size: meta.size,
          mode: meta.mode,
          mtime: meta.mtime
        });
        continue;
      }
      if (prev.hash === meta.hash) {
        if (prev.mode !== meta.mode || prev.size !== meta.size) {
          await db.upsertFimFile({
            path: file,
            hash: meta.hash,
            status: "ok",
            origin,
            size: meta.size,
            mode: meta.mode,
            mtime: meta.mtime
          });
        }
        continue;
      }
      if (prev.hash !== meta.hash) {
        const rec = await db.upsertFimFile({
          path: file,
          hash: meta.hash,
          status: "changed",
          origin,
          previousHash: prev.hash,
          size: meta.size,
          mode: meta.mode,
          mtime: meta.mtime
        });
        changes.push(rec);
      }
    }
  }
  return changes;
}

export function startFimWatch(
  db: SiemDatabase,
  onChange: (records: FimRecord[]) => void
): () => void {
  const watchers: fs.FSWatcher[] = [];
  let pending: ReturnType<typeof setTimeout> | null = null;
  const schedule = () => {
    if (pending) clearTimeout(pending);
    pending = setTimeout(() => {
      void scanFim(db, "live").then(onChange).catch((err) => console.warn("[fim] scan failed", err));
    }, 400);
  };
  for (const root of watchList()) {
    try {
      const watcher = fs.watch(root, { persistent: false, recursive: true }, schedule);
      watchers.push(watcher);
    } catch {
      try {
        const watcher = fs.watch(root, { persistent: false }, schedule);
        watchers.push(watcher);
      } catch {
        /* path may be unreadable */
      }
    }
  }
  const timer = setInterval(() => {
    void scanFim(db, "live").then(onChange).catch(() => undefined);
  }, 60_000);
  void scanFim(db, "live").then(onChange).catch(() => undefined);
  return () => {
    clearInterval(timer);
    if (pending) clearTimeout(pending);
    for (const watcher of watchers) watcher.close();
  };
}
