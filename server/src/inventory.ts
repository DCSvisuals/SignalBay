import fs from "node:fs";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import type { SiemDatabase } from "./database.js";
import { matchInventory } from "./inventoryMatch.js";
import type { InventoryHit, InventoryItem } from "./types.js";

const execFileAsync = promisify(execFile);

async function readAppVersion(appPath: string): Promise<string | null> {
  try {
    const { stdout } = await execFileAsync(
      "defaults",
      ["read", `${appPath}/Contents/Info`, "CFBundleShortVersionString"],
      { timeout: 2500 }
    );
    const version = stdout.trim();
    return version || null;
  } catch {
    return null;
  }
}

export async function collectInventory(db: SiemDatabase): Promise<{
  items: InventoryItem[];
  hits: InventoryHit[];
}> {
  const names = new Map<string, { version: string | null; path: string | null }>();
  try {
    for (const name of fs.readdirSync("/Applications")) {
      if (!name.endsWith(".app")) continue;
      const appPath = `/Applications/${name}`;
      names.set(name.replace(/\.app$/i, ""), {
        version: await readAppVersion(appPath),
        path: appPath
      });
    }
  } catch {
    /* ignore */
  }
  try {
    const { stdout } = await execFileAsync("brew", ["list", "--versions"], { timeout: 8000 });
    for (const line of stdout.split("\n")) {
      const [pkg, version] = line.trim().split(/\s+/);
      if (pkg) names.set(pkg, { version: version ?? null, path: null });
    }
  } catch {
    /* brew optional */
  }

  const items: InventoryItem[] = [];
  for (const [name, meta] of names) {
    items.push(await db.upsertInventory({ name, version: meta.version, path: meta.path }));
  }
  await db.clearInventoryHits();
  const kev = await db.listKevCatalog();
  const hits: InventoryHit[] = [];
  for (const item of items) {
    for (const vuln of kev) {
      const verdict = matchInventory(item.name, item.version, vuln.vendor, vuln.product, vuln.title);
      if (!verdict) continue;
      hits.push(
        await db.insertInventoryHit({
          inventoryId: item.id,
          name: item.name,
          cve: vuln.cve,
          title: vuln.title,
          confidence: verdict.confidence,
          installedVersion: item.version
        })
      );
    }
  }
  return { items, hits };
}

export function startInventoryLoop(
  db: SiemDatabase,
  onScan: (result: { items: InventoryItem[]; hits: InventoryHit[] }) => void
): () => void {
  const run = () => {
    void collectInventory(db).then(onScan).catch((err) => console.warn("[inventory]", err));
  };
  run();
  const timer = setInterval(run, 30 * 60 * 1000);
  return () => clearInterval(timer);
}
