import fs from "node:fs";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import type { SiemDatabase } from "./database.js";
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
      if (!matchesInstalledProduct(item.name, vuln.vendor, vuln.product, vuln.title)) continue;
      hits.push(
        await db.insertInventoryHit({
          inventoryId: item.id,
          name: item.name,
          cve: vuln.cve,
          title: vuln.title
        })
      );
    }
  }
  return { items, hits };
}

function tokens(value: string): string[] {
  return value
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .filter((part) => part.length > 0);
}

function matchesInstalledProduct(
  appName: string,
  vendor: string,
  product: string,
  title: string
): boolean {
  const app = tokens(appName);
  if (app.length === 0) return false;
  const productTokens = tokens(product);
  const titleTokens = tokens(`${vendor} ${product}`);
  if (productTokens.length && app.every((part) => productTokens.includes(part))) return true;
  if (productTokens.length && productTokens.every((part) => app.includes(part)) && productTokens.join(" ").length >= 4) {
    return true;
  }
  const distinctive = app.filter((part) => part.length >= 5);
  if (distinctive.some((part) => productTokens.includes(part) || titleTokens.includes(part))) return true;
  return false;
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
