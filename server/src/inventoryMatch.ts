const STOP = new Set([
  "app",
  "the",
  "for",
  "and",
  "inc",
  "llc",
  "ltd",
  "com",
  "server",
  "client",
  "agent",
  "manager",
  "helper",
  "update",
  "service",
  "system",
  "tools",
  "utility",
  "plugin",
  "software",
  "desktop",
  "version",
  "project",
  "unknown",
  "apple",
  "microsoft",
  "google"
]);

export interface InventoryVerdict {
  confidence: "high" | "medium";
}

function norm(value: string): string {
  return value.toLowerCase().replace(/[^a-z0-9]+/g, " ").trim();
}

function tokens(value: string): string[] {
  return norm(value)
    .split(" ")
    .filter((part) => part.length >= 4 && !STOP.has(part));
}

/** KEV has no affected-version field. Reject only when the title names a different major. */
function versionConflict(installed: string | null, text: string): boolean {
  if (!installed) return false;
  const major = installed.match(/\d+/)?.[0];
  const mentioned = [...text.matchAll(/\b(\d{1,3})\.\d+/g)].map((match) => match[1]);
  if (!major || mentioned.length === 0) return false;
  return mentioned.every((item) => item !== major);
}

export function matchInventory(
  appName: string,
  version: string | null,
  vendor: string,
  product: string,
  title: string
): InventoryVerdict | null {
  const app = norm(appName);
  const prod = norm(product);
  if (!app || !prod) return null;
  const blob = `${vendor} ${product} ${title}`;
  if (versionConflict(version, blob)) return null;

  if (app === prod) {
    if (STOP.has(prod) || prod.length < 4) return null;
    return { confidence: "high" };
  }
  const appIsSpecific = app.length >= 5 && !STOP.has(app);
  if (prod.length >= 4 && !STOP.has(prod) && (app.includes(prod) || (appIsSpecific && prod.includes(app)))) {
    return { confidence: prod.length >= 5 ? "high" : "medium" };
  }

  const prodTokens = tokens(product);
  if (prodTokens.length === 0) return null;
  const appTokens = new Set(app.split(" "));
  const allPresent = prodTokens.every((part) => appTokens.has(part) || app.includes(part));
  if (!allPresent) return null;
  if (prodTokens.length >= 2 || prodTokens[0].length >= 6) return { confidence: "high" };
  return { confidence: "medium" };
}
