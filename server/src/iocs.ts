import type { SiemDatabase } from "./database.js";
import type { LogEvent } from "./types.js";

export async function matchIoc(db: SiemDatabase, event: LogEvent): Promise<{ value: string; kind: string } | null> {
  const iocs = await db.listIocs();
  if (iocs.length === 0) return null;
  const blob = `${event.sourceIp ?? ""} ${event.message} ${event.hostname ?? ""}`.toLowerCase();
  for (const ioc of iocs) {
    if (ioc.value && blob.includes(ioc.value.toLowerCase())) {
      return { value: ioc.value, kind: ioc.kind };
    }
  }
  return null;
}
