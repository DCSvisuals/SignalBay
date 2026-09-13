import type { LogEvent } from "../types";

export type GroupWindow = "live" | "1m" | "5m" | "1h";

export interface LogGroup {
  id: string;
  count: number;
  latest: LogEvent;
  events: LogEvent[];
  hourKey: string;
  hourLabel: string;
}

const TS =
  /\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2}|[+-]\d{4})?/g;
const HEX = /\b0x[0-9a-fA-F]+\b/g;
const UUID = /\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b/g;

export function normalizeMessage(message: string): string {
  return message
    .replace(TS, "")
    .replace(HEX, "0x…")
    .replace(UUID, "uuid")
    .replace(/\s+/g, " ")
    .trim();
}

function pad(n: number): string {
  return String(n).padStart(2, "0");
}

export function timeBucket(iso: string, window: GroupWindow): { key: string; label: string } {
  const d = new Date(iso);
  const y = d.getFullYear();
  const mo = pad(d.getMonth() + 1);
  const day = pad(d.getDate());
  const h = d.getHours();
  const min = d.getMinutes();
  const hh = pad(h);

  if (window === "live") {
    const stamp = `${pad(h)}:${pad(min)}:${pad(d.getSeconds())}.${String(d.getMilliseconds()).padStart(3, "0")}`;
    return { key: iso, label: stamp };
  }
  if (window === "1m") {
    return { key: `${y}-${mo}-${day}T${hh}:${pad(min)}`, label: `${hh}h${pad(min)}` };
  }
  if (window === "5m") {
    const start = Math.floor(min / 5) * 5;
    const end = start + 4;
    return {
      key: `${y}-${mo}-${day}T${hh}:${pad(start)}`,
      label: `${hh}h${pad(start)}–${hh}h${pad(end)}`
    };
  }
  return { key: `${y}-${mo}-${day}T${hh}`, label: `${hh}h–${hh}h59` };
}

export function groupEventsByHour(events: LogEvent[], window: GroupWindow = "1h"): LogGroup[] {
  if (window === "live") {
    return events.map((event) => {
      const bucket = timeBucket(event.receivedAt, "live");
      return {
        id: `live-${event.id}`,
        count: 1,
        latest: event,
        events: [event],
        hourKey: bucket.key,
        hourLabel: bucket.label
      };
    });
  }

  const buckets = new Map<string, LogEvent[]>();
  for (const event of events) {
    const hour = timeBucket(event.receivedAt, window);
    const key = [
      hour.key,
      event.appName ?? "syslog",
      event.hostname ?? event.sourceIp ?? "",
      event.transport ?? "udp",
      event.severityLabel,
      normalizeMessage(event.message)
    ].join("|");
    const list = buckets.get(key);
    if (list) list.push(event);
    else buckets.set(key, [event]);
  }
  const groups: LogGroup[] = [];
  for (const [id, rows] of buckets) {
    rows.sort((a, b) => (a.receivedAt < b.receivedAt ? 1 : -1));
    const latest = rows[0];
    const hour = timeBucket(latest.receivedAt, window);
    groups.push({
      id,
      count: rows.length,
      latest,
      events: rows,
      hourKey: hour.key,
      hourLabel: hour.label
    });
  }
  groups.sort((a, b) => (a.latest.receivedAt < b.latest.receivedAt ? 1 : -1));
  return groups;
}
