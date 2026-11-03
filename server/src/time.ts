const MONTHS: Record<string, number> = {
  jan: 0,
  feb: 1,
  mar: 2,
  apr: 3,
  may: 4,
  jun: 5,
  jul: 6,
  aug: 7,
  sep: 8,
  oct: 9,
  nov: 10,
  dec: 11
};

function sane(ms: number, receivedAt: Date): boolean {
  return Math.abs(ms - receivedAt.getTime()) < 370 * 24 * 60 * 60 * 1000;
}

/** Syslog event time. RFC 3164 has no zone, so it is read in the Mac's local time. */
export function parseSyslogTimestamp(value: string | null | undefined, receivedAt = new Date()): string {
  if (!value || value === "-") return receivedAt.toISOString();
  const trimmed = value.trim();
  const direct = Date.parse(trimmed);
  if (!Number.isNaN(direct) && sane(direct, receivedAt)) return new Date(direct).toISOString();

  const match = trimmed.match(/^([A-Za-z]{3})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})$/);
  if (!match) return receivedAt.toISOString();
  const month = MONTHS[match[1].toLowerCase()];
  if (month === undefined) return receivedAt.toISOString();
  const day = Number(match[2]);
  const hour = Number(match[3]);
  const minute = Number(match[4]);
  const second = Number(match[5]);
  let year = receivedAt.getFullYear();
  let stamp = new Date(year, month, day, hour, minute, second);
  if (stamp.getTime() - receivedAt.getTime() > 26 * 60 * 60 * 1000) {
    year -= 1;
    stamp = new Date(year, month, day, hour, minute, second);
  }
  if (!sane(stamp.getTime(), receivedAt)) return receivedAt.toISOString();
  return stamp.toISOString();
}
