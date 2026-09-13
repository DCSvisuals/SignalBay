import { ChevronDown, X } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import type { LogEvent } from "../types";

interface Props {
  event: LogEvent;
  events: LogEvent[];
  hourCopies?: LogEvent[];
  hourLabel?: string;
  onClose: () => void;
}

const FACILITY: Record<number, string> = {
  0: "kern",
  1: "user",
  2: "mail",
  3: "daemon",
  4: "auth",
  5: "syslog",
  6: "lpr",
  7: "news",
  8: "uucp",
  9: "cron",
  10: "authpriv",
  11: "ftp",
  16: "local0",
  17: "local1",
  18: "local2",
  19: "local3"
};

export function LogProcessPopup({ event, events, hourCopies = [], hourLabel, onClose }: Props) {
  const processName = event.appName ?? "syslog";
  const [hourOpen, setHourOpen] = useState(hourCopies.length > 1);
  const related = useMemo(
    () =>
      events
        .filter(
          (row) =>
            row.id !== event.id &&
            (row.appName ?? "syslog") === processName &&
            (row.hostname ?? "") === (event.hostname ?? "")
        )
        .slice(0, 8),
    [events, event, processName]
  );

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  const facility =
    event.facility === null
      ? "—"
      : `${event.facility} (${FACILITY[event.facility] ?? "other"})`;

  return (
    <div className="popup-overlay" onClick={onClose} role="presentation">
      <div
        className="popup-card"
        role="dialog"
        aria-modal="true"
        aria-labelledby="process-popup-title"
        onClick={(e) => e.stopPropagation()}
      >
        <header className="popup-head">
          <div>
            <p className="popup-kicker">Process detail</p>
            <h3 id="process-popup-title">
              {processName}
              {event.procId ? <span className="pid">pid {event.procId}</span> : null}
            </h3>
          </div>
          <button className="ghost" onClick={onClose} aria-label="Close">
            <X size={14} />
          </button>
        </header>

        <div className="popup-meta">
          <span className={`sev ${event.severityLabel}`}>{event.severityLabel}</span>
          <span className="chip">{(event.transport ?? "udp").toUpperCase()}</span>
          <span className="chip">{event.hostname ?? event.sourceIp ?? "unknown host"}</span>
          <span className="chip">{formatFull(event.receivedAt)}</span>
          {hourCopies.length > 1 ? (
            <span className="chip">
              ×{hourCopies.length} in {hourLabel ?? "this hour"}
            </span>
          ) : null}
        </div>

        <dl className="popup-fields">
          <div>
            <dt>Host</dt>
            <dd>{event.hostname ?? "—"}</dd>
          </div>
          <div>
            <dt>Source IP</dt>
            <dd>{event.sourceIp ?? "—"}</dd>
          </div>
          <div>
            <dt>Transport</dt>
            <dd>{(event.transport ?? "udp").toUpperCase()}</dd>
          </div>
          <div>
            <dt>Facility</dt>
            <dd>{facility}</dd>
          </div>
          <div>
            <dt>Syslog severity</dt>
            <dd>
              {event.severity ?? "—"} · {event.severityLabel}
            </dd>
          </div>
          <div className="wide">
            <dt>Message</dt>
            <dd className="wrap">{event.message}</dd>
          </div>
          <div className="wide">
            <dt>Raw syslog</dt>
            <dd>
              <pre>{event.raw}</pre>
            </dd>
          </div>
          <div className="wide">
            <dt>Parsed JSON</dt>
            <dd>
              <pre>{JSON.stringify(event.parsed, null, 2)}</pre>
            </dd>
          </div>
        </dl>

        {hourCopies.length > 1 && (
          <section className="popup-related">
            <button
              type="button"
              className={hourOpen ? "acc-head on" : "acc-head"}
              onClick={() => setHourOpen((v) => !v)}
            >
              <ChevronDown size={14} />
              <h4>
                {hourCopies.length} matching logs in {hourLabel ?? "this hour"}
              </h4>
            </button>
            {hourOpen && (
              <ul>
                {hourCopies.map((row) => (
                  <li key={row.id}>
                    <time>{formatClock(row.receivedAt)}</time>
                    <span className={`sev ${row.severityLabel}`}>{row.severityLabel}</span>
                    <span>{row.message}</span>
                  </li>
                ))}
              </ul>
            )}
          </section>
        )}

        {related.length > 0 && (
          <section className="popup-related">
            <h4>Recent {processName} on {event.hostname ?? "this host"}</h4>
            <ul>
              {related.map((row) => (
                <li key={row.id}>
                  <time>{formatClock(row.receivedAt)}</time>
                  <span className={`sev ${row.severityLabel}`}>{row.severityLabel}</span>
                  <span>{row.message}</span>
                </li>
              ))}
            </ul>
          </section>
        )}
      </div>
    </div>
  );
}

function pad(n: number, w = 2): string {
  return String(n).padStart(w, "0");
}

function formatClock(iso: string): string {
  const d = new Date(iso);
  return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
}

function formatFull(iso: string): string {
  const d = new Date(iso);
  return `${d.toLocaleDateString()} ${formatClock(iso)}.${pad(d.getMilliseconds(), 3)}`;
}
