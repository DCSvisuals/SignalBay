import { ChevronDown, ShieldAlert } from "lucide-react";
import { useMemo, useState } from "react";
import type { Incident } from "../types";

interface Props {
  incidents: Incident[];
  selectedId: number | null;
  onSelect: (id: number) => void;
  demoMode?: boolean;
  onCaseStatus?: (id: number, status: Incident["status"]) => void;
}

interface IncidentGroup {
  id: string;
  latest: Incident;
  copies: Incident[];
}

function groupIdentical(incidents: Incident[]): IncidentGroup[] {
  const buckets = new Map<string, Incident[]>();
  for (const incident of incidents) {
    const key = [
      incident.title,
      incident.ruleName,
      incident.severity,
      incident.status,
      incident.origin ?? "live"
    ].join("|");
    const list = buckets.get(key);
    if (list) list.push(incident);
    else buckets.set(key, [incident]);
  }
  const groups: IncidentGroup[] = [];
  for (const [id, copies] of buckets) {
    copies.sort((a, b) => (a.createdAt < b.createdAt ? 1 : -1));
    groups.push({ id, latest: copies[0], copies });
  }
  groups.sort((a, b) => (a.latest.createdAt < b.latest.createdAt ? 1 : -1));
  return groups;
}

export function AnomalyExplorer({
  incidents,
  selectedId,
  onSelect,
  demoMode = false,
  onCaseStatus
}: Props) {
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const groups = useMemo(() => groupIdentical(incidents), [incidents]);

  return (
    <article className="panel anomaly-panel">
      <header className="panel-head">
        <div>
          <h2>Active Anomaly Explorer</h2>
          <p>
            {demoMode
              ? "Incidents from demo logs only — isolated from real SIEM traffic."
              : "Incidents from live collectors — isolated from demo traffic."}
          </p>
          <p>
            The Live Log Stream shows every syslog. This list only shows rows that
            matched a correlation rule. Select one to load it into AI Triage.
          </p>
        </div>
        <span className="count">
          {groups.length}
          {groups.length !== incidents.length ? ` · ${incidents.length}` : ""}
        </span>
      </header>
      <div className="incident-list">
        {incidents.length === 0 && (
          <div className="empty compact">
            {demoMode
              ? "No demo anomalies yet. Inject or start the demo stream to flag incidents."
              : "No open anomalies yet. Real matching syslog will appear here."}
          </div>
        )}
        {groups.map((group) => {
          const incident = group.latest;
          const open = expandedId === group.id;
          const selected = group.copies.some((row) => row.id === selectedId);
          return (
            <div key={group.id} className={open ? "incident-group open" : "incident-group"}>
              <div
                className={selected ? "incident active" : "incident"}
                role="button"
                tabIndex={0}
                onClick={() => onSelect(incident.id)}
                onKeyDown={(event) => {
                  if (event.key === "Enter" || event.key === " ") onSelect(incident.id);
                }}
              >
                <ShieldAlert size={14} />
                <div className="incident-body">
                  <div className="incident-title">
                    {incident.title}
                    {group.copies.length > 1 ? (
                      <strong className="dup-count">×{group.copies.length}</strong>
                    ) : incident.occurrenceCount && incident.occurrenceCount > 1 ? (
                      <strong className="dup-count">×{incident.occurrenceCount}</strong>
                    ) : null}
                  </div>
                  <div className="incident-meta">
                    <span className={`sev ${incident.severity}`}>{incident.severity}</span>
                    <span>{incident.status}</span>
                    <span>{incident.ruleName}</span>
                    <span>risk {incident.riskScore}</span>
                  </div>
                  {incident.mitre && incident.mitre.length > 0 && (
                    <div className="incident-meta">
                      {incident.mitre.slice(0, 2).map((ref) => (
                        <span className="chip" key={ref.id}>
                          {ref.id} {ref.technique}
                        </span>
                      ))}
                    </div>
                  )}
                  {onCaseStatus && (
                    <div className="demo-controls" onClick={(event) => event.stopPropagation()}>
                      <button className="ghost" onClick={() => onCaseStatus(incident.id, "ack")}>
                        Ack
                      </button>
                      <button className="ghost" onClick={() => onCaseStatus(incident.id, "closed")}>
                        Close
                      </button>
                    </div>
                  )}
                </div>
                {group.copies.length > 1 ? (
                  <button
                    type="button"
                    className={open ? "acc-toggle on" : "acc-toggle"}
                    aria-label="Show identical copies"
                    onClick={(event) => {
                      event.stopPropagation();
                      setExpandedId(open ? null : group.id);
                    }}
                  >
                    <ChevronDown size={14} />
                  </button>
                ) : null}
              </div>
              {open && (
                <div className="incident-accordion">
                  {group.copies.map((row) => (
                    <button
                      type="button"
                      key={row.id}
                      className={row.id === selectedId ? "incident-copy on" : "incident-copy"}
                      onClick={() => onSelect(row.id)}
                    >
                      <time>{formatWhen(row.createdAt)}</time>
                      <span>#{row.id}</span>
                      <span>risk {row.riskScore}</span>
                    </button>
                  ))}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </article>
  );
}

function formatWhen(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
}
