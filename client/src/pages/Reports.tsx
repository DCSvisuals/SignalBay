import { useEffect, useState } from "react";
import { api } from "../lib/api";
import type { ReportSummary } from "../types";

const CAP_LABELS: Record<string, string> = {
  logCollection: "Log collection and normalization",
  dashboard: "Centralized dashboard",
  correlation: "Real-time correlation",
  threatIntel: "Threat intelligence (CISA KEV and IOCs)",
  uebaLite: "UEBA lite (auth baseline and first-seen source)",
  soarConfirm: "SOAR (confirm-to-act playbooks)",
  riskScoring: "Risk scoring",
  complianceExport: "Compliance snapshot (not a certification)",
  rbacOptional: "RBAC",
  retention: "Retention with gzip archive",
  jsonIngest: "JSON ingest",
  customRules: "Custom rules",
  enrichment: "Enrichment (user, source, category)",
  historicalHunt: "Historical full-text hunt",
  localLlm: "Local or cloud LLM analytics",
  cases: "Case notes and assignee",
  webhook: "Webhook alerts",
  fimWatch: "File integrity incidents",
  versionedKev: "High-confidence KEV matching"
};

type Series = Awaited<ReturnType<typeof api.reportSeries>>;
type AuditRow = Awaited<ReturnType<typeof api.audit>>[number];

export function Reports() {
  const [data, setData] = useState<(ReportSummary & { capabilities?: Record<string, boolean> }) | null>(null);
  const [series, setSeries] = useState<Series | null>(null);
  const [audit, setAudit] = useState<AuditRow[]>([]);
  const [retentionDays, setRetentionDays] = useState(7);
  const [webhookUrl, setWebhookUrl] = useState("");
  const [msg, setMsg] = useState<string | null>(null);

  const load = () => {
    void api.reportSummary(24).then(setData).catch(() => undefined);
    void api.reportSeries(24).then(setSeries).catch(() => undefined);
    void api.audit().then(setAudit).catch(() => undefined);
    void api.settings().then((settings) => {
      setRetentionDays(settings.retentionDays);
      setWebhookUrl(settings.webhookUrl);
    }).catch(() => undefined);
  };

  useEffect(() => {
    load();
  }, []);

  if (!data) return <article className="panel"><div className="empty">Loading report…</div></article>;
  const max = Math.max(1, ...(series?.buckets.map((row) => row.n) ?? [1]));

  return (
    <div className="reports-grid">
      <article className="panel">
        <header className="panel-head">
          <div>
            <h2>SOC report · last {data.windowHours}h</h2>
            <p>Generated {new Date(data.generatedAt).toLocaleString()}</p>
          </div>
          <a className="ghost" href="/api/compliance" target="_blank" rel="noreferrer">
            Compliance HTML
          </a>
        </header>
        <div className="kpi-row">
          <div className="kpi"><strong>{data.events}</strong><span>events</span></div>
          <div className="kpi"><strong>{data.openIncidents}</strong><span>open incidents</span></div>
          <div className="kpi"><strong>{data.highOpen}</strong><span>high / critical</span></div>
          <div className="kpi"><strong>{data.retentionDays}d</strong><span>retention</span></div>
        </div>
        <h3 className="subh">Events per hour</h3>
        <div className="bars">
          {(series?.buckets ?? []).map((row) => (
            <div className="bar-row" key={row.hour} title={`${row.hour}:00 · ${row.n}`}>
              <span>{row.hour.slice(11, 13)}</span>
              <div className="bar-track">
                <div className="bar-fill" style={{ width: `${Math.max(row.n ? 4 : 0, (row.n / max) * 100)}%` }} />
              </div>
              <strong>{row.n}</strong>
            </div>
          ))}
        </div>
        <h3 className="subh">Failed users</h3>
        <ul className="ops-list">
          {(series?.failedUsers ?? []).map((row) => (
            <li className="ops-row" key={row.user}>
              <span>{row.user}</span>
              <strong>{row.n}</strong>
            </li>
          ))}
          {(series?.failedUsers.length ?? 0) === 0 && <li className="empty compact">No failed logins in this window.</li>}
        </ul>
        <h3 className="subh">Public source IPs</h3>
        <ul className="ops-list">
          {(series?.publicSources ?? []).map((row) => (
            <li className="ops-row" key={row.ip}>
              <span>{row.ip}</span>
              <strong>{row.n}</strong>
            </li>
          ))}
          {(series?.publicSources.length ?? 0) === 0 && <li className="empty compact">No public sources in this window.</li>}
        </ul>
      </article>
      <article className="panel">
        <header className="panel-head">
          <div>
            <h2>Operations</h2>
            <p>Retention archives old events to gzip JSONL before deleting them. A database copy is kept under Application Support.</p>
          </div>
        </header>
        <form
          className="hunt-form"
          onSubmit={(event) => {
            event.preventDefault();
            void api
              .saveSettings({ retentionDays, webhookUrl })
              .then(() => {
                setMsg("Settings saved");
                load();
              })
              .catch((err) => setMsg(err instanceof Error ? err.message : "Save failed"));
          }}
        >
          <input
            type="number"
            min={1}
            max={90}
            value={retentionDays}
            onChange={(e) => setRetentionDays(Number(e.target.value))}
          />
          <input
            value={webhookUrl}
            onChange={(e) => setWebhookUrl(e.target.value)}
            placeholder="https://webhook.example/alerts"
          />
          <button className="primary" type="submit">Save</button>
          <button
            className="ghost"
            type="button"
            onClick={() =>
              void api.backup().then((row) => setMsg(`Backup ${row.file}`)).catch((err) =>
                setMsg(err instanceof Error ? err.message : "Backup failed")
              )
            }
          >
            Backup now
          </button>
        </form>
        {msg && <p className="muted pad">{msg}</p>}
        <h3 className="subh">Operator audit</h3>
        <ul className="ops-list">
          {audit.map((row) => (
            <li className="ops-row" key={row.id}>
              <span>
                {row.action} · {row.detail}
              </span>
              <strong>{row.createdAt.slice(11, 19)}</strong>
            </li>
          ))}
          {audit.length === 0 && <li className="empty compact">No operator actions recorded yet.</li>}
        </ul>
        <h3 className="subh">What is actually on</h3>
        <ul className="cap-list">
          {Object.entries(CAP_LABELS).map(([key, label]) => (
            <li key={key} className={data.capabilities?.[key] ? "on" : "off"}>
              {data.capabilities?.[key] ? "ON" : "OFF"} · {label}
            </li>
          ))}
        </ul>
      </article>
    </div>
  );
}
