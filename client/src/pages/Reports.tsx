import { useEffect, useState } from "react";
import { api } from "../lib/api";
import type { ReportSummary } from "../types";

const CAP_LABELS: Record<string, string> = {
  logCollection: "1 Log collection & normalization",
  dashboard: "2 Centralized dashboard",
  correlation: "3 Real-time correlation",
  threatIntel: "4 Threat intelligence (CISA/KEV + IOCs)",
  uebaLite: "5 UEBA lite (auth baseline)",
  soarConfirm: "6 SOAR (confirm-to-act playbooks)",
  riskScoring: "7 Risk scoring + IOC bump",
  complianceExport: "8 Compliance snapshot",
  rbacOptional: "9 RBAC (set SIEM_AUTH=1)",
  retention: "10 Retention / hot window",
  jsonIngest: "11 JSON ingest (hybrid/lab agents)",
  customRules: "12 Custom rules",
  enrichment: "13 Enrichment (IP scope, entity)",
  historicalHunt: "14 Historical hunt",
  localLlm: "15 Local/cloud LLM analytics"
};

export function Reports() {
  const [data, setData] = useState<(ReportSummary & { capabilities?: Record<string, boolean> }) | null>(
    null
  );

  useEffect(() => {
    void api.reportSummary(24).then(setData).catch(() => undefined);
  }, []);

  if (!data) return <article className="panel"><div className="empty">Loading report…</div></article>;

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
        <h3 className="subh">Top hosts</h3>
        <ul className="ops-list">
          {(data.topHosts ?? []).map((row) => (
            <li className="ops-row" key={row.hostname}>
              <span>{row.hostname}</span>
              <strong>{row.n}</strong>
            </li>
          ))}
        </ul>
      </article>
      <article className="panel">
        <header className="panel-head">
          <div>
            <h2>Capability map</h2>
            <p>Home-lab coverage of the 15 SIEM features — not a Gartner score.</p>
          </div>
        </header>
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
