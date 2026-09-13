import { ExternalLink, Sparkles } from "lucide-react";
import { useState } from "react";
import { api } from "../lib/api";
import { newsSeverity, newsSocialLinks, newsSourceLinks } from "../lib/newsMeta";
import { cleanHtmlText } from "../lib/text";
import type { LlmStatus, NewsItem } from "../types";
import { MarkdownView } from "./MarkdownView";

interface Props {
  item: NewsItem | null;
  llm: LlmStatus | null;
  onUpdated: (item: NewsItem) => void;
}

export function AiSummaryCard({ item, llm, onUpdated }: Props) {
  const [busy, setBusy] = useState(false);

  const run = async () => {
    if (!item) return;
    setBusy(true);
    try {
      const updated = await api.summarize(item.id);
      onUpdated(updated);
    } finally {
      setBusy(false);
    }
  };

  const links = item ? newsSourceLinks(item) : [];
  const social = item ? newsSocialLinks(item) : [];
  const severity = item ? newsSeverity(item) : "info";

  return (
    <article className="panel summary-panel">
      <header className="panel-head">
        <div>
          <h2>AI Summary Card</h2>
          <p>3-bullet local model brief · Asset / Vector / Remediation</p>
        </div>
        <button className="primary" disabled={!item || busy || llm?.state !== "ready"} onClick={() => void run()}>
          <Sparkles size={14} />
          {busy ? "Summarizing…" : "Summarize offline"}
        </button>
      </header>
      {!item ? (
        <div className="empty">Select a headline.</div>
      ) : (
        <div className="summary-body">
          <h3>{cleanHtmlText(item.title, 180)}</h3>
          <div className="chips">
            <span className={`source ${item.source}`}>
              {item.source === "kev" ? "KEV" : "Advisory"}
            </span>
            <span className={`sev ${severity}`}>{severity}</span>
            {item.cveIds.map((cve) => (
              <a
                key={cve}
                className="cve"
                href={`https://nvd.nist.gov/vuln/detail/${cve}`}
                target="_blank"
                rel="noreferrer"
              >
                {cve}
              </a>
            ))}
            {item.vendor && <span className="chip">{item.vendor}</span>}
            {item.product && <span className="chip">{item.product}</span>}
          </div>
          {links.length > 0 && (
            <div className="link-group">
              <p className="link-group-label">Official sources</p>
              <div className="source-links">
                {links.map((link) => (
                  <a key={link.url} href={link.url} target="_blank" rel="noreferrer">
                    <ExternalLink size={12} />
                    {link.label}
                  </a>
                ))}
              </div>
            </div>
          )}
          {social.length > 0 && (
            <div className="link-group">
              <p className="link-group-label">Related discussion</p>
              <div className="source-links">
                {social.map((link) => (
                  <a key={link.url} href={link.url} target="_blank" rel="noreferrer">
                    <ExternalLink size={12} />
                    {link.label}
                  </a>
                ))}
              </div>
            </div>
          )}
          {item.aiSummary ? (
            <MarkdownView value={item.aiSummary} />
          ) : (
            <div className="empty compact">
              {llm?.state === "ready"
                ? "No local summary yet. Generate a 3-bullet technical brief."
                : llm?.message ?? "Waiting for the Metal engine."}
            </div>
          )}
          {item.summary && (
            <details>
              <summary>Source excerpt</summary>
              <p>{cleanHtmlText(item.summary, 400)}</p>
            </details>
          )}
        </div>
      )}
    </article>
  );
}


