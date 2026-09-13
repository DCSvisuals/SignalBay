import { Copy, Newspaper, Sparkles, Terminal } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { api } from "../lib/api";
import { incidentCves, newsForCves } from "../lib/cveNews";
import type { Incident, LlmStatus, NewsItem } from "../types";
import { CveNewsPopup } from "./CveNewsPopup";
import { MarkdownView } from "./MarkdownView";
import { SeverityGauge } from "./SeverityGauge";

interface Props {
  incident: Incident | null;
  llm: LlmStatus | null;
  news: NewsItem[];
  onUpdated: (incident: Incident) => void;
}

export function AiTriageViewport({ incident, llm, news, onUpdated }: Props) {
  const [busy, setBusy] = useState(false);
  const [copied, setCopied] = useState(false);
  const [showNews, setShowNews] = useState(false);
  const [cveArticles, setCveArticles] = useState<NewsItem[]>([]);

  const cves = useMemo(() => (incident ? incidentCves(incident) : []), [incident]);
  const localMatch = useMemo(() => newsForCves(news, cves), [news, cves]);
  const articles = cveArticles.length ? cveArticles : localMatch.matches;
  const relatedCves = useMemo(() => {
    const primary = new Set(cves);
    const extra = new Set<string>();
    for (const item of articles) {
      for (const cve of item.cveIds) {
        const id = cve.toUpperCase();
        if (!primary.has(id)) extra.add(id);
      }
    }
    return [...extra];
  }, [articles, cves]);
  const canShowNews = Boolean(incident?.aiSummary) && articles.length > 0;

  useEffect(() => {
    setShowNews(false);
    setCveArticles([]);
    if (!incident?.aiSummary || !cves.length) return;
    let cancelled = false;
    void api
      .newsByCves(cves)
      .then((rows) => {
        if (!cancelled) setCveArticles(rows);
      })
      .catch(() => {
        if (!cancelled) setCveArticles(localMatch.matches);
      });
    return () => {
      cancelled = true;
    };
  }, [incident?.id, incident?.aiSummary, cves.join("|")]);

  const run = async () => {
    if (!incident) return;
    setBusy(true);
    try {
      const updated = await api.triage(incident.id);
      onUpdated(updated);
    } catch (err) {
      console.warn(err);
    } finally {
      setBusy(false);
    }
  };

  const copy = async () => {
    const text = incident?.containmentCommands || extractFence(incident?.aiSummary);
    if (!text) return;
    await navigator.clipboard.writeText(text);
    setCopied(true);
    window.setTimeout(() => setCopied(false), 1400);
  };

  return (
    <article className="panel triage-panel">
      <header className="panel-head">
        <div>
          <h2>AI Triage Viewport</h2>
          <p>Qwen2.5-3B GGUF · local Metal inference</p>
        </div>
        <div className="triage-actions">
          {canShowNews && (
            <button className="ghost" onClick={() => setShowNews(true)}>
              <Newspaper size={14} />
              News ({articles.length})
            </button>
          )}
          <button className="primary" disabled={!incident || busy || llm?.state !== "ready"} onClick={() => void run()}>
            <Sparkles size={14} />
            {busy ? "Inferring…" : "Triage with Metal"}
          </button>
        </div>
      </header>
      {!incident ? (
        <div className="empty">Select an anomaly to generate a local incident report.</div>
      ) : (
        <div className="triage-body">
          <div className="triage-card">
            <div className="triage-meta">
              <SeverityGauge score={incident.riskScore} label={incident.severity} />
              <div>
                <p className="inner-kicker">Selected incident</p>
                <h3>{incident.title}</h3>
                <p className="muted">{incident.evidence}</p>
                <p className="engine-note">{llm?.message ?? "Engine warming"}</p>
              </div>
            </div>
            <div className="triage-summary">
              <p className="inner-kicker">Summary</p>
              {incident.aiSummary ? (
                <MarkdownView value={incident.aiSummary} />
              ) : (
                <div className="empty compact">
                  No GGUF summary yet. Run triage once the Metal engine reports ready.
                </div>
              )}
              {(incident.containmentCommands || incident.aiSummary) && (
                <button className="ghost copy-cmd" onClick={() => void copy()}>
                  {copied ? <Terminal size={13} /> : <Copy size={13} />}
                  {copied ? "Copied containment commands" : "Copy macOS containment commands"}
                </button>
              )}
            </div>
          </div>
        </div>
      )}
      {showNews && incident && (
        <CveNewsPopup
          cves={cves}
          relatedCves={relatedCves}
          articles={articles}
          onClose={() => setShowNews(false)}
        />
      )}
    </article>
  );
}

function extractFence(markdown: string | null | undefined): string {
  if (!markdown) return "";
  const match = markdown.match(/```(?:bash|zsh|sh)?\n([\s\S]*?)```/i);
  return match ? match[1].trim() : markdown;
}
