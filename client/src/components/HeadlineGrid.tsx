import { ExternalLink } from "lucide-react";
import { newsSeverity, newsSourceLinks } from "../lib/newsMeta";
import { cleanHtmlText } from "../lib/text";
import type { NewsItem } from "../types";

interface Props {
  news: NewsItem[];
  selectedId: number | null;
  onSelect: (id: number) => void;
}

export function HeadlineGrid({ news, selectedId, onSelect }: Props) {
  return (
    <article className="panel headline-panel">
      <header className="panel-head">
        <div>
          <h2>Headline Selector Grid</h2>
          <p>CISA advisories + Known Exploited Vulnerabilities</p>
        </div>
      </header>
      <div className="headline-grid">
        {news.length === 0 && (
          <div className="empty">Waiting on CISA XML / KEV JSON ingest…</div>
        )}
        {news.map((item) => {
          const title = cleanHtmlText(item.title, 140);
          const blurb =
            [item.vendor, item.product].filter(Boolean).join(" · ") ||
            cleanHtmlText(item.summary, 180) ||
            "CISA feed item";
          const severity = newsSeverity(item);
          const source = newsSourceLinks(item)[0] ?? null;
          return (
            <article
              key={item.id}
              className={item.id === selectedId ? "headline active" : "headline"}
              role="button"
              tabIndex={0}
              onClick={() => onSelect(item.id)}
              onKeyDown={(event) => {
                if (event.key === "Enter" || event.key === " ") {
                  event.preventDefault();
                  onSelect(item.id);
                }
              }}
            >
              <div className="headline-kicker">
                <span className={`sev ${severity}`}>{severity}</span>
                {item.cveIds.slice(0, 2).map((cve) => (
                  <span className="cve" key={cve}>
                    {cve}
                  </span>
                ))}
              </div>
              <h3>{title}</h3>
              <p>{blurb}</p>
              <div className="headline-foot">
                <time>{formatDate(item.publishedAt || item.fetchedAt)}</time>
                {source && (
                  <a
                    href={source.url}
                    target="_blank"
                    rel="noreferrer"
                    onClick={(e) => e.stopPropagation()}
                  >
                    <ExternalLink size={12} />
                    {source.label}
                  </a>
                )}
              </div>
            </article>
          );
        })}
      </div>
    </article>
  );
}

function formatDate(value: string): string {
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return value;
  return d.toLocaleDateString(undefined, { month: "short", day: "numeric", year: "numeric" });
}
