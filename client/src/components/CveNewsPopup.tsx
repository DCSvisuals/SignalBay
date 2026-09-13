import { ExternalLink, X } from "lucide-react";
import { useEffect } from "react";
import { newsSeverity, newsSocialLinks, newsSourceLinks } from "../lib/newsMeta";
import { cleanHtmlText } from "../lib/text";
import type { NewsItem } from "../types";

interface Props {
  cves: string[];
  relatedCves: string[];
  articles: NewsItem[];
  onClose: () => void;
}

export function CveNewsPopup({ cves, relatedCves, articles, onClose }: Props) {
  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  return (
    <div className="popup-overlay" onClick={onClose} role="presentation">
      <div
        className="popup-card news-popup"
        role="dialog"
        aria-modal="true"
        aria-labelledby="cve-news-title"
        onClick={(event) => event.stopPropagation()}
      >
        <header className="popup-head">
          <div>
            <p className="popup-kicker">Threat intel for this incident</p>
            <h3 id="cve-news-title">CVE news</h3>
          </div>
          <button className="ghost" onClick={onClose} aria-label="Close">
            <X size={14} />
          </button>
        </header>
        <div className="chips">
          {cves.map((cve) => (
            <span className="cve" key={cve}>
              {cve}
            </span>
          ))}
          {relatedCves.map((cve) => (
            <span className="chip" key={cve}>
              related {cve}
            </span>
          ))}
        </div>
        <div className="cve-news-list">
          {articles.map((item) => {
            const official = newsSourceLinks(item);
            const social = newsSocialLinks(item);
            return (
              <article className="cve-news-item" key={item.id}>
                <div className="headline-kicker">
                  <span className={`source ${item.source}`}>
                    {item.source === "kev" ? "KEV" : "Advisory"}
                  </span>
                  <span className={`sev ${newsSeverity(item)}`}>{newsSeverity(item)}</span>
                  {item.cveIds.slice(0, 3).map((cve) => (
                    <span className="cve" key={cve}>
                      {cve}
                    </span>
                  ))}
                </div>
                <h4>{cleanHtmlText(item.title, 160)}</h4>
                {item.summary && <p>{cleanHtmlText(item.summary, 220)}</p>}
                <div className="source-links">
                  {official.map((link) => (
                    <a key={link.url} href={link.url} target="_blank" rel="noreferrer">
                      <ExternalLink size={12} />
                      {link.label}
                    </a>
                  ))}
                  {social.map((link) => (
                    <a key={link.url} href={link.url} target="_blank" rel="noreferrer">
                      <ExternalLink size={12} />
                      {link.label}
                    </a>
                  ))}
                </div>
              </article>
            );
          })}
        </div>
      </div>
    </div>
  );
}
