import { ExternalLink, X } from "lucide-react";
import { useEffect } from "react";
import { newsSeverity, newsSocialLinks, newsSourceLinks } from "../lib/newsMeta";
import { cleanHtmlText } from "../lib/text";
import type { InventoryHit, NewsItem } from "../types";

interface Props {
  hit: InventoryHit;
  articles: NewsItem[];
  loading?: boolean;
  onClose: () => void;
}

export function InventoryCvePopup({ hit, articles, loading = false, onClose }: Props) {
  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  const primary = articles[0] ?? null;
  const severity = primary ? newsSeverity(primary) : "high";
  const official = primary
    ? newsSourceLinks(primary)
    : [
        { label: "NVD", url: `https://nvd.nist.gov/vuln/detail/${hit.cve}` },
        {
          label: "CISA KEV",
          url: `https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=${encodeURIComponent(hit.cve)}`
        }
      ];
  const social = primary
    ? newsSocialLinks(primary)
    : [
        {
          label: "X / Twitter",
          url: `https://x.com/search?q=${encodeURIComponent(hit.cve)}&f=live`
        }
      ];

  return (
    <div className="popup-overlay" onClick={onClose} role="presentation">
      <div
        className="popup-card news-popup"
        role="dialog"
        aria-modal="true"
        aria-labelledby="inventory-cve-title"
        onClick={(event) => event.stopPropagation()}
      >
        <header className="popup-head">
          <div>
            <p className="popup-kicker">Inventory / KEV match</p>
            <h3 id="inventory-cve-title">{hit.cve}</h3>
          </div>
          <button className="ghost" onClick={onClose} aria-label="Close">
            <X size={14} />
          </button>
        </header>

        <div className="popup-meta">
          <span className={`sev ${severity}`}>{severity}</span>
          <span className="cve">{hit.cve}</span>
          <span className="chip">{hit.name}</span>
        </div>

        <dl className="popup-fields">
          <div>
            <dt>Local app</dt>
            <dd>{hit.name}</dd>
          </div>
          <div>
            <dt>Matched</dt>
            <dd>{formatWhen(hit.collectedAt)}</dd>
          </div>
          {primary?.vendor ? (
            <div>
              <dt>Vendor</dt>
              <dd>{primary.vendor}</dd>
            </div>
          ) : null}
          {primary?.product ? (
            <div>
              <dt>Product</dt>
              <dd>{primary.product}</dd>
            </div>
          ) : null}
          <div className="wide">
            <dt>KEV title</dt>
            <dd className="wrap">{cleanHtmlText(primary?.title ?? hit.title, 240)}</dd>
          </div>
          {(primary?.summary || primary?.content) && (
            <div className="wide">
              <dt>Description</dt>
              <dd className="wrap">
                {cleanHtmlText(primary.summary ?? primary.content ?? "", 600)}
              </dd>
            </div>
          )}
        </dl>

        {loading && <p className="muted">Loading KEV details…</p>}

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

        {articles.length > 1 && (
          <section className="popup-related">
            <h4>Related advisories</h4>
            <ul>
              {articles.slice(1, 6).map((item) => (
                <li key={item.id}>
                  <span className={`source ${item.source}`}>
                    {item.source === "kev" ? "KEV" : "Advisory"}
                  </span>
                  <span>{cleanHtmlText(item.title, 120)}</span>
                </li>
              ))}
            </ul>
          </section>
        )}
      </div>
    </div>
  );
}

function formatWhen(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleString();
}
