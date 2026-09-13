import type { NewsItem, SeverityLabel, SourceLink } from "../types";

export function newsSeverity(item: NewsItem): SeverityLabel {
  if (item.severity) return item.severity;
  const blob = `${item.title}\n${item.summary ?? ""}\n${item.content ?? ""}\n${item.url ?? ""}`;
  if (item.source === "kev") {
    return /ransomware use:\s*known/i.test(blob) ? "critical" : "high";
  }
  const scores = [...blob.matchAll(/\b(?:cvss(?:v[34])?|v3(?:\.\d)?|3\.[01]|4\.0)\s+(\d{1,2}(?:\.\d+)?)\b/gi)]
    .map((m) => Number(m[1]))
    .filter((n) => n >= 0 && n <= 10);
  const max = scores.length ? Math.max(...scores) : -1;
  if (max >= 9) return "critical";
  if (max >= 7 || /\/ics-advisories\/|\/alerts\//i.test(item.url ?? "")) return "high";
  if (max >= 4) return "medium";
  if (max >= 0) return "low";
  return "medium";
}

export function newsSourceLinks(item: NewsItem): SourceLink[] {
  if (item.sourceLinks?.length) return item.sourceLinks;
  const links: SourceLink[] = [];
  const seen = new Set<string>();
  const add = (label: string, url?: string | null) => {
    if (!url || seen.has(url)) return;
    seen.add(url);
    links.push({ label, url });
  };
  if (item.url) add(labelForUrl(item.url), item.url);
  if (item.source === "kev" && item.cveIds[0]) {
    add("NVD", `https://nvd.nist.gov/vuln/detail/${item.cveIds[0]}`);
    add(
      "CISA KEV",
      `https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=${encodeURIComponent(item.cveIds[0])}`
    );
  } else {
    for (const cve of item.cveIds.slice(0, 2)) {
      add(`NVD ${cve}`, `https://nvd.nist.gov/vuln/detail/${cve}`);
    }
  }
  return links;
}

export function newsSocialLinks(item: NewsItem): SourceLink[] {
  const cve = item.cveIds[0];
  const query = [cve, item.vendor, item.product, item.title.replace(/[^\w\s-]+/g, " ")]
    .filter(Boolean)
    .slice(0, 3)
    .join(" ")
    .replace(/\s+/g, " ")
    .trim();
  const q = encodeURIComponent(query || item.title);
  return [
    { label: "X / Twitter", url: `https://x.com/search?q=${q}&f=live` },
    { label: "Facebook", url: `https://www.facebook.com/search/top?q=${q}` }
  ];
}

function labelForUrl(url: string): string {
  const lower = url.toLowerCase();
  if (lower.includes("nvd.nist.gov")) return "NVD";
  if (lower.includes("/ics-advisories/")) return "CISA ICS";
  if (lower.includes("/alerts/")) return "CISA Alert";
  if (lower.includes("/cybersecurity-advisories/")) return "CISA Advisory";
  if (lower.includes("known-exploited-vulnerabilities")) return "CISA KEV";
  if (lower.includes("cisa.gov")) return "CISA";
  try {
    return new URL(url).hostname.replace(/^www\./, "");
  } catch {
    return "Source";
  }
}
