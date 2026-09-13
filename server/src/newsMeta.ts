import type { NewsItem, SeverityLabel } from "./types.js";

export interface SourceLink {
  label: string;
  url: string;
}

const RANK: Record<SeverityLabel, number> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4
};

export function classifyNewsSeverity(input: {
  source: "xml" | "kev";
  title: string;
  url: string | null;
  summary: string | null;
  content: string | null;
}): SeverityLabel {
  const blob = `${input.title}\n${input.summary ?? ""}\n${input.content ?? ""}\n${input.url ?? ""}`;
  let label: SeverityLabel = input.source === "kev" ? "high" : "info";

  if (input.source === "kev" && /ransomware use:\s*known/i.test(blob)) {
    label = "critical";
  }

  const scores = extractCvssScores(blob);
  if (scores.length) {
    const max = Math.max(...scores);
    label = worse(label, fromCvss(max));
  }

  if (/\bcritical\b/i.test(blob) && /cvss|base severity|actively exploited|known exploited/i.test(blob)) {
    label = worse(label, "critical");
  } else if (/\bhigh\b/i.test(blob) && /cvss|base severity/i.test(blob)) {
    label = worse(label, "high");
  } else if (/\bmedium\b/i.test(blob) && /cvss|base severity/i.test(blob)) {
    label = worse(label, "medium");
  }

  const url = input.url ?? "";
  if (/\/ics-advisories\/|icsa-/i.test(`${url} ${input.title}`)) {
    label = worse(label, "high");
  } else if (/\/alerts\//i.test(url) || /\balert\b/i.test(input.title)) {
    label = worse(label, "high");
  } else if (/cybersecurity-advisories|analysis-reports/i.test(url)) {
    label = worse(label, "medium");
  }

  if (label === "info" && input.source === "xml") return "medium";
  return label;
}

export function buildSourceLinks(input: {
  source: "xml" | "kev";
  url: string | null;
  cveIds: string[];
  content: string | null;
}): SourceLink[] {
  const links: SourceLink[] = [];
  const seen = new Set<string>();
  const add = (label: string, url: string | null | undefined) => {
    const trimmed = (url ?? "").trim();
    if (!trimmed || seen.has(trimmed)) return;
    seen.add(trimmed);
    links.push({ label, url: trimmed });
  };

  if (input.source === "kev") {
    const cve = input.cveIds[0];
    if (input.url) add(labelForUrl(input.url), input.url);
    if (cve) {
      add("NVD", `https://nvd.nist.gov/vuln/detail/${cve}`);
      add("CISA KEV", `https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=${encodeURIComponent(cve)}`);
    } else {
      add("CISA KEV", "https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
    }
  } else {
    add(labelForUrl(input.url), input.url);
    for (const cve of input.cveIds.slice(0, 2)) {
      add(`NVD ${cve}`, `https://nvd.nist.gov/vuln/detail/${cve}`);
    }
  }

  const extra = input.content?.match(/https?:\/\/[^\s<>"']+/g) ?? [];
  for (const raw of extra) {
    const url = raw.replace(/[.,);]+$/, "");
    if (/chromereleases|vendor|advisory|cisa\.gov\/news-events\/directives/i.test(url)) {
      add(labelForUrl(url), url);
    }
    if (links.length >= 5) break;
  }

  return links;
}

export function withNewsMeta<T extends Omit<NewsItem, "severity" | "sourceLinks">>(
  item: T
): T & Pick<NewsItem, "severity" | "sourceLinks"> {
  return {
    ...item,
    severity: classifyNewsSeverity(item),
    sourceLinks: buildSourceLinks(item)
  };
}

function labelForUrl(url: string | null | undefined): string {
  if (!url) return "Source";
  const lower = url.toLowerCase();
  if (lower.includes("nvd.nist.gov")) return "NVD";
  if (lower.includes("/ics-advisories/") || lower.includes("icsa-")) return "CISA ICS";
  if (lower.includes("/alerts/")) return "CISA Alert";
  if (lower.includes("/cybersecurity-advisories/")) return "CISA Advisory";
  if (lower.includes("/analysis-reports/")) return "CISA Analysis";
  if (lower.includes("known-exploited-vulnerabilities")) return "CISA KEV";
  if (lower.includes("cisa.gov")) return "CISA";
  try {
    return new URL(url).hostname.replace(/^www\./, "");
  } catch {
    return "Source";
  }
}

function extractCvssScores(text: string): number[] {
  const scores: number[] = [];
  const patterns = [
    /\b(?:cvss(?:v[34](?:\.\d)?)?|v3(?:\.\d)?)\s+(\d{1,2}(?:\.\d+)?)\b/gi,
    /\b(?:3\.[01]|4\.0)\s+(\d{1,2}(?:\.\d+)?)\s+(?:critical|high|medium|low)\b/gi,
    /\b(\d{1,2}(?:\.\d+)?)\s+(?:critical|high|medium|low)\b/gi
  ];
  for (const re of patterns) {
    for (const match of text.matchAll(re)) {
      const n = Number(match[1]);
      if (n >= 0 && n <= 10) scores.push(n);
    }
  }
  return scores;
}

function fromCvss(score: number): SeverityLabel {
  if (score >= 9) return "critical";
  if (score >= 7) return "high";
  if (score >= 4) return "medium";
  return "low";
}

function worse(a: SeverityLabel, b: SeverityLabel): SeverityLabel {
  return RANK[b] > RANK[a] ? b : a;
}
