import type { Incident, NewsItem } from "../types";

const CVE_RE = /CVE-\d{4}-\d{4,7}/gi;

export function extractCves(...texts: Array<string | null | undefined>): string[] {
  const found = new Set<string>();
  for (const text of texts) {
    if (!text) continue;
    for (const match of text.matchAll(CVE_RE)) {
      found.add(match[0].toUpperCase());
    }
  }
  return [...found];
}

export function incidentCves(incident: Incident): string[] {
  return extractCves(incident.title, incident.ruleName, incident.evidence, incident.aiSummary);
}

export function newsForCves(news: NewsItem[], cves: string[]): {
  matches: NewsItem[];
  relatedCves: string[];
} {
  const wanted = new Set(cves.map((cve) => cve.toUpperCase()));
  if (!wanted.size) return { matches: [], relatedCves: [] };

  const mentions = (item: NewsItem, id: string) =>
    item.cveIds.some((cve) => cve.toUpperCase() === id) ||
    `${item.title} ${item.summary ?? ""} ${item.content ?? ""}`.toUpperCase().includes(id);

  const direct = news.filter((item) => [...wanted].some((cve) => mentions(item, cve)));
  const relatedCves = new Set<string>();
  for (const item of direct) {
    for (const cve of item.cveIds) {
      const id = cve.toUpperCase();
      if (!wanted.has(id)) relatedCves.add(id);
    }
  }
  const related = news.filter(
    (item) =>
      !direct.some((row) => row.id === item.id) &&
      item.cveIds.some((cve) => relatedCves.has(cve.toUpperCase()))
  );
  return { matches: [...direct, ...related], relatedCves: [...relatedCves] };
}
