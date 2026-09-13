import { hub } from "./bus.js";
import { SiemDatabase, sha256 } from "./database.js";
import type { LlmEngine } from "./llm.js";
import { cleanHtmlText } from "./text.js";
import type { NewsItem } from "./types.js";

const DEFAULT_XML = "https://www.cisa.gov/cybersecurity-advisories/all.xml";
const DEFAULT_KEV =
  "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

const XML_FALLBACKS = [
  DEFAULT_XML,
  "https://www.cisa.gov/news-events/cybersecurity-advisories/rss.xml",
  "https://www.cisa.gov/sites/default/files/feeds/cybersecurity-advisories.xml",
  "https://www.cisa.gov/news-events/ics-advisories/rss.xml",
  "https://www.cisa.gov/uscert/ncas/alerts.xml"
];

const CVE_RE = /CVE-\d{4}-\d{4,7}/gi;
const UA =
  "LocalSIEM/1.0 (macOS; privacy-focused local SIEM; +http://127.0.0.1:5173)";

interface KevVulnerability {
  cveID?: string;
  vendorProject?: string;
  product?: string;
  vulnerabilityName?: string;
  dateAdded?: string;
  shortDescription?: string;
  requiredAction?: string;
  dueDate?: string;
  knownRansomwareCampaignUse?: string;
  notes?: string;
}

export class ThreatAggregator {
  private timer: NodeJS.Timeout | null = null;

  constructor(
    private db: SiemDatabase,
    private llm: LlmEngine,
    private onKevUpdate?: (cves: string[]) => void
  ) {}

  start(intervalMs = 15 * 60 * 1000): void {
    void this.sync("startup");
    this.timer = setInterval(() => {
      void this.sync("schedule");
    }, intervalMs);
  }

  stop(): void {
    if (this.timer) clearInterval(this.timer);
  }

  async sync(reason = "manual"): Promise<{ inserted: number; scanned: number }> {
    console.log(`[aggregator] sync (${reason})`);
    let inserted = 0;
    let scanned = 0;
    const xmlResult = await this.ingestXml();
    inserted += xmlResult.inserted;
    scanned += xmlResult.scanned;

    const kevResult = await this.ingestKev();
    inserted += kevResult.inserted;
    scanned += kevResult.scanned;

    if (this.onKevUpdate) {
      this.onKevUpdate(await this.db.listKevCves());
    }

    const toSummarize = (await this.db.listUnsummarizedNews(5)).slice(0, 5);
    for (const item of toSummarize) {
      void this.summarize(item);
    }

    console.log(
      `[aggregator] scanned=${scanned} inserted=${inserted} queued_summaries=${toSummarize.length}`
    );
    return { inserted, scanned };
  }

  async summarize(item: NewsItem): Promise<NewsItem | null> {
    const markdown = await this.llm.summarizeNews(item);
    if (!markdown) return null;
    const updated = await this.db.updateNewsSummary(item.id, markdown);
    const report = await this.db.insertAiReport("news", item.id, markdown);
    hub.broadcast({ type: "ai_report", payload: report });
    if (updated) hub.broadcast({ type: "news", payload: updated });
    return updated;
  }

  private async ingestXml(): Promise<{
    inserted: number;
    scanned: number;
    items: NewsItem[];
  }> {
    const preferred = process.env.CISA_XML_URL || DEFAULT_XML;
    const urls = [preferred, ...XML_FALLBACKS.filter((u) => u !== preferred)];
    let xml = "";
    let used = "";
    for (const url of urls) {
      try {
        xml = await fetchText(url);
        if (xml.includes("<item") || xml.includes("<entry")) {
          used = url;
          break;
        }
      } catch (err) {
        console.warn(`[aggregator] XML fetch failed ${url}:`, (err as Error).message);
      }
    }
    if (!xml) {
      console.warn("[aggregator] no CISA XML feed reachable");
      return { inserted: 0, scanned: 0, items: [] };
    }
    const records = parseRss(xml);
    console.log(`[aggregator] XML ${used} -> ${records.length} items`);
    const items: NewsItem[] = [];
    let inserted = 0;
    for (const rec of records) {
      const cveIds = extractCves(`${rec.title} ${rec.description} ${rec.link}`);
      const hash = sha256(`xml|${rec.title}|${rec.link}|${cveIds.join(",")}`);
      if (await this.db.newsHashExists(hash)) continue;
      const row = await this.db.insertNews({
        source: "xml",
        title: rec.title,
        url: rec.link || null,
        publishedAt: rec.pubDate,
        summary: rec.description || null,
        cveIds,
        vendor: null,
        product: null,
        content: rec.description || null,
        hash
      });
      if (row) {
        inserted += 1;
        items.push(row);
        hub.broadcast({ type: "news", payload: row });
      }
    }
    return { inserted, scanned: records.length, items };
  }

  private async ingestKev(): Promise<{
    inserted: number;
    scanned: number;
    items: NewsItem[];
  }> {
    const url = process.env.CISA_KEV_URL || DEFAULT_KEV;
    let body: { vulnerabilities?: KevVulnerability[] };
    try {
      const text = await fetchText(url);
      body = JSON.parse(text) as { vulnerabilities?: KevVulnerability[] };
    } catch (err) {
      console.warn("[aggregator] KEV fetch failed:", (err as Error).message);
      return { inserted: 0, scanned: 0, items: [] };
    }
    const vulns = Array.isArray(body.vulnerabilities) ? body.vulnerabilities : [];
    const sorted = [...vulns].sort((a, b) =>
      String(b.dateAdded ?? "").localeCompare(String(a.dateAdded ?? ""))
    );
    const items: NewsItem[] = [];
    let inserted = 0;
    for (const vuln of sorted) {
      const cve = (vuln.cveID || "").toUpperCase();
      if (!cve) continue;
      const title =
        vuln.vulnerabilityName ||
        `${vuln.vendorProject ?? "Unknown"} ${vuln.product ?? ""} ${cve}`.trim();
      const hash = sha256(`kev|${cve}|${title}|${vuln.dateAdded ?? ""}`);
      if (await this.db.newsHashExists(hash)) continue;
      const content = [
        vuln.shortDescription,
        vuln.requiredAction ? `Required action: ${vuln.requiredAction}` : "",
        vuln.knownRansomwareCampaignUse
          ? `Ransomware use: ${vuln.knownRansomwareCampaignUse}`
          : "",
        vuln.dueDate ? `Due: ${vuln.dueDate}` : "",
        vuln.notes || ""
      ]
        .filter(Boolean)
        .join("\n");
      const row = await this.db.insertNews({
        source: "kev",
        title,
        url: `https://nvd.nist.gov/vuln/detail/${cve}`,
        publishedAt: vuln.dateAdded ? `${vuln.dateAdded}T00:00:00.000Z` : null,
        summary: vuln.shortDescription ?? null,
        cveIds: [cve],
        vendor: vuln.vendorProject ?? null,
        product: vuln.product ?? null,
        content,
        hash
      });
      if (row) {
        inserted += 1;
        items.push(row);
        hub.broadcast({ type: "news", payload: row });
      }
    }
    return { inserted, scanned: vulns.length, items };
  }
}

async function fetchText(url: string): Promise<string> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 25_000);
  try {
    const res = await fetch(url, {
      signal: controller.signal,
      headers: {
        "User-Agent": UA,
        Accept: "application/rss+xml, application/xml, application/json, text/xml, */*"
      }
    });
    if (!res.ok) {
      throw new Error(`HTTP ${res.status} ${res.statusText}`);
    }
    return await res.text();
  } finally {
    clearTimeout(timer);
  }
}

function parseRss(xml: string): Array<{
  title: string;
  link: string;
  pubDate: string | null;
  description: string;
}> {
  const blocks = [
    ...xml.matchAll(/<item\b[\s\S]*?<\/item>/gi),
    ...xml.matchAll(/<entry\b[\s\S]*?<\/entry>/gi)
  ];
  return blocks
    .map((match) => {
      const block = match[0];
      const title = cleanHtmlText(inner(block, "title") || "Untitled advisory", 180);
      const link =
        inner(block, "link") ||
        attr(block, "link", "href") ||
        inner(block, "guid") ||
        "";
      const pubDate =
        inner(block, "pubDate") ||
        inner(block, "updated") ||
        inner(block, "published") ||
        inner(block, "dc:date");
      const description = cleanHtmlText(
        inner(block, "description") || inner(block, "summary") || "",
        280
      );
      return {
        title,
        link,
        pubDate: normalizeDate(pubDate),
        description
      };
    })
    .filter((item) => item.title);
}

function inner(xml: string, tag: string): string | null {
  const re = new RegExp(
    `<${tag}(?:\\s[^>]*)?>([\\s\\S]*?)<\\/${tag}\\s*>|<${tag}(?:\\s[^>]*)?/>`,
    "i"
  );
  const match = xml.match(re);
  if (!match) return null;
  return (match[1] || "").replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, "$1").trim();
}

function attr(xml: string, tag: string, name: string): string | null {
  const re = new RegExp(`<${tag}[^>]*\\s${name}=["']([^"']+)["'][^>]*>`, "i");
  const match = xml.match(re);
  return match ? match[1] : null;
}

function normalizeDate(value: string | null | undefined): string | null {
  if (!value) return null;
  const d = new Date(value);
  return Number.isNaN(d.getTime()) ? value : d.toISOString();
}

function extractCves(text: string): string[] {
  const found = text.match(CVE_RE) ?? [];
  return [...new Set(found.map((c) => c.toUpperCase()))];
}
