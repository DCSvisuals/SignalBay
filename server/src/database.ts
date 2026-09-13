import crypto from "node:crypto";
import sqlite3 from "sqlite3";
import { DB_PATH, ensureAppSupport } from "./paths.js";
import { withNewsMeta } from "./newsMeta.js";
import { cleanHtmlText } from "./text.js";
import type {
  EventOrigin,
  FimRecord,
  Incident,
  InventoryHit,
  InventoryItem,
  LogEvent,
  LogTransport,
  NewsItem,
  ResponseAction,
  SeverityLabel
} from "./types.js";
import { isLogTransport } from "./types.js";

type SqlParams = Array<string | number | null>;

function openDatabase(file: string): Promise<sqlite3.Database> {
  return new Promise((resolve, reject) => {
    const db = new sqlite3.Database(file, (err) => {
      if (err) reject(err);
      else resolve(db);
    });
  });
}

export class SiemDatabase {
  private db!: sqlite3.Database;

  async init(): Promise<void> {
    ensureAppSupport();
    this.db = await openDatabase(DB_PATH);
    this.db.serialize();
    await this.exec("PRAGMA journal_mode = WAL;");
    await this.exec("PRAGMA synchronous = NORMAL;");
    await this.exec("PRAGMA busy_timeout = 5000;");
    await this.exec("PRAGMA cache_size = -64000;");
    await this.exec("PRAGMA temp_store = MEMORY;");
    await this.exec("PRAGMA foreign_keys = ON;");
    await this.exec(`
      CREATE TABLE IF NOT EXISTS events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        received_at TEXT NOT NULL,
        facility INTEGER,
        severity INTEGER,
        hostname TEXT,
        app_name TEXT,
        proc_id TEXT,
        message TEXT NOT NULL,
        raw TEXT NOT NULL,
        source_ip TEXT,
        parsed_json TEXT NOT NULL,
        hash TEXT NOT NULL UNIQUE
      );
    `);
    await this.exec(`
      CREATE TABLE IF NOT EXISTS incidents (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        created_at TEXT NOT NULL,
        title TEXT NOT NULL,
        rule_name TEXT NOT NULL,
        severity TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'open',
        event_ids TEXT NOT NULL,
        evidence TEXT,
        ai_summary TEXT,
        containment_commands TEXT,
        risk_score INTEGER NOT NULL DEFAULT 0
      );
    `);
    await this.exec(`
      CREATE TABLE IF NOT EXISTS news (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        source TEXT NOT NULL,
        title TEXT NOT NULL,
        url TEXT,
        published_at TEXT,
        summary TEXT,
        cve_ids TEXT,
        vendor TEXT,
        product TEXT,
        content TEXT,
        hash TEXT NOT NULL UNIQUE,
        ai_summary TEXT,
        fetched_at TEXT NOT NULL
      );
    `);
    await this.exec(`
      CREATE TABLE IF NOT EXISTS ai_reports (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        created_at TEXT NOT NULL,
        kind TEXT NOT NULL,
        target_id INTEGER NOT NULL,
        markdown TEXT NOT NULL
      );
    `);
    await this.exec("CREATE INDEX IF NOT EXISTS idx_events_received ON events(received_at);");
    await this.exec("CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity);");
    await this.exec("CREATE INDEX IF NOT EXISTS idx_events_hostname ON events(hostname);");
    await this.exec("CREATE INDEX IF NOT EXISTS idx_events_app ON events(app_name);");
    await this.exec("CREATE INDEX IF NOT EXISTS idx_events_hash ON events(hash);");
    await this.exec("CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status, created_at);");
    await this.exec("CREATE INDEX IF NOT EXISTS idx_incidents_severity ON incidents(severity);");
    await this.exec("CREATE INDEX IF NOT EXISTS idx_news_published ON news(published_at);");
    await this.exec("CREATE INDEX IF NOT EXISTS idx_news_hash ON news(hash);");
    await this.exec("CREATE INDEX IF NOT EXISTS idx_news_source ON news(source, fetched_at);");
    await this.exec("CREATE INDEX IF NOT EXISTS idx_ai_kind ON ai_reports(kind, target_id);");
    await this.ensureColumn("events", "origin", "TEXT NOT NULL DEFAULT 'live'");
    await this.ensureColumn("events", "transport", "TEXT NOT NULL DEFAULT 'udp'");
    await this.ensureColumn("incidents", "occurrence_count", "INTEGER NOT NULL DEFAULT 1");
    await this.ensureColumn("incidents", "origin", "TEXT NOT NULL DEFAULT 'live'");
    await this.exec("CREATE INDEX IF NOT EXISTS idx_events_origin ON events(origin, id);");
    await this.exec("CREATE INDEX IF NOT EXISTS idx_events_transport ON events(origin, transport, id);");
    await this.exec("CREATE INDEX IF NOT EXISTS idx_incidents_origin ON incidents(origin, id);");
    await this.ensureColumn("incidents", "mitre", "TEXT");
    await this.exec(`
      CREATE TABLE IF NOT EXISTS iocs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        kind TEXT NOT NULL,
        value TEXT NOT NULL UNIQUE,
        note TEXT,
        created_at TEXT NOT NULL
      );
    `);
    await this.exec(`
      CREATE TABLE IF NOT EXISTS ueba_hours (
        hour_key TEXT NOT NULL,
        hostname TEXT NOT NULL,
        metric TEXT NOT NULL,
        count INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY (hour_key, hostname, metric)
      );
    `);
    await this.exec(`
      CREATE TABLE IF NOT EXISTS audit_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        created_at TEXT NOT NULL,
        actor TEXT NOT NULL,
        action TEXT NOT NULL,
        detail TEXT
      );
    `);
    await this.exec(`
      CREATE TABLE IF NOT EXISTS fim_files (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        path TEXT NOT NULL UNIQUE,
        hash TEXT NOT NULL,
        status TEXT NOT NULL,
        previous_hash TEXT,
        updated_at TEXT NOT NULL,
        origin TEXT NOT NULL DEFAULT 'live'
      );
    `);
    await this.exec(`
      CREATE TABLE IF NOT EXISTS inventory (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL UNIQUE,
        version TEXT,
        path TEXT,
        collected_at TEXT NOT NULL
      );
    `);
    await this.exec(`
      CREATE TABLE IF NOT EXISTS inventory_hits (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        inventory_id INTEGER NOT NULL,
        name TEXT NOT NULL,
        cve TEXT NOT NULL,
        title TEXT NOT NULL,
        collected_at TEXT NOT NULL
      );
    `);
    await this.exec(`
      CREATE TABLE IF NOT EXISTS responses (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        created_at TEXT NOT NULL,
        incident_id INTEGER,
        action TEXT NOT NULL,
        target TEXT NOT NULL,
        command TEXT NOT NULL,
        status TEXT NOT NULL,
        output TEXT,
        origin TEXT NOT NULL DEFAULT 'live'
      );
    `);
    await this.run(
      `UPDATE events SET origin = 'demo'
       WHERE origin = 'live'
         AND hostname IN ('mbp-research.local','mini-build.lan','gateway.home','studio-m4.local')`
    );
    await this.run(
      `UPDATE incidents SET origin = 'demo'
       WHERE origin = 'live'
         AND (title LIKE '%mbp-research%' OR title LIKE '%mini-build%'
           OR title LIKE '%gateway.home%' OR title LIKE '%studio-m4%'
           OR evidence LIKE '%mbp-research%' OR evidence LIKE '%studio-m4%')`
    );
  }

  private async ensureColumn(table: string, name: string, ddl: string): Promise<void> {
    const cols = await this.all<{ name: string }>(`PRAGMA table_info(${table})`);
    if (!cols.some((col) => col.name === name)) {
      await this.exec(`ALTER TABLE ${table} ADD COLUMN ${name} ${ddl}`);
    }
  }

  run(sql: string, params: SqlParams = []): Promise<sqlite3.RunResult> {
    return new Promise((resolve, reject) => {
      this.db.run(sql, params, function onRun(err) {
        if (err) reject(err);
        else resolve(this);
      });
    });
  }

  get<T>(sql: string, params: SqlParams = []): Promise<T | undefined> {
    return new Promise((resolve, reject) => {
      this.db.get(sql, params, (err, row) => {
        if (err) reject(err);
        else resolve(row as T | undefined);
      });
    });
  }

  all<T>(sql: string, params: SqlParams = []): Promise<T[]> {
    return new Promise((resolve, reject) => {
      this.db.all(sql, params, (err, rows) => {
        if (err) reject(err);
        else resolve((rows ?? []) as T[]);
      });
    });
  }

  exec(sql: string): Promise<void> {
    return new Promise((resolve, reject) => {
      this.db.exec(sql, (err) => {
        if (err) reject(err);
        else resolve();
      });
    });
  }

  async insertEvent(input: {
    receivedAt: string;
    facility: number | null;
    severity: number | null;
    hostname: string | null;
    appName: string | null;
    procId: string | null;
    message: string;
    raw: string;
    sourceIp: string | null;
    parsed: Record<string, unknown>;
    hash: string;
    origin?: EventOrigin;
    transport?: LogTransport;
  }): Promise<LogEvent | null> {
    try {
      const origin = input.origin ?? "live";
      const transport = input.transport ?? "udp";
      const result = await this.run(
        `INSERT INTO events (
          received_at, facility, severity, hostname, app_name, proc_id,
          message, raw, source_ip, parsed_json, hash, origin, transport
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [
          input.receivedAt,
          input.facility,
          input.severity,
          input.hostname,
          input.appName,
          input.procId,
          input.message,
          input.raw,
          input.sourceIp,
          JSON.stringify(input.parsed),
          input.hash,
          origin,
          transport
        ]
      );
      const row = await this.get<EventRow>("SELECT * FROM events WHERE id = ?", [
        result.lastID
      ]);
      return row ? mapEvent(row) : null;
    } catch (err) {
      const code = (err as NodeJS.ErrnoException & { code?: string }).code;
      if (code === "SQLITE_CONSTRAINT" || String(err).includes("UNIQUE")) {
        return null;
      }
      throw err;
    }
  }

  async listEvents(opts: {
    limit?: number;
    q?: string;
    before?: string;
    from?: string;
    to?: string;
    transport?: string;
    app?: string;
    origin?: EventOrigin;
  } = {}): Promise<LogEvent[]> {
    const limit = Math.min(Math.max(opts.limit ?? 200, 1), 2000);
    const clauses: string[] = [];
    const params: SqlParams = [];
    clauses.push("origin = ?");
    params.push(opts.origin ?? "live");
    if (opts.q) {
      clauses.push(
        "(message LIKE ? OR hostname LIKE ? OR app_name LIKE ? OR raw LIKE ? OR source_ip LIKE ?)"
      );
      const like = `%${opts.q}%`;
      params.push(like, like, like, like, like);
    }
    if (opts.before) {
      clauses.push("received_at < ?");
      params.push(opts.before);
    }
    if (opts.from) {
      clauses.push("received_at >= ?");
      params.push(opts.from);
    }
    if (opts.to) {
      clauses.push("received_at <= ?");
      params.push(opts.to);
    }
    if (opts.transport) {
      clauses.push("transport = ?");
      params.push(opts.transport);
    }
    if (opts.app) {
      clauses.push("app_name LIKE ?");
      params.push(`%${opts.app}%`);
    }
    const where = clauses.length ? `WHERE ${clauses.join(" AND ")}` : "";
    params.push(limit);
    const rows = await this.all<EventRow>(
      `SELECT * FROM events ${where} ORDER BY id DESC LIMIT ?`,
      params
    );
    return rows.map(mapEvent);
  }

  async getEvent(id: number): Promise<LogEvent | null> {
    const row = await this.get<EventRow>("SELECT * FROM events WHERE id = ?", [id]);
    return row ? mapEvent(row) : null;
  }

  async countEventsSince(iso: string): Promise<number> {
    const row = await this.get<{ n: number }>(
      "SELECT COUNT(*) as n FROM events WHERE received_at >= ?",
      [iso]
    );
    return row?.n ?? 0;
  }

  async recentAuthFailures(
    hostname: string,
    sinceIso: string,
    origin: EventOrigin
  ): Promise<EventRow[]> {
    return this.all<EventRow>(
      `SELECT * FROM events
       WHERE hostname = ?
         AND origin = ?
         AND received_at >= ?
         AND (
           lower(message) LIKE '%failed password%'
           OR lower(message) LIKE '%invalid user%'
           OR lower(message) LIKE '%wrong password%'
           OR lower(message) LIKE '%incorrect password%'
         )
         AND lower(message) NOT LIKE '%ocsp%'
         AND lower(message) NOT LIKE '%trustd%'
         AND lower(message) NOT LIKE '%fetchfailed%'
         AND lower(message) NOT LIKE '%coreauthd%'
         AND lower(message) NOT LIKE '%localauthentication%'
         AND lower(message) NOT LIKE '%companions not supported%'
       ORDER BY id DESC
       LIMIT 40`,
      [hostname, origin, sinceIso]
    );
  }

  async insertIncident(input: {
    title: string;
    ruleName: string;
    severity: SeverityLabel;
    eventIds: number[];
    evidence: string;
    riskScore: number;
    origin?: EventOrigin;
    mitre?: Array<{ id: string; tactic: string; technique: string }>;
  }): Promise<Incident> {
    const createdAt = new Date().toISOString();
    const origin = input.origin ?? "live";
    const result = await this.run(
      `INSERT INTO incidents (
        created_at, title, rule_name, severity, status, event_ids,
        evidence, ai_summary, containment_commands, risk_score, origin, mitre
      ) VALUES (?, ?, ?, ?, 'open', ?, ?, NULL, NULL, ?, ?, ?)`,
      [
        createdAt,
        input.title,
        input.ruleName,
        input.severity,
        JSON.stringify(input.eventIds),
        input.evidence,
        input.riskScore,
        origin,
        JSON.stringify(input.mitre ?? [])
      ]
    );
    const row = await this.get<IncidentRow>("SELECT * FROM incidents WHERE id = ?", [
      result.lastID
    ]);
    if (!row) throw new Error("Failed to load inserted incident");
    return mapIncident(row);
  }

  async listIncidents(opts: { status?: string; origin?: EventOrigin } = {}): Promise<Incident[]> {
    const origin = opts.origin ?? "live";
    const rows = opts.status
      ? await this.all<IncidentRow>(
          "SELECT * FROM incidents WHERE origin = ? AND status = ? ORDER BY id DESC LIMIT 200",
          [origin, opts.status]
        )
      : await this.all<IncidentRow>(
          "SELECT * FROM incidents WHERE origin = ? ORDER BY id DESC LIMIT 200",
          [origin]
        );
    return rows.map(mapIncident);
  }

  async getIncident(id: number): Promise<Incident | null> {
    const row = await this.get<IncidentRow>("SELECT * FROM incidents WHERE id = ?", [id]);
    return row ? mapIncident(row) : null;
  }

  async openIncidentByRule(
    ruleName: string,
    sinceIso: string,
    origin: EventOrigin
  ): Promise<Incident | null> {
    const row = await this.get<IncidentRow>(
      `SELECT * FROM incidents
       WHERE rule_name = ? AND origin = ? AND status = 'open' AND created_at >= ?
       ORDER BY id DESC LIMIT 1`,
      [ruleName, origin, sinceIso]
    );
    return row ? mapIncident(row) : null;
  }

  async touchIncident(
    id: number,
    eventId: number,
    evidence: string,
    riskScore: number
  ): Promise<Incident | null> {
    const current = await this.getIncident(id);
    if (!current) return null;
    const ids = Array.from(new Set([...current.eventIds, eventId])).slice(-80);
    await this.run(
      `UPDATE incidents
       SET occurrence_count = occurrence_count + 1,
           event_ids = ?,
           risk_score = CASE WHEN ? > risk_score THEN ? ELSE risk_score END
       WHERE id = ?`,
      [JSON.stringify(ids), riskScore, riskScore, id]
    );
    return this.getIncident(id);
  }

  async closeNoiseIncidents(): Promise<number> {
    const result = await this.run(
      `UPDATE incidents
       SET status = 'closed'
       WHERE status != 'closed'
         AND (
           lower(ifnull(evidence, '')) LIKE '%ocsp%'
           OR lower(ifnull(evidence, '')) LIKE '%trustd%'
           OR lower(ifnull(evidence, '')) LIKE '%fetchfailed%'
           OR lower(ifnull(evidence, '')) LIKE '%sandboxd%'
           OR lower(ifnull(evidence, '')) LIKE '%ktccservice%'
           OR lower(ifnull(evidence, '')) LIKE '%coreauthd%'
           OR lower(ifnull(evidence, '')) LIKE '%localauthentication%'
           OR lower(ifnull(evidence, '')) LIKE '%companions not supported%'
         )`
    );
    return result.changes ?? 0;
  }

  async pruneEvents(keep = 200_000, maxAgeDays = 7): Promise<number> {
    const cutoff = new Date(Date.now() - maxAgeDays * 24 * 60 * 60 * 1000).toISOString();
    const old = await this.run("DELETE FROM events WHERE received_at < ?", [cutoff]);
    const overflow = await this.run(
      `DELETE FROM events WHERE id NOT IN (
         SELECT id FROM events ORDER BY id DESC LIMIT ?
       )`,
      [keep]
    );
    return (old.changes ?? 0) + (overflow.changes ?? 0);
  }

  async expirePendingResponses(maxAgeHours = 24): Promise<number> {
    const cutoff = new Date(Date.now() - maxAgeHours * 60 * 60 * 1000).toISOString();
    const result = await this.run(
      `UPDATE responses
       SET status = 'denied', output = 'Expired (not confirmed in time)'
       WHERE status = 'pending' AND created_at < ?`,
      [cutoff]
    );
    return result.changes ?? 0;
  }

  async updateIncidentStatus(id: number, status: "open" | "ack" | "closed"): Promise<Incident | null> {
    await this.run("UPDATE incidents SET status = ? WHERE id = ?", [status, id]);
    return this.getIncident(id);
  }

  async updateIncidentAi(
    id: number,
    aiSummary: string,
    containmentCommands: string | null
  ): Promise<Incident | null> {
    await this.run(
      "UPDATE incidents SET ai_summary = ?, containment_commands = ? WHERE id = ?",
      [aiSummary, containmentCommands, id]
    );
    return this.getIncident(id);
  }

  async newsHashExists(hash: string): Promise<boolean> {
    const row = await this.get<{ n: number }>(
      "SELECT COUNT(*) as n FROM news WHERE hash = ?",
      [hash]
    );
    return (row?.n ?? 0) > 0;
  }

  async insertNews(input: {
    source: "xml" | "kev";
    title: string;
    url: string | null;
    publishedAt: string | null;
    summary: string | null;
    cveIds: string[];
    vendor: string | null;
    product: string | null;
    content: string | null;
    hash: string;
  }): Promise<NewsItem | null> {
    try {
      const fetchedAt = new Date().toISOString();
      const result = await this.run(
        `INSERT INTO news (
          source, title, url, published_at, summary, cve_ids, vendor, product,
          content, hash, ai_summary, fetched_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?)`,
        [
          input.source,
          input.title,
          input.url,
          input.publishedAt,
          input.summary,
          JSON.stringify(input.cveIds),
          input.vendor,
          input.product,
          input.content,
          input.hash,
          fetchedAt
        ]
      );
      const row = await this.get<NewsRow>("SELECT * FROM news WHERE id = ?", [
        result.lastID
      ]);
      return row ? mapNews(row) : null;
    } catch (err) {
      if (String(err).includes("UNIQUE")) return null;
      throw err;
    }
  }

  async listNews(limit = 80): Promise<NewsItem[]> {
    const rows = await this.all<NewsRow>(
      `SELECT * FROM news
       ORDER BY COALESCE(published_at, fetched_at) DESC
       LIMIT ?`,
      [limit]
    );
    return rows.map(mapNews);
  }

  async listNewsByCves(cves: string[], limit = 40): Promise<NewsItem[]> {
    const unique = [...new Set(cves.map((cve) => cve.trim().toUpperCase()).filter(Boolean))];
    if (!unique.length) return [];
    const direct = await this.queryNewsByCves(unique, limit);
    const related = new Set<string>();
    for (const item of direct) {
      for (const cve of item.cveIds) {
        const id = cve.toUpperCase();
        if (!unique.includes(id)) related.add(id);
      }
    }
    if (!related.size) return direct;
    const extra = await this.queryNewsByCves([...related], limit);
    const seen = new Set(direct.map((item) => item.id));
    for (const item of extra) {
      if (!seen.has(item.id)) direct.push(item);
    }
    return direct.slice(0, limit);
  }

  private async queryNewsByCves(cves: string[], limit: number): Promise<NewsItem[]> {
    const clauses: string[] = [];
    const params: SqlParams = [];
    for (const cve of cves.slice(0, 12)) {
      const needle = `%${cve}%`;
      clauses.push(
        "(upper(cve_ids) LIKE ? OR upper(title) LIKE ? OR upper(ifnull(summary,'')) LIKE ? OR upper(ifnull(content,'')) LIKE ?)"
      );
      params.push(needle, needle, needle, needle);
    }
    params.push(limit);
    const rows = await this.all<NewsRow>(
      `SELECT * FROM news
       WHERE ${clauses.join(" OR ")}
       ORDER BY COALESCE(published_at, fetched_at) DESC
       LIMIT ?`,
      params
    );
    return rows.map(mapNews);
  }

  async getNews(id: number): Promise<NewsItem | null> {
    const row = await this.get<NewsRow>("SELECT * FROM news WHERE id = ?", [id]);
    return row ? mapNews(row) : null;
  }

  async listUnsummarizedNews(limit = 6): Promise<NewsItem[]> {
    const rows = await this.all<NewsRow>(
      `SELECT * FROM news
       WHERE ai_summary IS NULL
       ORDER BY COALESCE(published_at, fetched_at) DESC
       LIMIT ?`,
      [limit]
    );
    return rows.map(mapNews);
  }

  async updateNewsSummary(id: number, markdown: string): Promise<NewsItem | null> {
    await this.run("UPDATE news SET ai_summary = ? WHERE id = ?", [markdown, id]);
    return this.getNews(id);
  }

  async listKevCves(): Promise<string[]> {
    const rows = await this.all<{ cve_ids: string }>(
      "SELECT cve_ids FROM news WHERE source = 'kev'"
    );
    const set = new Set<string>();
    for (const row of rows) {
      try {
        const ids = JSON.parse(row.cve_ids) as string[];
        for (const id of ids) set.add(id.toUpperCase());
      } catch {
        /* ignore */
      }
    }
    return [...set];
  }

  async listKevCatalog(): Promise<Array<{ cve: string; vendor: string; product: string; title: string }>> {
    const rows = await this.all<{ title: string; vendor: string | null; product: string | null; cve_ids: string }>(
      "SELECT title, vendor, product, cve_ids FROM news WHERE source = 'kev' LIMIT 2000"
    );
    const out: Array<{ cve: string; vendor: string; product: string; title: string }> = [];
    for (const row of rows) {
      let ids: string[] = [];
      try {
        ids = JSON.parse(row.cve_ids) as string[];
      } catch {
        ids = [];
      }
      for (const cve of ids) {
        out.push({
          cve: cve.toUpperCase(),
          vendor: row.vendor ?? "",
          product: row.product ?? "",
          title: row.title
        });
      }
    }
    return out;
  }

  async getFimFile(filePath: string): Promise<FimRecord | null> {
    const row = await this.get<{
      id: number;
      path: string;
      hash: string;
      status: FimRecord["status"];
      previous_hash: string | null;
      updated_at: string;
      origin: EventOrigin;
    }>("SELECT * FROM fim_files WHERE path = ?", [filePath]);
    return row ? mapFim(row) : null;
  }

  async upsertFimFile(input: {
    path: string;
    hash: string;
    status: FimRecord["status"];
    origin: EventOrigin;
    previousHash?: string;
  }): Promise<FimRecord> {
    const updatedAt = new Date().toISOString();
    await this.run(
      `INSERT INTO fim_files (path, hash, status, previous_hash, updated_at, origin)
       VALUES (?, ?, ?, ?, ?, ?)
       ON CONFLICT(path) DO UPDATE SET
         hash = excluded.hash,
         status = excluded.status,
         previous_hash = excluded.previous_hash,
         updated_at = excluded.updated_at`,
      [input.path, input.hash, input.status, input.previousHash ?? null, updatedAt, input.origin]
    );
    const row = await this.getFimFile(input.path);
    if (!row) throw new Error("FIM upsert failed");
    return row;
  }

  async listFim(origin: EventOrigin, changedOnly = true): Promise<FimRecord[]> {
    const rows = changedOnly
      ? await this.all<Parameters<typeof mapFim>[0]>(
          "SELECT * FROM fim_files WHERE origin = ? AND status = 'changed' ORDER BY updated_at DESC LIMIT 80",
          [origin]
        )
      : await this.all<Parameters<typeof mapFim>[0]>(
          "SELECT * FROM fim_files WHERE origin = ? ORDER BY updated_at DESC LIMIT 80",
          [origin]
        );
    return rows.map(mapFim);
  }

  async upsertInventory(input: {
    name: string;
    version: string | null;
    path: string | null;
  }): Promise<InventoryItem> {
    const collectedAt = new Date().toISOString();
    await this.run(
      `INSERT INTO inventory (name, version, path, collected_at)
       VALUES (?, ?, ?, ?)
       ON CONFLICT(name) DO UPDATE SET
         version = excluded.version,
         path = excluded.path,
         collected_at = excluded.collected_at`,
      [input.name, input.version, input.path, collectedAt]
    );
    const row = await this.get<{
      id: number;
      name: string;
      version: string | null;
      path: string | null;
      collected_at: string;
    }>("SELECT * FROM inventory WHERE name = ?", [input.name]);
    if (!row) throw new Error("inventory upsert failed");
    return {
      id: row.id,
      name: row.name,
      version: row.version,
      path: row.path,
      collectedAt: row.collected_at
    };
  }

  async insertInventoryHit(input: {
    inventoryId: number;
    name: string;
    cve: string;
    title: string;
  }): Promise<InventoryHit> {
    const existing = await this.get<{ id: number }>(
      "SELECT id FROM inventory_hits WHERE inventory_id = ? AND cve = ?",
      [input.inventoryId, input.cve]
    );
    const collectedAt = new Date().toISOString();
    if (existing) {
      return {
        id: existing.id,
        inventoryId: input.inventoryId,
        name: input.name,
        cve: input.cve,
        title: input.title,
        collectedAt
      };
    }
    const result = await this.run(
      `INSERT INTO inventory_hits (inventory_id, name, cve, title, collected_at)
       VALUES (?, ?, ?, ?, ?)`,
      [input.inventoryId, input.name, input.cve, input.title, collectedAt]
    );
    return {
      id: result.lastID,
      inventoryId: input.inventoryId,
      name: input.name,
      cve: input.cve,
      title: input.title,
      collectedAt
    };
  }

  async clearInventoryHits(): Promise<void> {
    await this.run("DELETE FROM inventory_hits");
  }

  async listInventoryHits(): Promise<InventoryHit[]> {
    const rows = await this.all<{
      id: number;
      inventory_id: number;
      name: string;
      cve: string;
      title: string;
      collected_at: string;
    }>("SELECT * FROM inventory_hits ORDER BY id DESC LIMIT 80");
    return rows.map((row) => ({
      id: row.id,
      inventoryId: row.inventory_id,
      name: row.name,
      cve: row.cve,
      title: row.title,
      collectedAt: row.collected_at
    }));
  }

  async insertResponse(input: Omit<ResponseAction, "id" | "createdAt" | "output" | "status"> & {
    status?: ResponseAction["status"];
  }): Promise<ResponseAction> {
    const createdAt = new Date().toISOString();
    const status = input.status ?? "pending";
    const result = await this.run(
      `INSERT INTO responses (created_at, incident_id, action, target, command, status, output, origin)
       VALUES (?, ?, ?, ?, ?, ?, NULL, ?)`,
      [createdAt, input.incidentId, input.action, input.target, input.command, status, input.origin]
    );
    return {
      id: result.lastID,
      createdAt,
      incidentId: input.incidentId,
      action: input.action,
      target: input.target,
      command: input.command,
      status,
      output: null,
      origin: input.origin
    };
  }

  async listResponses(origin: EventOrigin, status?: ResponseAction["status"]): Promise<ResponseAction[]> {
    const rows = status
      ? await this.all<ResponseRow>(
          "SELECT * FROM responses WHERE origin = ? AND status = ? ORDER BY id DESC LIMIT 80",
          [origin, status]
        )
      : await this.all<ResponseRow>(
          "SELECT * FROM responses WHERE origin = ? ORDER BY id DESC LIMIT 80",
          [origin]
        );
    return rows.map(mapResponse);
  }

  async getResponse(id: number): Promise<ResponseAction | null> {
    const row = await this.get<ResponseRow>("SELECT * FROM responses WHERE id = ?", [id]);
    return row ? mapResponse(row) : null;
  }

  async updateResponse(
    id: number,
    status: ResponseAction["status"],
    output: string
  ): Promise<ResponseAction | null> {
    await this.run("UPDATE responses SET status = ?, output = ? WHERE id = ?", [status, output, id]);
    return this.getResponse(id);
  }

  async insertAiReport(kind: "news" | "incident" | "event", targetId: number, markdown: string) {
    const createdAt = new Date().toISOString();
    const result = await this.run(
      "INSERT INTO ai_reports (created_at, kind, target_id, markdown) VALUES (?, ?, ?, ?)",
      [createdAt, kind, targetId, markdown]
    );
    return {
      id: result.lastID,
      createdAt,
      kind,
      targetId,
      markdown
    };
  }

  async counts(): Promise<{
    events: number;
    incidents: number;
    news: number;
    fimChanges: number;
    inventoryHits: number;
    pendingResponses: number;
  }> {
    const events = await this.get<{ n: number }>("SELECT COUNT(*) as n FROM events");
    const incidents = await this.get<{ n: number }>("SELECT COUNT(*) as n FROM incidents");
    const news = await this.get<{ n: number }>("SELECT COUNT(*) as n FROM news");
    const fimChanges = await this.get<{ n: number }>(
      "SELECT COUNT(*) as n FROM fim_files WHERE status = 'changed'"
    );
    const inventoryHits = await this.get<{ n: number }>("SELECT COUNT(*) as n FROM inventory_hits");
    const pendingResponses = await this.get<{ n: number }>(
      "SELECT COUNT(*) as n FROM responses WHERE status = 'pending'"
    );
    return {
      events: events?.n ?? 0,
      incidents: incidents?.n ?? 0,
      news: news?.n ?? 0,
      fimChanges: fimChanges?.n ?? 0,
      inventoryHits: inventoryHits?.n ?? 0,
      pendingResponses: pendingResponses?.n ?? 0
    };
  }

  async listIocs(): Promise<Array<{ id: number; kind: string; value: string; note: string | null; createdAt: string }>> {
    const rows = await this.all<{
      id: number;
      kind: string;
      value: string;
      note: string | null;
      created_at: string;
    }>("SELECT * FROM iocs ORDER BY id DESC");
    return rows.map((row) => ({
      id: row.id,
      kind: row.kind,
      value: row.value,
      note: row.note,
      createdAt: row.created_at
    }));
  }

  async upsertIoc(kind: string, value: string, note: string | null): Promise<void> {
    await this.run(
      `INSERT INTO iocs (kind, value, note, created_at) VALUES (?, ?, ?, ?)
       ON CONFLICT(value) DO UPDATE SET kind = excluded.kind, note = excluded.note`,
      [kind, value.trim(), note, new Date().toISOString()]
    );
  }

  async deleteIoc(id: number): Promise<void> {
    await this.run("DELETE FROM iocs WHERE id = ?", [id]);
  }

  async bumpUeba(hostname: string, metric: string): Promise<{ count: number; baseline: number }> {
    const hour = new Date().toISOString().slice(0, 13);
    await this.run(
      `INSERT INTO ueba_hours (hour_key, hostname, metric, count) VALUES (?, ?, ?, 1)
       ON CONFLICT(hour_key, hostname, metric) DO UPDATE SET count = count + 1`,
      [hour, hostname, metric]
    );
    const row = await this.get<{ count: number }>(
      "SELECT count FROM ueba_hours WHERE hour_key = ? AND hostname = ? AND metric = ?",
      [hour, hostname, metric]
    );
    const avg = await this.get<{ avg: number }>(
      `SELECT AVG(count) as avg FROM ueba_hours WHERE hostname = ? AND metric = ? AND hour_key != ?`,
      [hostname, metric, hour]
    );
    return { count: row?.count ?? 1, baseline: Number(avg?.avg ?? 0) };
  }

  async insertAudit(actor: string, action: string, detail: string): Promise<void> {
    await this.run("INSERT INTO audit_log (created_at, actor, action, detail) VALUES (?, ?, ?, ?)", [
      new Date().toISOString(),
      actor,
      action,
      detail
    ]);
  }

  async reportSummary(hours = 24): Promise<Record<string, unknown>> {
    const since = new Date(Date.now() - hours * 3600 * 1000).toISOString();
    const events = await this.get<{ n: number }>(
      "SELECT COUNT(*) as n FROM events WHERE received_at >= ? AND origin = 'live'",
      [since]
    );
    const open = await this.get<{ n: number }>(
      "SELECT COUNT(*) as n FROM incidents WHERE status = 'open' AND origin = 'live'"
    );
    const high = await this.get<{ n: number }>(
      "SELECT COUNT(*) as n FROM incidents WHERE status = 'open' AND severity IN ('high','critical') AND origin = 'live'"
    );
    const bySev = await this.all<{ severity: string; n: number }>(
      "SELECT severity, COUNT(*) as n FROM incidents WHERE origin = 'live' GROUP BY severity"
    );
    const topHosts = await this.all<{ hostname: string; n: number }>(
      `SELECT hostname, COUNT(*) as n FROM events
       WHERE received_at >= ? AND origin = 'live' AND hostname IS NOT NULL
       GROUP BY hostname ORDER BY n DESC LIMIT 8`,
      [since]
    );
    const byTransport = await this.all<{ transport: string; n: number }>(
      `SELECT transport, COUNT(*) as n FROM events
       WHERE received_at >= ? AND origin = 'live' GROUP BY transport`,
      [since]
    );
    return {
      generatedAt: new Date().toISOString(),
      windowHours: hours,
      events: events?.n ?? 0,
      openIncidents: open?.n ?? 0,
      highOpen: high?.n ?? 0,
      bySeverity: Object.fromEntries(bySev.map((row) => [row.severity, row.n])),
      topHosts,
      byTransport,
      retentionDays: 7,
      hotWindowHours: 48
    };
  }

  close(): Promise<void> {
    return new Promise((resolve, reject) => {
      this.db.close((err) => (err ? reject(err) : resolve()));
    });
  }
}

export interface EventRow {
  id: number;
  received_at: string;
  facility: number | null;
  severity: number | null;
  hostname: string | null;
  app_name: string | null;
  proc_id: string | null;
  message: string;
  raw: string;
  source_ip: string | null;
  parsed_json: string;
  hash: string;
  origin?: EventOrigin;
  transport?: string;
}

interface IncidentRow {
  id: number;
  created_at: string;
  title: string;
  rule_name: string;
  severity: SeverityLabel;
  status: "open" | "ack" | "closed";
  event_ids: string;
  evidence: string | null;
  ai_summary: string | null;
  containment_commands: string | null;
  risk_score: number;
  origin?: EventOrigin;
  mitre?: string | null;
  occurrence_count?: number;
}

interface NewsRow {
  id: number;
  source: "xml" | "kev";
  title: string;
  url: string | null;
  published_at: string | null;
  summary: string | null;
  cve_ids: string | null;
  vendor: string | null;
  product: string | null;
  content: string | null;
  hash: string;
  ai_summary: string | null;
  fetched_at: string;
}

export function mapEvent(row: EventRow): LogEvent {
  let parsed: Record<string, unknown> = {};
  try {
    parsed = JSON.parse(row.parsed_json) as Record<string, unknown>;
  } catch {
    parsed = {};
  }
  return {
    id: row.id,
    receivedAt: row.received_at,
    facility: row.facility,
    severity: row.severity,
    severityLabel: syslogSeverityLabel(row.severity),
    hostname: row.hostname,
    appName: row.app_name,
    procId: row.proc_id,
    message: row.message,
    raw: row.raw,
    sourceIp: row.source_ip,
    parsed,
    hash: row.hash,
    origin: row.origin === "demo" ? "demo" : "live",
    transport: isLogTransport(row.transport) ? row.transport : "udp"
  };
}

function mapIncident(row: IncidentRow): Incident {
  let eventIds: number[] = [];
  try {
    eventIds = JSON.parse(row.event_ids) as number[];
  } catch {
    eventIds = [];
  }
  return {
    id: row.id,
    createdAt: row.created_at,
    title: row.title,
    ruleName: row.rule_name,
    severity: row.severity,
    status: row.status,
    eventIds,
    evidence: row.evidence ?? "",
    aiSummary: row.ai_summary,
    containmentCommands: row.containment_commands,
    riskScore: row.risk_score,
    origin: row.origin === "demo" ? "demo" : "live",
    mitre: parseMitre(row.mitre),
    occurrenceCount: row.occurrence_count ?? 1
  };
}

interface ResponseRow {
  id: number;
  created_at: string;
  incident_id: number | null;
  action: ResponseAction["action"];
  target: string;
  command: string;
  status: ResponseAction["status"];
  output: string | null;
  origin: EventOrigin;
}

function mapFim(row: {
  id: number;
  path: string;
  hash: string;
  status: FimRecord["status"];
  previous_hash: string | null;
  updated_at: string;
  origin: EventOrigin;
}): FimRecord {
  return {
    id: row.id,
    path: row.path,
    hash: row.hash,
    status: row.status,
    previousHash: row.previous_hash,
    updatedAt: row.updated_at,
    origin: row.origin
  };
}

function mapResponse(row: ResponseRow): ResponseAction {
  return {
    id: row.id,
    createdAt: row.created_at,
    incidentId: row.incident_id,
    action: row.action,
    target: row.target,
    command: row.command,
    status: row.status,
    output: row.output,
    origin: row.origin === "demo" ? "demo" : "live"
  };
}

function parseMitre(raw: string | null | undefined): Array<{ id: string; tactic: string; technique: string }> {
  if (!raw) return [];
  try {
    const value = JSON.parse(raw) as Array<{ id: string; tactic: string; technique: string }>;
    return Array.isArray(value) ? value : [];
  } catch {
    return [];
  }
}

function mapNews(row: NewsRow): NewsItem {
  let cveIds: string[] = [];
  try {
    cveIds = row.cve_ids ? (JSON.parse(row.cve_ids) as string[]) : [];
  } catch {
    cveIds = [];
  }
  return withNewsMeta({
    id: row.id,
    source: row.source,
    title: cleanHtmlText(row.title, 180),
    url: row.url,
    publishedAt: row.published_at,
    summary: cleanHtmlText(row.summary, 280),
    cveIds,
    vendor: row.vendor,
    product: row.product,
    content: cleanHtmlText(row.content, 1200),
    hash: row.hash,
    aiSummary: row.ai_summary,
    fetchedAt: row.fetched_at
  });
}

export function syslogSeverityLabel(severity: number | null): SeverityLabel {
  if (severity === null || severity === undefined) return "info";
  if (severity <= 1) return "critical";
  if (severity === 2) return "high";
  if (severity === 3) return "medium";
  if (severity === 4) return "low";
  return "info";
}

export function sha256(value: string): string {
  return crypto.createHash("sha256").update(value).digest("hex");
}
