import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { SiemDatabase } from "./database.js";
import { APP_SUPPORT } from "./paths.js";

test("stored events keep event time and are searchable", async () => {
  const file = path.join(os.tmpdir(), `localsiem-${Date.now()}-${Math.random().toString(16).slice(2)}.db`);
  const db = new SiemDatabase(file);
  await db.init();
  const eventTime = "2026-10-11T11:58:00.000Z";
  const saved = await db.insertEvent({
    receivedAt: "2026-10-11T12:00:00.000Z",
    eventTime,
    facility: 10,
    severity: 5,
    hostname: "mac.local",
    appName: "sshd",
    procId: "22",
    message: "Failed password for david from 203.0.113.10 port 22 ssh2",
    raw: "raw",
    sourceIp: "127.0.0.1",
    parsed: { user: "david", src_ip: "203.0.113.10", category: "auth", action: "login_failure" },
    hash: "hash-1",
    origin: "live",
    transport: "udp"
  });
  assert.ok(saved);
  assert.equal(saved?.eventTime, eventTime);
  assert.equal(saved?.userName, "david");
  assert.equal(saved?.srcIp, "203.0.113.10");
  const found = await db.listEvents({ q: "failed password", origin: "live" });
  assert.equal(found.length, 1);
  assert.equal(found[0]?.action, "login_failure");
  const byUser = await db.listEvents({ user: "david", origin: "live" });
  assert.equal(byUser.length, 1);
  const entity = await db.entityView("ip", "203.0.113.10", "live");
  assert.equal(entity.eventCount, 1);
  await db.addCaseNote(1, "operator", "checked the source");
  await db.close();
  fs.rmSync(file, { force: true });
  fs.rmSync(`${file}-wal`, { force: true });
  fs.rmSync(`${file}-shm`, { force: true });
});

const OLD_INSERT = `
  CREATE TRIGGER events_fts_insert AFTER INSERT ON events BEGIN
    INSERT INTO events_fts(rowid, message, hostname, app_name, raw, user_name, src_ip)
    VALUES (
      new.id, new.message, coalesce(new.hostname, ''), coalesce(new.app_name, ''),
      new.raw, coalesce(new.user_name, ''), coalesce(new.src_ip, '')
    );
  END;
`;

const OLD_DELETE = `
  CREATE TRIGGER events_fts_delete AFTER DELETE ON events BEGIN
    INSERT INTO events_fts(events_fts, rowid, message, hostname, app_name, raw, user_name, src_ip)
    VALUES (
      'delete', old.id, old.message, coalesce(old.hostname, ''), coalesce(old.app_name, ''),
      old.raw, coalesce(old.user_name, ''), coalesce(old.src_ip, '')
    );
  END;
`;

function archiveSnapshot(): Set<string> {
  const dir = path.join(APP_SUPPORT, "archive");
  if (!fs.existsSync(dir)) return new Set();
  return new Set(fs.readdirSync(dir));
}

function removeNewArchives(before: Set<string>): void {
  const dir = path.join(APP_SUPPORT, "archive");
  if (!fs.existsSync(dir)) return;
  for (const name of fs.readdirSync(dir)) {
    if (!before.has(name)) fs.rmSync(path.join(dir, name), { force: true });
  }
}

test("retention delete stays consistent after the old full-text triggers", async () => {
  const file = path.join(os.tmpdir(), `localsiem-${Date.now()}-${Math.random().toString(16).slice(2)}.db`);
  const planted = new SiemDatabase(file);
  await planted.init();
  await planted.exec("DROP TRIGGER IF EXISTS events_fts_insert");
  await planted.exec("DROP TRIGGER IF EXISTS events_fts_delete");
  await planted.exec(OLD_INSERT);
  await planted.exec(OLD_DELETE);
  for (let n = 1; n <= 3; n += 1) {
    const saved = await planted.insertEvent({
      receivedAt: `2020-01-0${n}T00:00:00.000Z`,
      facility: 4,
      severity: 4,
      hostname: null,
      appName: null,
      procId: null,
      message: `file changed /private/tmp/.hidden/launcher ${n}`,
      raw: `raw-null-host-${n}`,
      sourceIp: null,
      parsed: {},
      hash: `hash-null-host-${n}`,
      origin: "live",
      transport: "host"
    });
    assert.ok(saved);
  }
  const kept = await planted.insertEvent({
    receivedAt: "2099-01-01T00:00:00.000Z",
    facility: 10,
    severity: 5,
    hostname: "mac.local",
    appName: "sshd",
    procId: "22",
    message: "kept sshd failure from 203.0.113.10",
    raw: "raw-kept",
    sourceIp: "127.0.0.1",
    parsed: { user: "david", src_ip: "203.0.113.10", category: "auth", action: "login_failure" },
    hash: "hash-kept",
    origin: "live",
    transport: "udp"
  });
  assert.ok(kept);
  await planted.close();

  const before = archiveSnapshot();
  const db = new SiemDatabase(file);
  await db.init();
  const trigger = await db.get<{ sql: string }>(
    "SELECT sql FROM sqlite_master WHERE name = 'events_fts_delete'"
  );
  assert.equal((trigger?.sql ?? "").toLowerCase().includes("coalesce"), false);
  const aligned = await db.get<{ e: number; d: number }>(
    "SELECT (SELECT COUNT(*) FROM events) AS e, (SELECT COUNT(*) FROM events_fts_docsize) AS d"
  );
  assert.equal(aligned?.e, 4);
  assert.equal(aligned?.d, 4);
  const removed = await db.pruneEvents(200_000, 1);
  assert.equal(removed, 3);
  await db.exec("INSERT INTO events_fts(events_fts) VALUES('integrity-check')");
  const found = await db.listEvents({ q: "sshd failure", origin: "live" });
  assert.equal(found.length, 1);
  assert.equal(found[0]?.srcIp, "203.0.113.10");
  const cleared = await db.pruneEvents(0, 3650);
  assert.equal(cleared, 1);
  const check = await db.get<{ integrity_check: string }>("PRAGMA integrity_check");
  assert.equal(check?.integrity_check, "ok");
  const left = await db.listEvents({ origin: "live" });
  assert.equal(left.length, 0);
  await db.close();
  removeNewArchives(before);
  fs.rmSync(file, { force: true });
  fs.rmSync(`${file}-wal`, { force: true });
  fs.rmSync(`${file}-shm`, { force: true });
});
