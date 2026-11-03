import assert from "node:assert/strict";
import test from "node:test";
import { parseEventPayload } from "./parse.js";
import { parseSyslogTimestamp } from "./time.js";
import { toFtsQuery } from "./ftsQuery.js";

test("RFC 5424 keeps the syslog timestamp", () => {
  const received = new Date("2026-10-11T12:00:00.000Z");
  const raw = "<86>1 2026-10-11T11:58:00.000Z mac.local sshd 22 - - Failed password for david from 203.0.113.10 port 22 ssh2";
  const parsed = parseEventPayload(raw, { address: "127.0.0.1", port: 1514 }, received);
  assert.equal(parsed.eventTime, "2026-10-11T11:58:00.000Z");
  assert.equal(parsed.appName, "sshd");
  assert.equal(parsed.hostname, "mac.local");
  assert.match(parsed.message, /Failed password/);
});

test("RFC 3164 without a year uses the receive year", () => {
  const received = new Date(2026, 9, 11, 12, 0, 0);
  const stamp = parseSyslogTimestamp("Oct 11 11:58:00", received);
  const parsed = new Date(stamp);
  assert.equal(parsed.getFullYear(), 2026);
  assert.equal(parsed.getMonth(), 9);
  assert.equal(parsed.getDate(), 11);
  assert.equal(parsed.getHours(), 11);
});

test("a January stamp received in December belongs to the next calendar year boundary", () => {
  const received = new Date(2026, 0, 1, 0, 30, 0);
  const stamp = parseSyslogTimestamp("Dec 31 23:50:00", received);
  assert.equal(new Date(stamp).getFullYear(), 2025);
});

test("JSON ingest keeps its own timestamp and fields", () => {
  const raw = JSON.stringify({
    timestamp: "2026-10-11T01:02:03.000Z",
    hostname: "mac.local",
    app: "auditd",
    message: "privilege escalation watch",
    pid: 44
  });
  const parsed = parseEventPayload(raw, { address: "127.0.0.1", port: 0 });
  assert.equal(parsed.eventTime, "2026-10-11T01:02:03.000Z");
  assert.equal(parsed.appName, "auditd");
  assert.equal(parsed.procId, "44");
});

test("hunt text becomes an FTS prefix query", () => {
  assert.equal(toFtsQuery("Failed password"), `"failed"* AND "password"*`);
  assert.equal(toFtsQuery("a"), null);
});
