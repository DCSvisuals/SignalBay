import assert from "node:assert/strict";
import test from "node:test";
import { evaluateRules, isNoise } from "./rules.js";
import { isSuppressed } from "./settings.js";
import type { LogEvent } from "./types.js";

function event(partial: Partial<LogEvent>): LogEvent {
  return {
    id: 1,
    receivedAt: "2026-10-11T12:00:00.000Z",
    eventTime: "2026-10-11T12:00:00.000Z",
    facility: 4,
    severity: 5,
    severityLabel: "info",
    hostname: "mac.local",
    appName: "sshd",
    procId: "22",
    message: "",
    raw: "",
    sourceIp: "203.0.113.10",
    srcIp: "203.0.113.10",
    userName: "david",
    category: "auth",
    action: null,
    parsed: {},
    hash: "abc",
    origin: "live",
    transport: "udp",
    ...partial
  };
}

const empty = { kev: new Set<string>(), authFailures: 0, inventoryCves: new Set<string>() };

test("auth burst needs four failures", () => {
  const row = event({ message: "Failed password for david from 203.0.113.10 port 22 ssh2" });
  assert.equal(evaluateRules(row, { ...empty, authFailures: 3 }), null);
  const hit = evaluateRules(row, { ...empty, authFailures: 4 });
  assert.equal(hit?.ruleId, "100030");
  assert.equal(hit?.response?.action, "block_ip");
});

test("a successful login after failures is its own incident", () => {
  const row = event({
    message: "Accepted publickey for david from 203.0.113.10 port 22 ssh2",
    action: "login_success"
  });
  const hit = evaluateRules(row, { ...empty, authFailures: 4, authSuccessAfterFail: true });
  assert.equal(hit?.ruleId, "100031");
  assert.equal(hit?.severity, "critical");
});

test("ordinary sudo success does not alert", () => {
  const row = event({
    appName: "sudo",
    message: "david : TTY=ttys001 ; PWD=/Users/david ; USER=root ; COMMAND=/usr/bin/true",
    action: "sudo_success",
    srcIp: "127.0.0.1"
  });
  assert.equal(evaluateRules(row, empty), null);
});

test("first-seen public source alerts", () => {
  const row = event({
    message: "Accepted password for david from 203.0.113.10 port 22 ssh2",
    action: "login_success"
  });
  const hit = evaluateRules(row, { ...empty, firstSeenSrc: true });
  assert.equal(hit?.ruleId, "100032");
});

test("tmp, XProtect, firewall, and fim each have a behavior rule", () => {
  assert.equal(
    evaluateRules(event({ appName: "endpointsecurity", message: "exec /private/tmp/.hidden/launcher" }), empty)?.ruleId,
    "100050"
  );
  assert.equal(
    evaluateRules(event({ appName: "syspolicyd", message: "code signature invalid for Helper.app" }), empty)?.ruleId,
    "100051"
  );
  assert.equal(
    evaluateRules(event({ appName: "kernel", message: "pf: dropped in on en0 proto tcp from 203.0.113.8" }), empty)?.ruleId,
    "100052"
  );
  assert.equal(evaluateRules(event({ appName: "fim", message: "file changed /Library/LaunchAgents/a.plist", action: "fim_change" }), empty)?.ruleId, "100040");
});

test("macOS trust noise never becomes an incident", () => {
  const row = event({ appName: "trustd", message: "Failed password OCSP fetchFailed" });
  assert.equal(isNoise(row), true);
  assert.equal(evaluateRules(row, { ...empty, authFailures: 9 }), null);
});

test("a process exception suppresses the matching detection", () => {
  assert.equal(
    isSuppressed(
      { hostname: "mac.local", appName: "sshd", srcIp: "203.0.113.10" },
      "100030",
      [{ id: "1", kind: "process", value: "sshd", note: "", enabled: true }]
    ),
    true
  );
  assert.equal(
    isSuppressed(
      { hostname: "mac.local", appName: "sudo", srcIp: "203.0.113.10" },
      "100030",
      [{ id: "1", kind: "process", value: "sshd", note: "", enabled: true }]
    ),
    false
  );
});
