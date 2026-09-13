import { isBlockableIp } from "./netguard.js";
import type { EventOrigin, LogEvent, SeverityLabel } from "./types.js";

export interface MitreRef {
  tactic: string;
  technique: string;
  id: string;
}

export interface RuleHit {
  ruleId: string;
  ruleName: string;
  title: string;
  severity: SeverityLabel;
  riskScore: number;
  windowMinutes: number;
  mitre: MitreRef[];
  response?: {
    action: "block_ip" | "kill_pid" | "quarantine";
    target: string;
    command: string;
  };
}

const CVE_RE = /CVE-\d{4}-\d{4,7}/gi;
export const AUTH_FAIL =
  /failed password|invalid user|wrong password|incorrect password attempts|sshd:.*(fail|invalid)|sudo:.*incorrect password|pam_unix\(sshd:auth\): authentication failure/i;
export const NOISE =
  /trustd|ocsp|sandboxd|kTCCService|XProtectRemediator|com\.apple\.sandbox|fetchFailed|SecPathBuilder|SecError|coreauthd|LocalAuthentication|companions not supported|companionForUser/i;

export function isNoise(event: { message: string; appName?: string | null }): boolean {
  return NOISE.test(event.message) || NOISE.test(event.appName ?? "");
}

export function isAuthFailure(message: string, appName?: string | null): boolean {
  if (NOISE.test(message) || NOISE.test(appName ?? "")) return false;
  if (/coreauthd|LocalAuthentication|Touch ID|AppleIDAuth/i.test(`${appName ?? ""} ${message}`)) {
    return false;
  }
  return AUTH_FAIL.test(message);
}
const RANSOM = /ransomware|lockbit|blackcat|alphv|akira|clop|royal ransomware|play ransomware/i;
const SHELL = /reverse shell|meterpreter|cobalt strike|mimikatz|c2 beacon|powershell -enc/i;
const PRIV = /privilege escalation|sudoers|setuid|rootkit|unauthorized sudo/i;
const FIM_HINT = /launchd|launchdaemon|launchagent|crontab|sshd_config|\/etc\/hosts/i;
const IP_RE = /\b(?:\d{1,3}\.){3}\d{1,3}\b/;

const PROTECTED_PROC = /^(sshd|trustd|syslogd|launchd|kernel|log|WindowServer|loginwindow|configd|unifiedlog)$/i;

export function evaluateRules(
  event: LogEvent,
  ctx: { kev: Set<string>; authFailures: number; inventoryCves: Set<string> }
): RuleHit | null {
  if (isNoise(event)) return null;
  const blob = `${event.appName ?? ""} ${event.message}`;
  const cves = [...blob.matchAll(CVE_RE)].map((m) => m[0].toUpperCase());
  const ip = blob.match(IP_RE)?.[0] ?? event.sourceIp;
  const pid = event.procId;
  const block = isBlockableIp(ip) ? blockIp(ip) : undefined;

  const kevHit = cves.find((cve) => ctx.kev.has(cve) && ctx.inventoryCves.has(cve));
  if (kevHit) {
    return {
      ruleId: "100001",
      ruleName: `kev:${kevHit}`,
      title: `KEV match ${kevHit} on ${event.hostname ?? "unknown host"}`,
      severity: "critical",
      riskScore: 95,
      windowMinutes: 180,
      mitre: [
        { id: "T1190", tactic: "Initial Access", technique: "Exploit Public-Facing Application" }
      ],
      response: block
    };
  }

  if (RANSOM.test(blob) || SHELL.test(blob)) {
    return {
      ruleId: "100010",
      ruleName: `hostile:${event.hostname ?? "any"}`,
      title: `Hostile tooling indicator on ${event.hostname ?? "host"}`,
      severity: "critical",
      riskScore: 92,
      windowMinutes: 30,
      mitre: [
        { id: "T1486", tactic: "Impact", technique: "Data Encrypted for Impact" },
        { id: "T1059", tactic: "Execution", technique: "Command and Scripting Interpreter" }
      ],
      response: killPid(pid, event.appName) ?? block
    };
  }

  if (PRIV.test(blob)) {
    return {
      ruleId: "100020",
      ruleName: `priv:${event.hostname ?? "any"}`,
      title: `Privilege anomaly on ${event.hostname ?? "host"}`,
      severity: "high",
      riskScore: 78,
      windowMinutes: 20,
      mitre: [{ id: "T1068", tactic: "Privilege Escalation", technique: "Exploitation for Privilege Escalation" }],
      response: killPid(pid, event.appName)
    };
  }

  if (event.hostname && isAuthFailure(blob, event.appName) && ctx.authFailures >= 4) {
    return {
      ruleId: "100030",
      ruleName: `authburst:${event.hostname}`,
      title: `Auth burst on ${event.hostname} (${ctx.authFailures} fails / 2m)`,
      severity: "high",
      riskScore: 74,
      windowMinutes: 10,
      mitre: [{ id: "T1110", tactic: "Credential Access", technique: "Brute Force" }],
      response: block
    };
  }

  if (FIM_HINT.test(blob) && /write|modify|changed|created|deleted/i.test(blob)) {
    return {
      ruleId: "100040",
      ruleName: `fim:${event.hostname ?? "any"}`,
      title: `Persistence path change on ${event.hostname ?? "host"}`,
      severity: "high",
      riskScore: 80,
      windowMinutes: 30,
      mitre: [{ id: "T1543.001", tactic: "Persistence", technique: "Launch Agent" }]
    };
  }

  return null;
}

export function originOf(_origin: EventOrigin): EventOrigin {
  return _origin;
}

function blockIp(ip: string) {
  return {
    action: "block_ip" as const,
    target: ip,
    command: `sudo -n pfctl -t localsiem -T add ${ip}`
  };
}

function killPid(pid: string | null | undefined, appName?: string | null) {
  if (!pid || PROTECTED_PROC.test(pid) || PROTECTED_PROC.test(appName ?? "")) return undefined;
  const n = Number(pid);
  if (!Number.isInteger(n) || n <= 1) return undefined;
  return {
    action: "kill_pid" as const,
    target: pid,
    command: `kill -TERM ${n}`
  };
}
