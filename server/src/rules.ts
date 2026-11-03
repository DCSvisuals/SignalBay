import { ipScope } from "./enrich.js";
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

export interface BuiltinDetection {
  id: string;
  name: string;
  summary: string;
}

export const BUILTIN_DETECTIONS: BuiltinDetection[] = [
  { id: "100030", name: "SSH auth burst", summary: "Four failed logins on one host within two minutes." },
  { id: "100031", name: "Login after failures", summary: "A successful login lands inside a failure window." },
  { id: "100032", name: "First-seen login source", summary: "SSH or sudo succeeds from an address this host has not used in 30 days." },
  { id: "100050", name: "Untrusted execution path", summary: "A log names /tmp, Downloads, or a hidden directory." },
  { id: "100051", name: "XProtect or Gatekeeper", summary: "macOS blocked malware or an invalid code signature." },
  { id: "100052", name: "Firewall deny", summary: "pf or the application firewall dropped a packet." },
  { id: "100040", name: "File integrity change", summary: "A watched persistence file changed after its baseline." },
  { id: "100010", name: "Hostile tooling string", summary: "The line names ransomware or an offensive tool. Useful for forwarded alerts." },
  { id: "100020", name: "Privilege wording", summary: "The line names privilege escalation, a rootkit, or sudoers changes." },
  { id: "100001", name: "KEV on installed software", summary: "A log mentions a CISA KEV CVE that matched this Mac at high confidence." },
  { id: "chain-priv", name: "Auth burst then sudo", summary: "Sudo succeeds while an auth-burst incident is still open." }
];

const CVE_RE = /CVE-\d{4}-\d{4,7}/gi;
export const AUTH_FAIL =
  /failed password|invalid user|wrong password|incorrect password attempts|sshd:.*(fail|invalid)|sudo:.*incorrect password|pam_unix\(sshd:auth\): authentication failure/i;
export const NOISE =
  /trustd|ocsp|sandboxd|kTCCService|XProtectRemediator|com\.apple\.sandbox|fetchFailed|SecPathBuilder|SecError|coreauthd|LocalAuthentication|companions not supported|companionForUser/i;
const AUTH_OK = /accepted (password|publickey)|session opened for user/i;
const SUDO_OK = /sudo:/i;
const RANSOM = /ransomware|lockbit|blackcat|alphv|akira|clop|royal ransomware|play ransomware/i;
const SHELL = /reverse shell|meterpreter|cobalt strike|mimikatz|c2 beacon|powershell -enc/i;
const PRIV = /privilege escalation|sudoers|setuid|rootkit|unauthorized sudo/i;
const UNTRUSTED_PATH = /(?:\/private\/tmp\/|\/tmp\/|\/Downloads\/|\/\.[A-Za-z0-9_-]+\/)/;
const XPROTECT = /xprotect|gatekeeper|malware detected|code signature invalid/i;
const FIREWALL = /(?:^|\s)pf:|socketfilterfw|firewall/i;
const FIREWALL_DENY = /\b(dropped|deny|denied|blocked)\b/i;
const IP_RE = /\b(?:\d{1,3}\.){3}\d{1,3}\b/;
const PROTECTED_PROC = /^(sshd|trustd|syslogd|launchd|kernel|log|WindowServer|loginwindow|configd|unifiedlog)$/i;

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

export function isAuthSuccess(message: string): boolean {
  return AUTH_OK.test(message);
}

export function isSudoSuccess(message: string, appName?: string | null): boolean {
  const blob = `${appName ?? ""} ${message}`;
  return SUDO_OK.test(blob) && /COMMAND=/i.test(message) && !/incorrect|failure|sorry|incorrect password/i.test(message);
}

function publicIp(ip: string | null | undefined): boolean {
  return ipScope(ip) === "public";
}

export function evaluateRules(
  event: LogEvent,
  ctx: {
    kev: Set<string>;
    authFailures: number;
    inventoryCves: Set<string>;
    firstSeenSrc?: boolean;
    authSuccessAfterFail?: boolean;
  }
): RuleHit | null {
  if (isNoise(event)) return null;
  const blob = `${event.appName ?? ""} ${event.message}`;
  const cves = [...blob.matchAll(CVE_RE)].map((m) => m[0].toUpperCase());
  const ip = event.srcIp || blob.match(IP_RE)?.[0] || event.sourceIp;
  const block = ip && isBlockableIp(ip) ? blockIp(ip) : undefined;
  const action = event.action ?? "";

  if (event.appName === "fim" || action === "fim_change") {
    return {
      ruleId: "100040",
      ruleName: `fim:${event.hostname ?? "any"}`,
      title: `Persistence file changed on ${event.hostname ?? "host"}`,
      severity: "high",
      riskScore: 80,
      windowMinutes: 30,
      mitre: [{ id: "T1543.001", tactic: "Persistence", technique: "Launch Agent" }]
    };
  }

  const kevHit = cves.find((cve) => ctx.kev.has(cve) && ctx.inventoryCves.has(cve));
  if (kevHit) {
    return {
      ruleId: "100001",
      ruleName: `kev:${kevHit}`,
      title: `KEV match ${kevHit} on ${event.hostname ?? "unknown host"}`,
      severity: "critical",
      riskScore: 95,
      windowMinutes: 180,
      mitre: [{ id: "T1190", tactic: "Initial Access", technique: "Exploit Public-Facing Application" }],
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
      response: killPid(event.procId, event.appName) ?? block
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
      response: killPid(event.procId, event.appName)
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

  if (ctx.authSuccessAfterFail && isAuthSuccess(event.message)) {
    const fromPublic = publicIp(ip);
    return {
      ruleId: "100031",
      ruleName: `auth-success:${event.hostname ?? "any"}`,
      title: `Login succeeded after ${ctx.authFailures} failures on ${event.hostname ?? "host"}${fromPublic ? " from a public address" : ""}`,
      severity: fromPublic ? "critical" : "high",
      riskScore: fromPublic ? 90 : 76,
      windowMinutes: 15,
      mitre: [{ id: "T1110", tactic: "Credential Access", technique: "Brute Force" }],
      response: fromPublic ? block : undefined
    };
  }

  if (ctx.firstSeenSrc && (isAuthSuccess(event.message) || isSudoSuccess(event.message, event.appName)) && ip) {
    const fromPublic = publicIp(ip);
    return {
      ruleId: "100032",
      ruleName: `new-src:${event.hostname ?? "any"}:${ip}`,
      title: `First-seen ${fromPublic ? "public " : ""}source ${ip} on ${event.hostname ?? "host"}`,
      severity: fromPublic ? "high" : "medium",
      riskScore: fromPublic ? 70 : 48,
      windowMinutes: 60,
      mitre: [{ id: "T1078", tactic: "Defense Evasion", technique: "Valid Accounts" }]
    };
  }

  if (UNTRUSTED_PATH.test(blob)) {
    return {
      ruleId: "100050",
      ruleName: `untrusted-path:${event.hostname ?? "any"}`,
      title: `Execution path outside trusted directories on ${event.hostname ?? "host"}`,
      severity: "high",
      riskScore: 77,
      windowMinutes: 20,
      mitre: [{ id: "T1204", tactic: "Execution", technique: "User Execution" }]
    };
  }

  if (XPROTECT.test(blob)) {
    return {
      ruleId: "100051",
      ruleName: `xprotect:${event.hostname ?? "any"}`,
      title: `macOS protection event on ${event.hostname ?? "host"}`,
      severity: "high",
      riskScore: 84,
      windowMinutes: 30,
      mitre: [{ id: "T1204.002", tactic: "Execution", technique: "Malicious File" }]
    };
  }

  if (FIREWALL.test(blob) && FIREWALL_DENY.test(blob) && !/\ballow\b/i.test(event.message)) {
    return {
      ruleId: "100052",
      ruleName: `fw-deny:${event.hostname ?? "any"}`,
      title: `Firewall deny on ${event.hostname ?? "host"}`,
      severity: "medium",
      riskScore: 46,
      windowMinutes: 15,
      mitre: [{ id: "T1046", tactic: "Discovery", technique: "Network Service Discovery" }]
    };
  }

  return null;
}

export function originOf(_origin: EventOrigin): EventOrigin {
  return _origin;
}

export function blockIp(ip: string) {
  return {
    action: "block_ip" as const,
    target: ip,
    command: `sudo -n pfctl -t localsiem -T add ${ip}`
  };
}

export function killPid(pid: string | null | undefined, appName?: string | null) {
  if (!pid || PROTECTED_PROC.test(pid) || PROTECTED_PROC.test(appName ?? "")) return undefined;
  const n = Number(pid);
  if (!Number.isInteger(n) || n <= 1) return undefined;
  return {
    action: "kill_pid" as const,
    target: pid,
    command: `kill -TERM ${n}`
  };
}

export function responseForCustom(
  action: "block_ip" | "kill_pid" | "quarantine",
  target: string | null | undefined,
  event: LogEvent
): RuleHit["response"] | undefined {
  if (action === "block_ip") {
    const ip = target || event.srcIp || "";
    if (!isBlockableIp(ip)) return undefined;
    return blockIp(ip);
  }
  if (action === "kill_pid") return killPid(target || event.procId, event.appName);
  if (action === "quarantine" && target) {
    return { action: "quarantine", target, command: `quarantine ${target}` };
  }
  return undefined;
}
