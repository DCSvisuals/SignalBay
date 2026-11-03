import { execFile } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { promisify } from "node:util";
import { isBlockableIp } from "./netguard.js";
import { APP_SUPPORT, ensureAppSupport } from "./paths.js";
import type { ResponseAction } from "./types.js";

const execFileAsync = promisify(execFile);
const BLOCKLIST = path.join(APP_SUPPORT, "blocklist.txt");
const QUARANTINE = path.join(APP_SUPPORT, "quarantine");

const ALLOWED = new Set(["block_ip", "kill_pid", "quarantine"]);
const PROTECTED_PROCS =
  /^(sshd|trustd|syslogd|launchd|kernel|log|WindowServer|loginwindow|configd|kernel_task|taskgated)$/i;

export async function executeResponse(action: ResponseAction): Promise<{
  status: "executed" | "failed";
  output: string;
}> {
  if (!ALLOWED.has(action.action)) {
    return { status: "failed", output: "Unknown action" };
  }
  try {
    if (action.action === "block_ip") return await blockIp(action.target);
    if (action.action === "kill_pid") return await killPid(action.target);
    return await quarantinePath(action.target);
  } catch (err) {
    return { status: "failed", output: err instanceof Error ? err.message : String(err) };
  }
}

export async function undoResponse(action: ResponseAction): Promise<{
  status: "undone" | "failed";
  output: string;
}> {
  if (action.action !== "block_ip") {
    return { status: "failed", output: "Undo is only implemented for block_ip" };
  }
  return undoBlockIp(action.target);
}

function listedIps(): string[] {
  if (!fs.existsSync(BLOCKLIST)) return [];
  return fs
    .readFileSync(BLOCKLIST, "utf8")
    .split("\n")
    .map((line) => line.trim())
    .filter(Boolean);
}

function anchorPath(): string {
  return path.join(APP_SUPPORT, "localsiem.pf.conf");
}

export function renderAnchor(ips: string[]): string {
  const body = ips.length ? ips.join(" ") : "";
  return [
    `table <localsiem> persist { ${body} }`,
    "block drop in quick from <localsiem> to any",
    "block drop out quick from any to <localsiem>",
    ""
  ].join("\n");
}

export async function pfTableStatus(): Promise<{ ready: boolean; detail: string; anchor: string }> {
  const anchor = anchorPath();
  try {
    const { stdout, stderr } = await execFileAsync("sudo", ["-n", "pfctl", "-t", "localsiem", "-T", "show"], {
      timeout: 8000
    });
    return { ready: true, detail: (stdout || stderr).trim() || "pf table localsiem is loaded", anchor };
  } catch (err) {
    const detail = err instanceof Error ? err.message : String(err);
    return {
      ready: false,
      detail: `${detail}\nLoad the anchor with: sudo pfctl -a localsiem -f ${anchor}`,
      anchor
    };
  }
}

async function reloadAnchor(ips: string[]): Promise<{ ok: boolean; detail: string }> {
  ensureAppSupport();
  const file = anchorPath();
  fs.writeFileSync(file, renderAnchor(ips));
  try {
    const { stdout, stderr } = await execFileAsync("sudo", ["-n", "pfctl", "-a", "localsiem", "-f", file], {
      timeout: 8000
    });
    return { ok: true, detail: (stdout + stderr).trim() || `Loaded ${file}` };
  } catch (err) {
    return { ok: false, detail: err instanceof Error ? err.message : String(err) };
  }
}

async function undoBlockIp(ip: string): Promise<{ status: "undone" | "failed"; output: string }> {
  ensureAppSupport();
  const next = listedIps().filter((line) => line !== ip);
  fs.writeFileSync(BLOCKLIST, next.length ? `${next.join("\n")}\n` : "");
  const loaded = await reloadAnchor(next);
  if (!loaded.ok) {
    return {
      status: "failed",
      output: `Removed ${ip} from ${BLOCKLIST}. pf still has the old anchor: ${loaded.detail}`
    };
  }
  return { status: "undone", output: `Removed ${ip} from the localsiem anchor. ${loaded.detail}`.trim() };
}

async function blockIp(ip: string): Promise<{ status: "executed" | "failed"; output: string }> {
  if (!isBlockableIp(ip)) {
    return { status: "failed", output: "Refusing to block this address (loopback, self, or invalid)" };
  }
  ensureAppSupport();
  const ips = listedIps();
  if (!ips.includes(ip)) ips.push(ip);
  fs.writeFileSync(BLOCKLIST, ips.length ? `${ips.join("\n")}\n` : "");
  const loaded = await reloadAnchor(ips);
  const notes = [`Wrote ${ip} to ${BLOCKLIST}`];
  if (!loaded.ok) {
    notes.push("pf did not load the anchor. The address is listed, and it is not blocked.");
    notes.push(loaded.detail);
    notes.push("Run scripts/install_pf_anchor.sh, then confirm the action again.");
    return { status: "failed", output: notes.join("\n") };
  }
  notes.push(loaded.detail || "pf anchor localsiem reloaded");
  return { status: "executed", output: notes.join("\n") };
}

async function killPid(pidRaw: string): Promise<{ status: "executed" | "failed"; output: string }> {
  const pid = Number(pidRaw);
  if (!Number.isInteger(pid) || pid <= 1 || pid === process.pid) {
    return { status: "failed", output: "Refusing to signal this PID" };
  }
  if (pid > 999999) {
    return { status: "failed", output: "PID out of range" };
  }
  try {
    const { stdout } = await execFileAsync("ps", ["-p", String(pid), "-o", "comm=", "uid="], { timeout: 2000 });
    const parts = stdout.trim().split(/\s+/);
    const comm = parts[0]?.replace(/^-/, "") ?? "";
    const uid = parts[1];
    if (uid === "0") {
      return { status: "failed", output: `Refusing to kill root-owned process ${comm} (${pid})` };
    }
    if (PROTECTED_PROCS.test(comm)) {
      return { status: "failed", output: `Refusing to kill protected process ${comm} (${pid})` };
    }
  } catch {
    /* process may already be gone */
  }
  try {
    process.kill(pid, "SIGTERM");
    return { status: "executed", output: `Sent SIGTERM to pid ${pid}` };
  } catch (err) {
    return { status: "failed", output: err instanceof Error ? err.message : String(err) };
  }
}

async function quarantinePath(target: string): Promise<{ status: "executed" | "failed"; output: string }> {
  const resolved = path.resolve(target);
  const home = process.env.HOME ?? "";
  const allowedRoots = ["/tmp", "/private/tmp", path.join(home, "Downloads"), path.join(home, "Desktop")];
  if (!allowedRoots.some((root) => resolved === root || resolved.startsWith(`${root}/`))) {
    return { status: "failed", output: "Quarantine is limited to /tmp, Downloads, and Desktop" };
  }
  if (!fs.existsSync(resolved)) {
    return { status: "failed", output: `Path not found: ${resolved}` };
  }
  ensureAppSupport();
  fs.mkdirSync(QUARANTINE, { recursive: true });
  const dest = path.join(QUARANTINE, `${Date.now()}-${path.basename(resolved)}`);
  fs.renameSync(resolved, dest);
  return { status: "executed", output: `Moved ${resolved} -> ${dest}` };
}
