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

async function undoBlockIp(ip: string): Promise<{ status: "undone" | "failed"; output: string }> {
  ensureAppSupport();
  if (fs.existsSync(BLOCKLIST)) {
    const next = fs
      .readFileSync(BLOCKLIST, "utf8")
      .split("\n")
      .filter((line) => line && line !== ip);
    fs.writeFileSync(BLOCKLIST, next.length ? `${next.join("\n")}\n` : "");
  }
  try {
    const { stdout, stderr } = await execFileAsync(
      "sudo",
      ["-n", "pfctl", "-t", "localsiem", "-T", "delete", ip],
      { timeout: 8000 }
    );
    return {
      status: "undone",
      output: (stdout + stderr).trim() || `Removed ${ip} from pf table localsiem`
    };
  } catch (err) {
    return {
      status: "undone",
      output: `Removed ${ip} from ${BLOCKLIST}. pfctl undo: ${err instanceof Error ? err.message : String(err)}`
    };
  }
}

async function blockIp(ip: string): Promise<{ status: "executed" | "failed"; output: string }> {
  if (!isBlockableIp(ip)) {
    return { status: "failed", output: "Refusing to block this address (loopback, self, or invalid)" };
  }
  ensureAppSupport();
  const existing = fs.existsSync(BLOCKLIST) ? fs.readFileSync(BLOCKLIST, "utf8") : "";
  if (!existing.split("\n").includes(ip)) {
    fs.appendFileSync(BLOCKLIST, `${ip}\n`);
  }
  const notes: string[] = [`Wrote ${ip} to ${BLOCKLIST}`];
  try {
    const { stdout, stderr } = await execFileAsync("sudo", ["-n", "pfctl", "-t", "localsiem", "-T", "add", ip], {
      timeout: 8000
    });
    notes.push((stdout + stderr).trim() || "pfctl table updated");
    return { status: "executed", output: notes.join("\n") };
  } catch (err) {
    notes.push(
      `pfctl needs passwordless sudo for table localsiem. Command: sudo pfctl -t localsiem -T add ${ip}`
    );
    notes.push(err instanceof Error ? err.message : String(err));
    return { status: "executed", output: notes.join("\n") };
  }
}

async function killPid(pidRaw: string): Promise<{ status: "executed" | "failed"; output: string }> {
  const pid = Number(pidRaw);
  if (!Number.isInteger(pid) || pid <= 1 || pid === process.pid) {
    return { status: "failed", output: "Refusing to signal this PID" };
  }
  try {
    const { stdout } = await execFileAsync("ps", ["-p", String(pid), "-o", "comm="], { timeout: 2000 });
    const comm = stdout.trim().replace(/^-/, "");
    if (/^(sshd|trustd|syslogd|launchd|kernel|log|WindowServer|loginwindow|configd)$/i.test(comm)) {
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
    return {
      status: "failed",
      output: "Quarantine is limited to /tmp, Downloads, and Desktop"
    };
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
