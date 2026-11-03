import { spawn, type ChildProcess } from "node:child_process";
import type { UdpCollector } from "./collector.js";
import { computerName } from "./host.js";

const PREDICATE = `(${[
  'process == "sshd"',
  'process == "sudo"',
  'process == "screensharingd"',
  'process == "syspolicyd"',
  'subsystem == "com.apple.XProtect"',
  'subsystem == "com.apple.syspolicy.exec"',
  'eventMessage CONTAINS[c] "Failed password"',
  'eventMessage CONTAINS[c] "Invalid user"',
  'eventMessage CONTAINS[c] "Accepted publickey"',
  'eventMessage CONTAINS[c] "Accepted password"',
  'eventMessage CONTAINS[c] "Gatekeeper"',
  'eventMessage CONTAINS[c] "malware"'
].join(" OR ")})`;

const DROP =
  /trustd|ocsp|sandboxd|kTCCService|XProtectRemediator|com\.apple\.sandbox|SecError|SecPathBuilder|coreauthd|LocalAuthentication|companions not supported|companionForUser/i;

export function startMacSensor(collector: UdpCollector): () => void {
  let child: ChildProcess | null = null;
  let stopped = false;
  let restart: ReturnType<typeof setTimeout> | null = null;

  const start = () => {
    if (stopped) return;
    try {
      child = spawn(
        "log",
        ["stream", "--style", "syslog", "--level", "info", "--predicate", PREDICATE],
        { stdio: ["ignore", "pipe", "pipe"] }
      );
    } catch (err) {
      console.warn("[sensor] could not start unified log stream", err);
      restart = setTimeout(start, 5000);
      return;
    }

    const host = computerName();
    let buf = "";
    child.stdout?.on("data", (chunk: Buffer) => {
      buf += chunk.toString("utf8");
      const lines = buf.split("\n");
      buf = lines.pop() ?? "";
      for (const line of lines) {
        const trimmed = line.trim();
        if (!trimmed || DROP.test(trimmed)) continue;
        const syslog = trimmed.startsWith("<")
          ? trimmed
          : `<14>1 ${new Date().toISOString()} ${host} unifiedlog - - - ${trimmed}`;
        void collector.ingestLive(syslog, "host", "127.0.0.1");
      }
    });
    child.stderr?.on("data", (chunk: Buffer) => {
      const text = chunk.toString("utf8").trim();
      if (text) console.warn("[sensor]", text.slice(0, 200));
    });
    child.on("exit", (code) => {
      console.warn(`[sensor] log stream exited (${code ?? "?"})`);
      child = null;
      if (!stopped) restart = setTimeout(start, 3000);
    });
    console.log("[sensor] macOS host log stream attached (transport=host)");
  };

  start();
  return () => {
    stopped = true;
    if (restart) clearTimeout(restart);
    child?.kill("SIGTERM");
  };
}
