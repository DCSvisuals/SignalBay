import { execFile } from "node:child_process";
import { getSettings } from "./settings.js";

function escapeAppleScript(value: string): string {
  return value
    .replace(/\\/g, "\\\\")
    .replace(/'/g, "\\'")
    .replace(/\n/g, "\\n")
    .replace(/\r/g, "\\r")
    .replace(/\t/g, "\\t");
}

export function notifyHigh(title: string, body: string): void {
  const safeTitle = escapeAppleScript(title).slice(0, 80);
  const safeBody = escapeAppleScript(body).slice(0, 180);
  execFile(
    "osascript",
    ["-e", `display notification '${safeBody}' with title 'Signalbay' subtitle '${safeTitle}'`],
    () => undefined
  );
  const url = getSettings().webhookUrl;
  if (!url) return;
  void fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      source: "Signalbay",
      title,
      body,
      at: new Date().toISOString()
    })
  }).catch((err) => {
    console.warn("[notify] webhook failed", err instanceof Error ? err.message : err);
  });
}
