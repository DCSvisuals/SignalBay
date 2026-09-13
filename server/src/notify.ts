import { execFile } from "node:child_process";

export function notifyHigh(title: string, body: string): void {
  const safeTitle = title.replace(/"/g, "'").slice(0, 80);
  const safeBody = body.replace(/"/g, "'").slice(0, 180);
  execFile(
    "osascript",
    ["-e", `display notification "${safeBody}" with title "LocalSIEM" subtitle "${safeTitle}"`],
    () => undefined
  );
}
