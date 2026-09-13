import { execFileSync } from "node:child_process";
import fs from "node:fs";
import net from "node:net";
import path from "node:path";
import tls from "node:tls";
import { APP_SUPPORT, ensureAppSupport } from "./paths.js";

export function peerIp(addr?: string): string {
  if (!addr) return "0.0.0.0";
  return addr.replace(/^::ffff:/, "");
}

export function ensureTlsMaterial(): { key: Buffer; cert: Buffer; certPath: string } {
  ensureAppSupport();
  const keyPath = path.join(APP_SUPPORT, "syslog-tls.key");
  const certPath = path.join(APP_SUPPORT, "syslog-tls.crt");
  if (!fs.existsSync(keyPath) || !fs.existsSync(certPath)) {
    execFileSync(
      "openssl",
      [
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-keyout",
        keyPath,
        "-out",
        certPath,
        "-days",
        "3650",
        "-nodes",
        "-subj",
        "/CN=LocalSIEM-syslog"
      ],
      { stdio: ["ignore", "pipe", "pipe"] }
    );
    fs.chmodSync(keyPath, 0o600);
    console.log(`[collector] TLS cert written to ${certPath}`);
  }
  return {
    key: fs.readFileSync(keyPath),
    cert: fs.readFileSync(certPath),
    certPath
  };
}

/** RFC 6587: octet-counting (`len SP msg`) or non-transparent (NL-terminated). */
export class SyslogFrameBuffer {
  private buf = Buffer.alloc(0);

  push(chunk: Buffer): string[] {
    this.buf = Buffer.concat([this.buf, chunk]);
    const out: string[] = [];
    while (this.buf.length) {
      const head = this.buf.toString("latin1", 0, Math.min(this.buf.length, 16));
      const counted = head.match(/^(\d{1,9}) /);
      if (counted) {
        const n = Number(counted[1]);
        const header = counted[0].length;
        if (this.buf.length < header + n) return out;
        const msg = this.buf.subarray(header, header + n).toString("utf8").replace(/\u0000/g, "").trim();
        this.buf = this.buf.subarray(header + n);
        if (msg) out.push(msg);
        continue;
      }
      if (/^\d+$/.test(head) && this.buf.length < 24) return out;
      const nl = this.buf.indexOf(0x0a);
      if (nl === -1) {
        if (this.buf.length > 64 * 1024) {
          const msg = this.buf.toString("utf8").replace(/\u0000/g, "").trim();
          this.buf = Buffer.alloc(0);
          if (msg) out.push(msg);
        }
        return out;
      }
      const msg = this.buf.subarray(0, nl).toString("utf8").replace(/\r$/, "").replace(/\u0000/g, "").trim();
      this.buf = this.buf.subarray(nl + 1);
      if (msg) out.push(msg);
    }
    return out;
  }

  flush(): string[] {
    const msg = this.buf.toString("utf8").replace(/\u0000/g, "").trim();
    this.buf = Buffer.alloc(0);
    return msg ? [msg] : [];
  }
}

export interface RelpFrame {
  txnr: string;
  command: string;
  data: string;
}

/** librelp / rsyslog RELP: `txnr SP command SP datalen [SP data] LF` */
export class RelpBuffer {
  private buf = Buffer.alloc(0);

  push(chunk: Buffer): RelpFrame[] {
    this.buf = Buffer.concat([this.buf, chunk]);
    const frames: RelpFrame[] = [];
    while (this.buf.length) {
      const head = this.buf.toString("latin1", 0, Math.min(this.buf.length, 48));
      const m = head.match(/^(\d{1,9}) ([A-Za-z]+) (\d{1,9})/);
      if (!m) {
        if (this.buf.length > 2048) this.buf = Buffer.alloc(0);
        break;
      }
      const txnr = m[1];
      const command = m[2].toLowerCase();
      const datalen = Number(m[3]);
      let offset = Buffer.byteLength(m[0], "latin1");
      if (datalen > 0) {
        if (this.buf.length <= offset) break;
        if (this.buf[offset] === 0x20) offset += 1;
        if (this.buf.length < offset + datalen) break;
        const data = this.buf.subarray(offset, offset + datalen).toString("utf8");
        let end = offset + datalen;
        if (end < this.buf.length && this.buf[end] === 0x0d) end += 1;
        if (end < this.buf.length && this.buf[end] === 0x0a) end += 1;
        this.buf = this.buf.subarray(end);
        frames.push({ txnr, command, data });
      } else {
        if (this.buf.length <= offset) break;
        if (this.buf[offset] === 0x20) offset += 1;
        if (this.buf.length <= offset) break;
        if (this.buf[offset] === 0x0d) offset += 1;
        if (this.buf.length <= offset) break;
        if (this.buf[offset] === 0x0a) offset += 1;
        this.buf = this.buf.subarray(offset);
        frames.push({ txnr, command, data: "" });
      }
    }
    return frames;
  }
}

export function relpReply(txnr: string, body: string): string {
  return `${txnr} rsp ${Buffer.byteLength(body, "utf8")} ${body}\n`;
}

export async function listenPort<T>(
  preferred: number,
  fallback: number,
  label: string,
  bind: (port: number) => Promise<T>
): Promise<{ server: T; port: number }> {
  const tried = [preferred, fallback];
  let lastError: unknown;
  for (const port of tried) {
    try {
      const server = await bind(port);
      console.log(`[collector] ${label} listening on 0.0.0.0:${port}`);
      return { server, port };
    } catch (err) {
      lastError = err;
      const code = (err as NodeJS.ErrnoException).code;
      if (code === "EACCES" || code === "EADDRINUSE") {
        console.warn(`[collector] ${label} port ${port} unavailable (${code}); trying fallback`);
        continue;
      }
      throw err;
    }
  }
  throw lastError ?? new Error(`Unable to bind ${label}`);
}

export function bindNet(port: number, onSocket: (socket: net.Socket) => void): Promise<net.Server> {
  return new Promise((resolve, reject) => {
    const server = net.createServer(onSocket);
    const onError = (err: Error) => {
      server.close();
      reject(err);
    };
    server.once("error", onError);
    server.listen(port, "0.0.0.0", () => {
      server.off("error", onError);
      server.on("error", (err) => console.error("[collector] tcp server error", err));
      resolve(server);
    });
  });
}

export function bindTls(
  port: number,
  material: { key: Buffer; cert: Buffer },
  onSocket: (socket: tls.TLSSocket) => void
): Promise<tls.Server> {
  return new Promise((resolve, reject) => {
    const server = tls.createServer(
      {
        key: material.key,
        cert: material.cert,
        requestCert: false,
        rejectUnauthorized: false
      },
      onSocket
    );
    const onError = (err: Error) => {
      server.close();
      reject(err);
    };
    server.once("error", onError);
    server.listen(port, "0.0.0.0", () => {
      server.off("error", onError);
      server.on("error", (err) => console.error("[collector] tls server error", err));
      resolve(server);
    });
  });
}

export function closeServer(server: net.Server | null): Promise<void> {
  return new Promise((resolve) => {
    if (!server) return resolve();
    server.close(() => resolve());
  });
}
