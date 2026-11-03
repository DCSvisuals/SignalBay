import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { once } from "node:events";
import fs from "node:fs";
import path from "node:path";
import readline from "node:readline";
import { fileURLToPath } from "node:url";
import { APP_SUPPORT } from "./paths.js";

interface WorkerReply {
  ok?: boolean;
  error?: string;
  text?: string;
}

function pythonBin(): string {
  if (process.env.MLX_PYTHON) return process.env.MLX_PYTHON;
  const venv = path.join(APP_SUPPORT, "py", "bin", "python");
  if (fs.existsSync(venv)) return venv;
  return "python3";
}

function workerScript(): string {
  const here = path.dirname(fileURLToPath(import.meta.url));
  const candidates = [path.join(here, "mlx_worker.py"), path.join(here, "../src/mlx_worker.py")];
  return candidates.find((file) => fs.existsSync(file)) ?? candidates[0];
}

export class MlxWorker {
  private child: ChildProcessWithoutNullStreams | null = null;
  private pending: ((reply: WorkerReply) => void) | null = null;
  private failed: string | null = null;

  async load(modelDir: string): Promise<void> {
    await this.send({ op: "load", path: modelDir });
  }

  async complete(system: string, prompt: string, maxTokens: number): Promise<string> {
    const reply = await this.send({ op: "prompt", system, prompt, max_tokens: maxTokens });
    return (reply.text ?? "").trim();
  }

  stop(): void {
    const child = this.child;
    this.child = null;
    this.pending = null;
    this.failed = null;
    if (!child || child.killed) return;
    child.kill("SIGTERM");
  }

  private async send(payload: Record<string, unknown>): Promise<WorkerReply> {
    const child = this.ensure();
    if (this.pending) throw new Error("MLX worker is busy");
    const reply = await new Promise<WorkerReply>((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending = null;
        reject(new Error("MLX worker timed out"));
      }, 10 * 60 * 1000);
      this.pending = (message) => {
        clearTimeout(timer);
        if (message.ok === false) reject(new Error(message.error || "MLX request failed"));
        else resolve(message);
      };
      child.stdin.write(`${JSON.stringify(payload)}\n`);
    });
    return reply;
  }

  private ensure(): ChildProcessWithoutNullStreams {
    if (this.failed) throw new Error(this.failed);
    if (this.child && this.child.exitCode === null && !this.child.killed) return this.child;
    const script = workerScript();
    const child = spawn(pythonBin(), [script], { stdio: ["pipe", "pipe", "pipe"] });
    this.child = child;
    const lines = readline.createInterface({ input: child.stdout });
    lines.on("line", (line) => {
      let message: WorkerReply;
      try {
        message = JSON.parse(line) as WorkerReply;
      } catch {
        return;
      }
      if (message.ok === false && message.error) this.failed = message.error;
      const wait = this.pending;
      this.pending = null;
      wait?.(message);
    });
    child.stderr.on("data", (chunk: Buffer) => {
      const text = chunk.toString().trim();
      if (text) console.warn(`[mlx] ${text}`);
    });
    child.on("error", (err) => {
      this.failed = err.message;
      const wait = this.pending;
      this.pending = null;
      this.child = null;
      wait?.({ ok: false, error: err.message });
    });
    child.on("exit", (code) => {
      if (this.child === child) {
        this.failed = `MLX worker exited (${code ?? "signal"})`;
        this.child = null;
      }
      const wait = this.pending;
      this.pending = null;
      wait?.({ ok: false, error: this.failed ?? "MLX worker exited" });
    });
    return child;
  }
}

const DOWNLOAD_PY = `
import sys
from huggingface_hub import snapshot_download
snapshot_download(
    repo_id=sys.argv[1],
    local_dir=sys.argv[2],
    allow_patterns=["*.safetensors", "*.json", "*.txt", "*.model", "tokenizer*", "*.tiktoken"],
)
`;

export async function downloadMlxRepo(repo: string, dest: string): Promise<void> {
  fs.mkdirSync(path.dirname(dest), { recursive: true });
  const child = spawn(pythonBin(), ["-c", DOWNLOAD_PY, repo, dest], { stdio: ["ignore", "pipe", "pipe"] });
  let err = "";
  child.stderr.on("data", (chunk: Buffer) => {
    err = `${err}${chunk.toString()}`.slice(-4000);
  });
  const [code] = (await once(child, "exit")) as [number | null];
  if (code !== 0) {
    fs.rmSync(dest, { recursive: true, force: true });
    throw new Error(
      err.trim().slice(-500) ||
        `Could not download ${repo}. Install MLX support with the Signalbay Python env.`
    );
  }
}
