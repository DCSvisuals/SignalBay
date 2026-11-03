import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { isMlxModelDir, mlxDirName } from "./mlxCatalog.js";

/** Skip partial downloads that are still named .gguf. */
export const MIN_GGUF_BYTES = 50_000_000;

const NAME_RE = /^[\w.\-()+\s]+\.gguf$/i;

export interface ParsedGguf {
  fileName: string;
  localPath?: string;
  url?: string;
}

export type ModelSource =
  | ({ kind: "gguf" } & ParsedGguf)
  | { kind: "mlx-repo"; repo: string; dirName: string }
  | { kind: "mlx-dir"; localPath: string; dirName: string };

const REPO_RE = /^[A-Za-z0-9][\w.-]{0,80}\/[A-Za-z0-9][\w.-]{0,120}$/;

export function parseModelSource(input: string): ModelSource {
  const raw = input.trim();
  if (!raw) throw new Error("Enter a GGUF path, an MLX folder, or a Hugging Face model");
  if (REPO_RE.test(raw) && !raw.toLowerCase().endsWith(".gguf")) {
    return { kind: "mlx-repo", repo: raw, dirName: mlxDirName(raw) };
  }
  if (/^https?:\/\//i.test(raw)) return parseHttp(raw);
  const local = expandHome(raw);
  if (path.isAbsolute(local) && fs.existsSync(local) && fs.statSync(local).isDirectory()) {
    if (!isMlxModelDir(local)) {
      throw new Error("That folder is not an MLX model. It needs config.json and .safetensors or .npz weights.");
    }
    return { kind: "mlx-dir", localPath: path.resolve(local), dirName: path.basename(path.resolve(local)) };
  }
  return { kind: "gguf", ...parseGgufSource(raw) };
}

function parseHttp(raw: string): ModelSource {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new Error("That link is not a valid URL");
  }
  const parts = url.pathname.split("/").filter(Boolean);
  const last = decodeURIComponent(parts[parts.length - 1] ?? "");
  if (last.toLowerCase().endsWith(".gguf") || parts[2] === "resolve" || parts[2] === "blob") {
    return { kind: "gguf", ...parseGgufSource(raw) };
  }
  if (url.protocol !== "https:") throw new Error("Use an https://huggingface.co link");
  const host = url.hostname.toLowerCase();
  if (host !== "huggingface.co" && host !== "hf.co") {
    throw new Error("Only huggingface.co links can be added here. For a file on this Mac, paste its full path.");
  }
  if (parts.length >= 2 && parts[0] !== "datasets" && parts[0] !== "spaces") {
    const repo = `${parts[0]}/${parts[1]}`;
    return { kind: "mlx-repo", repo, dirName: mlxDirName(repo) };
  }
  throw new Error("Use a Hugging Face model link");
}

function expandHome(text: string): string {
  if (text.startsWith("~/")) return path.join(os.homedir(), text.slice(2));
  return text;
}

export function parseGgufSource(input: string): ParsedGguf {
  const raw = input.trim();
  if (!raw) throw new Error("Enter a GGUF path or a Hugging Face link");
  if (/^https?:\/\//i.test(raw)) return parseUrl(raw);
  return parsePath(raw);
}

function parseUrl(raw: string): ParsedGguf {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new Error("That link is not a valid URL");
  }
  if (url.protocol !== "https:") throw new Error("Use an https://huggingface.co link");
  const host = url.hostname.toLowerCase();
  if (host !== "huggingface.co" && host !== "hf.co") {
    throw new Error("Only huggingface.co links can be added here. For a file on this Mac, paste its full path.");
  }
  const parts = url.pathname.split("/");
  if (parts[3] === "blob") parts[3] = "resolve";
  if (parts[3] !== "resolve" || parts.length < 6) {
    throw new Error("Use a Hugging Face link that points at a .gguf file");
  }
  const fileName = safeGgufName(decodeURIComponent(parts[parts.length - 1] ?? ""));
  url.pathname = parts.join("/");
  url.search = "";
  url.hash = "";
  return { fileName, url: url.toString() };
}

function parsePath(raw: string): ParsedGguf {
  let text = raw;
  if (text.startsWith("~/")) {
    text = path.join(os.homedir(), text.slice(2));
  }
  if (!path.isAbsolute(text)) throw new Error("Use the full path to the .gguf file");
  return { fileName: safeGgufName(text), localPath: path.resolve(text) };
}

function safeGgufName(name: string): string {
  const base = path.basename(name).trim();
  if (!base.toLowerCase().endsWith(".gguf") || !NAME_RE.test(base) || base.length > 180) {
    throw new Error("The model file name must end in .gguf");
  }
  return base;
}

/** Put a local GGUF where the selector can see it. Hardlinks when the disk allows it. */
export function placeLocalGguf(sourcePath: string, modelsDir: string): string {
  const fileName = safeGgufName(sourcePath);
  let stat: fs.Stats;
  try {
    stat = fs.statSync(sourcePath);
  } catch {
    throw new Error("No file at that path");
  }
  if (!stat.isFile()) throw new Error("That path is not a file");
  if (stat.size < MIN_GGUF_BYTES) {
    const mb = Math.max(1, Math.round(stat.size / 1_000_000));
    throw new Error(`That GGUF is ${mb} MB. Add a file of at least 50 MB so a partial download is not loaded.`);
  }
  fs.mkdirSync(modelsDir, { recursive: true });
  const realDir = fs.realpathSync(modelsDir);
  const realSrc = fs.realpathSync(sourcePath);
  const dest = path.join(realDir, fileName);
  if (path.dirname(realSrc) === realDir) return realSrc;
  if (fs.existsSync(dest)) {
    const existing = fs.statSync(dest);
    if (existing.dev === stat.dev && existing.ino === stat.ino) return dest;
    if (existing.size === stat.size) return dest;
    throw new Error(`${fileName} is already in the models folder with a different size`);
  }
  try {
    fs.linkSync(realSrc, dest);
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code;
    if (code !== "EEXIST") fs.copyFileSync(realSrc, dest);
  }
  return dest;
}

/** Symlink an MLX model directory into the selector's mlx folder. */
export function placeMlxDir(sourcePath: string, modelsDir: string): string {
  if (!isMlxModelDir(sourcePath)) {
    throw new Error("That folder is not an MLX model. It needs config.json and .safetensors or .npz weights.");
  }
  const realSrc = fs.realpathSync(sourcePath);
  const root = path.join(modelsDir, "mlx");
  fs.mkdirSync(root, { recursive: true });
  const realRoot = fs.realpathSync(root);
  if (path.dirname(realSrc) === realRoot) return realSrc;
  const dest = path.join(realRoot, path.basename(realSrc));
  if (fs.existsSync(dest)) {
    if (fs.realpathSync(dest) === realSrc) return dest;
    throw new Error(`${path.basename(dest)} is already in the MLX models folder`);
  }
  fs.symlinkSync(realSrc, dest);
  return dest;
}
