import fs from "node:fs";
import path from "node:path";
import { MODELS_DIR, ensureAppSupport } from "./paths.js";
import type { LlmOption } from "./types.js";

export interface MlxModel {
  id: string;
  label: string;
  repo: string;
  dirName: string;
}

export const MLX_MODELS: MlxModel[] = [
  {
    id: "mlx-qwen-3b",
    label: "MLX Qwen 2.5 3B 4-bit",
    repo: "mlx-community/Qwen2.5-3B-Instruct-4bit",
    dirName: "mlx-community__Qwen2.5-3B-Instruct-4bit"
  },
  {
    id: "mlx-qwen-7b",
    label: "MLX Qwen 2.5 7B 4-bit",
    repo: "mlx-community/Qwen2.5-7B-Instruct-4bit",
    dirName: "mlx-community__Qwen2.5-7B-Instruct-4bit"
  },
  {
    id: "mlx-llama-3b",
    label: "MLX Llama 3.2 3B 4-bit",
    repo: "mlx-community/Llama-3.2-3B-Instruct-4bit",
    dirName: "mlx-community__Llama-3.2-3B-Instruct-4bit"
  },
  {
    id: "mlx-phi-3.5",
    label: "MLX Phi-3.5 mini 4-bit",
    repo: "mlx-community/Phi-3.5-mini-instruct-4bit",
    dirName: "mlx-community__Phi-3.5-mini-instruct-4bit"
  },
  {
    id: "mlx-mistral-7b",
    label: "MLX Mistral 7B 4-bit",
    repo: "mlx-community/Mistral-7B-Instruct-v0.3-4bit",
    dirName: "mlx-community__Mistral-7B-Instruct-v0.3-4bit"
  }
];

export function mlxRoot(): string {
  return path.join(MODELS_DIR, "mlx");
}

export function mlxWeightsDir(dirName: string): string {
  return path.join(mlxRoot(), dirName);
}

export function mlxDirName(repo: string): string {
  return repo.replace(/\//g, "__");
}

export function isMlxModelDir(dir: string): boolean {
  if (!fs.existsSync(path.join(dir, "config.json"))) return false;
  let names: string[] = [];
  try {
    names = fs.readdirSync(dir);
  } catch {
    return false;
  }
  return names.some(
    (name) =>
      name.endsWith(".safetensors") ||
      name.endsWith(".npz") ||
      name === "model.safetensors.index.json"
  );
}

export function listMlxOptions(): LlmOption[] {
  ensureAppSupport();
  const catalog: LlmOption[] = MLX_MODELS.map((item) => ({
    id: item.id,
    mode: "local",
    provider: "local",
    family: "mlx",
    runtime: "mlx",
    label: item.label,
    model: item.dirName,
    hfRepo: item.repo,
    cached: isMlxModelDir(mlxWeightsDir(item.dirName))
  }));
  const root = mlxRoot();
  if (!fs.existsSync(root)) return catalog;
  const known = new Set(MLX_MODELS.map((item) => item.dirName));
  const extras: LlmOption[] = [];
  for (const name of fs.readdirSync(root)) {
    if (known.has(name) || !isMlxModelDir(path.join(root, name))) continue;
    extras.push({
      id: `mlx-dir-${name}`,
      mode: "local",
      provider: "local",
      family: "mlx",
      runtime: "mlx",
      label: name.replace(/__/g, "/"),
      model: name,
      cached: true
    });
  }
  return [...catalog, ...extras];
}

export function mlxOptionId(dirName: string, repo?: string): string {
  const catalog = MLX_MODELS.find(
    (item) => item.dirName === dirName || (repo !== undefined && item.repo.toLowerCase() === repo.toLowerCase())
  );
  return catalog?.id ?? `mlx-dir-${dirName}`;
}
