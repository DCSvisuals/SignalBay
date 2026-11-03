import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { MIN_GGUF_BYTES, parseGgufSource, parseModelSource, placeLocalGguf, placeMlxDir } from "./llmImport.js";
import { isMlxModelDir, listMlxOptions } from "./mlxCatalog.js";

test("a huggingface blob link becomes a resolve download", () => {
  const parsed = parseGgufSource(
    "https://huggingface.co/Qwen/Qwen2.5-3B-Instruct-GGUF/blob/main/qwen2.5-3b-instruct-q4_k_m.gguf?download=true"
  );
  assert.equal(parsed.fileName, "qwen2.5-3b-instruct-q4_k_m.gguf");
  assert.equal(
    parsed.url,
    "https://huggingface.co/Qwen/Qwen2.5-3B-Instruct-GGUF/resolve/main/qwen2.5-3b-instruct-q4_k_m.gguf"
  );
});

test("a local model source must be a full gguf path or a huggingface link", () => {
  const home = parseGgufSource("~/models/custom model.gguf");
  assert.equal(home.localPath, path.join(os.homedir(), "models", "custom model.gguf"));
  assert.throws(() => parseGgufSource("models/custom.gguf"), /full path/);
  assert.throws(() => parseGgufSource("https://example.com/model.gguf"), /huggingface\.co/);
  assert.throws(() => parseGgufSource("/tmp/notes.txt"), /gguf/);
});

test("an MLX repo, model page, or folder is accepted beside GGUF", () => {
  const repo = parseModelSource("mlx-community/Qwen2.5-3B-Instruct-4bit");
  assert.equal(repo.kind, "mlx-repo");
  if (repo.kind === "mlx-repo") assert.equal(repo.dirName, "mlx-community__Qwen2.5-3B-Instruct-4bit");
  const page = parseModelSource("https://huggingface.co/mlx-community/Llama-3.2-3B-Instruct-4bit/tree/main");
  assert.equal(page.kind, "mlx-repo");
  const gguf = parseModelSource(
    "https://huggingface.co/Qwen/Qwen2.5-3B-Instruct-GGUF/resolve/main/qwen2.5-3b-instruct-q4_k_m.gguf"
  );
  assert.equal(gguf.kind, "gguf");
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "localsiem-mlx-"));
  const source = path.join(root, "outside", "my-mlx");
  fs.mkdirSync(source, { recursive: true });
  fs.writeFileSync(path.join(source, "config.json"), "{}");
  fs.writeFileSync(path.join(source, "model.safetensors"), "weights");
  assert.equal(isMlxModelDir(source), true);
  const linked = placeMlxDir(source, path.join(root, "models"));
  assert.equal(fs.realpathSync(linked), fs.realpathSync(source));
  assert.throws(() => parseModelSource(path.join(root, "outside")), /not an MLX model/);
  const options = listMlxOptions();
  assert.ok(options.some((item) => item.id === "mlx-qwen-3b" && item.runtime === "mlx"));
  fs.rmSync(root, { recursive: true, force: true });
});

test("placing a gguf hardlinks it into the models folder", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "localsiem-gguf-"));
  const models = path.join(root, "models");
  const source = path.join(root, "outside", "lab-model.gguf");
  fs.mkdirSync(path.dirname(source), { recursive: true });
  const fd = fs.openSync(source, "w");
  fs.ftruncateSync(fd, MIN_GGUF_BYTES);
  fs.closeSync(fd);
  const stored = placeLocalGguf(source, models);
  const again = placeLocalGguf(stored, models);
  assert.equal(again, stored);
  assert.equal(fs.statSync(stored).ino, fs.statSync(source).ino);
  const tiny = path.join(root, "tiny.gguf");
  fs.writeFileSync(tiny, "not a model");
  assert.throws(() => placeLocalGguf(tiny, models), /50 MB/);
  assert.throws(() => placeLocalGguf(path.join(root, "missing.gguf"), models), /No file/);
  fs.rmSync(root, { recursive: true, force: true });
});
