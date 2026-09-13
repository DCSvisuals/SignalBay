import fs from "node:fs";
import path from "node:path";
import { hub } from "./bus.js";
import { allProviderStatus, getCloudModel, getKey, type CloudProvider } from "./llmKeys.js";
import { MODELS_DIR, ensureAppSupport } from "./paths.js";
import type { Incident, LlmOption, LlmProvider, LlmStatus, NewsItem } from "./types.js";

type LocalSpec = LlmOption & { hfRepo: string; hfFile: string; hfUri: string; aliases: string[] };

const LOCAL_MODELS: LocalSpec[] = [
  {
    id: "local-qwen",
    mode: "local",
    provider: "local",
    family: "qwen",
    label: "qwen 2.5-3b (8 GB RAM)",
    model: "qwen2.5-3b-instruct-q4_k_m.gguf",
    hfRepo: "Qwen/Qwen2.5-3B-Instruct-GGUF",
    hfFile: "qwen2.5-3b-instruct-q4_k_m.gguf",
    hfUri: "hf:Qwen/Qwen2.5-3B-Instruct-GGUF:Q4_K_M",
    aliases: ["qwen2.5-3b", "qwen2.5-3b-instruct", "hf_qwen_qwen2.5-3b"]
  },
  {
    id: "local-qwen-7b",
    mode: "local",
    provider: "local",
    family: "qwen",
    label: "qwen 2.5-7b (16 GB RAM)",
    model: "qwen2.5-7b-instruct-q4_k_m.gguf",
    hfRepo: "Qwen/Qwen2.5-7B-Instruct-GGUF",
    hfFile: "qwen2.5-7b-instruct-q4_k_m.gguf",
    hfUri: "hf:Qwen/Qwen2.5-7B-Instruct-GGUF:Q4_K_M",
    aliases: ["qwen2.5-7b", "qwen2.5-7b-instruct"]
  },
  {
    id: "local-qwen-14b",
    mode: "local",
    provider: "local",
    family: "qwen",
    label: "qwen 2.5-14b (32 GB RAM)",
    model: "qwen2.5-14b-instruct-q4_k_m.gguf",
    hfRepo: "Qwen/Qwen2.5-14B-Instruct-GGUF",
    hfFile: "qwen2.5-14b-instruct-q4_k_m.gguf",
    hfUri: "hf:Qwen/Qwen2.5-14B-Instruct-GGUF:Q4_K_M",
    aliases: ["qwen2.5-14b", "qwen2.5-14b-instruct"]
  },
  {
    id: "local-phi-3.5",
    mode: "local",
    provider: "local",
    family: "phi",
    label: "Phi-3.5-mini (8 GB RAM)",
    model: "Phi-3.5-mini-instruct-Q4_K_M.gguf",
    hfRepo: "bartowski/Phi-3.5-mini-instruct-GGUF",
    hfFile: "Phi-3.5-mini-instruct-Q4_K_M.gguf",
    hfUri: "hf:bartowski/Phi-3.5-mini-instruct-GGUF:Q4_K_M",
    aliases: ["phi-3.5-mini", "phi3.5"]
  },
  {
    id: "local-mistral-7b",
    mode: "local",
    provider: "local",
    family: "mistral",
    label: "Mistral 7b (16 GB RAM)",
    model: "Mistral-7B-Instruct-v0.3-Q4_K_M.gguf",
    hfRepo: "bartowski/Mistral-7B-Instruct-v0.3-GGUF",
    hfFile: "Mistral-7B-Instruct-v0.3-Q4_K_M.gguf",
    hfUri: "hf:bartowski/Mistral-7B-Instruct-v0.3-GGUF:Q4_K_M",
    aliases: ["mistral-7b-instruct", "mistral-7b"]
  }
];

const CLOUD_OPTIONS: LlmOption[] = [
  {
    id: "cloud-anthropic",
    mode: "cloud",
    provider: "anthropic",
    family: "cloud",
    label: "Claude",
    model: "claude-sonnet-4-5"
  },
  {
    id: "cloud-openai",
    mode: "cloud",
    provider: "openai",
    family: "cloud",
    label: "ChatGPT",
    model: "gpt-4o"
  },
  {
    id: "cloud-google",
    mode: "cloud",
    provider: "google",
    family: "cloud",
    label: "Gemini",
    model: "gemini-2.0-flash"
  },
  {
    id: "cloud-xai",
    mode: "cloud",
    provider: "xai",
    family: "cloud",
    label: "Grok",
    model: "grok-4.6"
  }
];

const LEGACY_CLOUD_IDS: Record<string, string> = {
  "openai-terra": "cloud-openai",
  "openai-sol": "cloud-openai",
  "anthropic-sonnet": "cloud-anthropic",
  "anthropic-opus": "cloud-anthropic",
  "xai-grok-4.6": "cloud-xai",
  "google-3.8-flash": "cloud-google",
  "google-3.7-flash": "cloud-google",
  "google-3.6-flash": "cloud-google"
};

function extraLocalFiles(): LlmOption[] {
  ensureAppSupport();
  if (!fs.existsSync(MODELS_DIR)) return [];
  const known = new Set(
    LOCAL_MODELS.flatMap((item) => [item.hfFile.toLowerCase(), item.model.toLowerCase(), ...item.aliases])
  );
  const extras: LlmOption[] = [];
  for (const name of fs.readdirSync(MODELS_DIR)) {
    if (!name.toLowerCase().endsWith(".gguf")) continue;
    const full = path.join(MODELS_DIR, name);
    try {
      if (fs.statSync(full).size < 50_000_000) continue;
    } catch {
      continue;
    }
    const lower = name.toLowerCase();
    if ([...known].some((alias) => lower.includes(alias))) continue;
    extras.push({
      id: `local-file-${name}`,
      mode: "local",
      provider: "local",
      family: "other-local",
      label: name.replace(/\.gguf$/i, ""),
      model: name
    });
  }
  return extras;
}

export function listLlmOptions(): LlmOption[] {
  const locals: LlmOption[] = LOCAL_MODELS.map(({ aliases, ...rest }) => ({
    ...rest,
    cached: Boolean(findCachedGguf({ ...rest, aliases } as LocalSpec, rest.model))
  }));
  const extras = extraLocalFiles().map((item) => ({ ...item, cached: true }));
  return [...locals, ...extras, ...CLOUD_OPTIONS];
}

function findCachedGguf(spec: LocalSpec | undefined, modelName: string): string | null {
  ensureAppSupport();
  if (!fs.existsSync(MODELS_DIR)) return null;
  const needles = spec
    ? [spec.hfFile, spec.model, ...spec.aliases]
    : [modelName];
  for (const file of fs.readdirSync(MODELS_DIR)) {
    if (!file.toLowerCase().endsWith(".gguf")) continue;
    const full = path.join(MODELS_DIR, file);
    try {
      if (fs.statSync(full).size < 50_000_000) continue;
    } catch {
      continue;
    }
    const lower = file.toLowerCase();
    if (needles.some((n) => lower === n.toLowerCase() || lower.includes(n.toLowerCase()))) {
      return full;
    }
  }
  return null;
}

const SYSTEM_LOCAL = [
  "You are a senior macOS detection engineer embedded in LocalSIEM.",
  "All inference is local. Never suggest cloud lookups.",
  "Be concise, technical, and actionable.",
  "Prefer copyable zsh commands that work on Apple Silicon macOS."
].join(" ");

const SYSTEM_CLOUD = [
  "You are a senior macOS detection engineer assisting LocalSIEM.",
  "Be concise, technical, and actionable.",
  "Prefer copyable zsh commands that work on Apple Silicon macOS."
].join(" ");

type LlamaModule = typeof import("node-llama-cpp");

interface Job {
  run: () => Promise<void>;
}

function providerReady(provider: LlmProvider): boolean {
  if (provider === "local") return true;
  return Boolean(getKey(provider));
}

function providerLabel(provider: LlmProvider): string {
  if (provider === "openai") return "ChatGPT";
  if (provider === "anthropic") return "Anthropic";
  if (provider === "google") return "Gemini";
  if (provider === "xai") return "Grok";
  return "Local";
}

export class LlmEngine {
  status: LlmStatus = {
    state: "idle",
    gpu: null,
    gpuLayers: null,
    model: LOCAL_MODELS[0].model,
    message: "Metal engine not started",
    metal: false,
    mode: "local",
    selectedId: "local-qwen",
    options: listLlmOptions(),
    cloudConfigured: Object.values(allProviderStatus()).some((item) => item.configured),
    providers: allProviderStatus()
  };

  private selected = listLlmOptions()[0];
  private session: {
    prompt: (text: string, opts?: { maxTokens?: number }) => Promise<string>;
  } | null = null;
  private queue: Job[] = [];
  private draining = false;
  private localReady = false;
  private loadedLocalId: string | null = null;

  async start(): Promise<void> {
    await this.select("local-qwen");
  }

  async refreshAfterKeys(): Promise<LlmStatus> {
    return this.select(this.selected.id);
  }

  async select(id: string): Promise<LlmStatus> {
    const resolvedId = LEGACY_CLOUD_IDS[id] ?? id;
    const option = listLlmOptions().find((item) => item.id === resolvedId) ?? listLlmOptions()[0];
    this.selected = option;
    this.status = {
      ...this.status,
      selectedId: option.id,
      mode: option.mode,
      model: option.model,
      options: listLlmOptions(),
      cloudConfigured: Object.values(allProviderStatus()).some((item) => item.configured),
      providers: allProviderStatus()
    };

    if (option.mode === "cloud") {
      if (!providerReady(option.provider)) {
        this.setStatus({
          state: "error",
          gpu: "cloud",
          gpuLayers: null,
          metal: false,
          message: `Add a ${providerLabel(option.provider)} API key (APIs button) to use ${option.label}`
        });
        return this.status;
      }
      this.setStatus({
        state: "ready",
        gpu: "cloud",
        gpuLayers: null,
        metal: false,
        message: `Ready on ${providerLabel(option.provider)} · ${option.label}`
      });
      if (!this.localReady && !this.session) {
        void this.startLocal().catch((err) => {
          console.warn("[llm] background local start failed", err);
        });
      }
      return this.status;
    }

    if (this.localReady && this.session && this.loadedLocalId === option.id) {
      this.setStatus({
        state: "ready",
        metal: true,
        gpuLayers: "max",
        message: `Ready on metal · ${option.model} fully offloaded`
      });
      return this.status;
    }
    this.localReady = false;
    this.session = null;
    this.loadedLocalId = null;
    await this.startLocal();
    return this.status;
  }

  async summarizeNews(item: NewsItem): Promise<string | null> {
    const prompt = [
      "Summarize this CISA threat intelligence item for a macOS SOC analyst.",
      "Return GitHub-flavored Markdown with EXACTLY these three bullets and nothing else:",
      "- **Asset Impacted**: ...",
      "- **Attack Vector**: ...",
      "- **Remediation**: ...",
      "",
      `Title: ${item.title}`,
      `Source: ${item.source}`,
      `CVEs: ${item.cveIds.join(", ") || "none listed"}`,
      `Vendor/Product: ${item.vendor ?? "n/a"} / ${item.product ?? "n/a"}`,
      `URL: ${item.url ?? "n/a"}`,
      `Body: ${(item.content || item.summary || "").slice(0, 2500)}`
    ].join("\n");
    return this.prompt(prompt, 280);
  }

  async triageIncident(incident: Incident, eventSnippets: string[]): Promise<string | null> {
    const prompt = [
      "Triage this SIEM incident. Return Markdown with these sections:",
      "## Assessment",
      "## Risk Severity",
      "## Indicators",
      "## macOS Containment Commands",
      "The containment section must be a fenced bash code block of copyable commands",
      "(pfctl, lsof, log show, launchctl, pkill, spctl) tailored to the evidence.",
      "Include a 0-100 risk number in Risk Severity.",
      "",
      `Title: ${incident.title}`,
      `Rule: ${incident.ruleName}`,
      `Severity: ${incident.severity}`,
      `Risk score seed: ${incident.riskScore}`,
      `Evidence:\n${incident.evidence}`,
      `Related logs:\n${eventSnippets.join("\n").slice(0, 2500)}`
    ].join("\n");
    return this.prompt(prompt, 420);
  }

  private localStatus(patch: Partial<LlmStatus>): void {
    if (this.selected.mode !== "local") return;
    this.setStatus(patch);
  }

  private async startLocal(): Promise<void> {
    this.localStatus({
      state: "compiling",
      metal: true,
      message: "Initializing node-llama-cpp with Apple Metal GPU offload"
    });
    try {
      const llamaCpp: LlamaModule = await import("node-llama-cpp");
      ensureAppSupport();
      const modelPath = await this.resolveModel(llamaCpp);
      this.localStatus({
        state: "loading",
        message: `Loading ${this.selected.model} with full Metal offload`
      });

      const llamaOptions = {
        gpu: "metal" as const,
        build: "auto" as const,
        cmakeOptions: {
          GGML_METAL: "ON",
          GGML_METAL_EMBED_LIBRARY: "ON"
        },
        existingPrebuiltBinaryMustMatchBuildOptions: false,
        progressLogs: true
      };
      let llama;
      try {
        llama = await llamaCpp.getLlama("lastBuild");
        if (String(llama.gpu).toLowerCase() !== "metal") {
          await llama.dispose?.();
          llama = await llamaCpp.getLlama(llamaOptions);
        }
      } catch {
        llama = await llamaCpp.getLlama(llamaOptions);
      }

      const gpu = String(llama.gpu ?? "metal");
      const model = await llama.loadModel({
        modelPath,
        gpuLayers: "max"
      });
      const context = await model.createContext();
      const session = new llamaCpp.LlamaChatSession({
        contextSequence: context.getSequence(),
        systemPrompt: SYSTEM_LOCAL
      });

      this.session = session;
      this.localReady = true;
      this.loadedLocalId = this.selected.id;
      if (this.selected.mode === "local") {
        this.setStatus({
          state: "ready",
          gpu,
          gpuLayers: "max",
          metal: gpu.toLowerCase().includes("metal") || gpu === "metal",
          message: `Ready on ${gpu} · ${this.selected.model} fully offloaded`
        });
      }
      console.log(`[llm] local ready gpu=${gpu} model=${modelPath}`);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      console.error("[llm] failed to start local engine", err);
      if (this.selected.mode === "local") {
        this.setStatus({
          state: "error",
          message: `LLM unavailable: ${message}`
        });
      }
    }
  }

  private prompt(text: string, maxTokens: number): Promise<string | null> {
    return new Promise((resolve) => {
      this.queue.push({
        run: async () => {
          try {
            if (this.selected.mode === "cloud") {
              if (!providerReady(this.selected.provider)) {
                resolve(null);
                return;
              }
              const result = await cloudComplete(
                this.selected.provider as CloudProvider,
                getCloudModel(this.selected.provider as CloudProvider, this.selected.model),
                text,
                maxTokens
              );
              resolve(result.trim());
              return;
            }
            if (!this.session || !this.localReady) {
              resolve(null);
              return;
            }
            const result = await this.session.prompt(text, { maxTokens });
            resolve(result.trim());
          } catch (err) {
            console.error("[llm] prompt failed", err);
            resolve(null);
          }
        }
      });
      void this.drain();
    });
  }

  private async drain(): Promise<void> {
    if (this.draining) return;
    this.draining = true;
    while (this.queue.length) {
      const job = this.queue.shift();
      if (job) await job.run();
    }
    this.draining = false;
  }

  async prefetch(id: string): Promise<LlmStatus> {
    const spec = LOCAL_MODELS.find((item) => item.id === id);
    if (!spec) return this.status;
    if (findCachedGguf(spec, spec.model)) {
      this.setStatus({ downloadingId: null, downloadPercent: null });
      return this.status;
    }
    this.setStatus({
      downloadingId: id,
      downloadPercent: 0,
      message: `Downloading ${spec.label}`
    });
    try {
      await this.fetchGguf(spec, (pct) => {
        this.setStatus({
          downloadingId: id,
          downloadPercent: pct,
          message: `Downloading ${spec.label} · ${pct}%`
        });
      });
      this.setStatus({
        downloadingId: null,
        downloadPercent: 100,
        message:
          this.selected.mode === "local" && this.localReady
            ? `Ready on metal · ${this.selected.model}`
            : `Downloaded ${spec.label}`
      });
    } catch (err) {
      this.setStatus({
        downloadingId: null,
        downloadPercent: null,
        message: err instanceof Error ? err.message : `Download failed for ${spec.label}`
      });
    }
    return this.status;
  }

  private async fetchGguf(spec: LocalSpec, onPct: (pct: number) => void): Promise<string> {
    const llamaCpp: LlamaModule = await import("node-llama-cpp");
    if (typeof llamaCpp.resolveModelFile === "function") {
      try {
        const resolved = await llamaCpp.resolveModelFile(spec.hfUri, MODELS_DIR);
        if (resolved && fs.existsSync(resolved)) return resolved;
      } catch (err) {
        console.warn("[llm] resolveModelFile failed, falling back to HTTP", err);
      }
    }
    const dest = path.join(MODELS_DIR, spec.hfFile);
    const url = `https://huggingface.co/${spec.hfRepo}/resolve/main/${spec.hfFile}`;
    await downloadFile(url, dest, onPct);
    return dest;
  }

  private async resolveModel(llamaCpp: LlamaModule): Promise<string> {
    const spec = LOCAL_MODELS.find((item) => item.id === this.selected.id);
    const existing = findCachedGguf(spec, this.selected.model);
    if (existing) return existing;

    if (!spec?.hfRepo) {
      const bundled = path.join(MODELS_DIR, this.selected.model);
      if (fs.existsSync(bundled)) return bundled;
      throw new Error(`No GGUF on disk for ${this.selected.label}. Put a .gguf in ${MODELS_DIR}`);
    }

    this.localStatus({
      state: "downloading",
      message: `Downloading ${spec.label} from Hugging Face (${spec.hfFile})`
    });
    return this.fetchGguf(spec, (pct) => {
      this.localStatus({
        state: "downloading",
        message: `Downloading ${spec.label} · ${pct}%`
      });
    });
  }

  private setStatus(patch: Partial<LlmStatus>): void {
    this.status = {
      ...this.status,
      ...patch,
      selectedId: this.selected.id,
      mode: this.selected.mode,
      model: this.selected.model,
      options: listLlmOptions(),
      cloudConfigured: Object.values(allProviderStatus()).some((item) => item.configured),
      providers: allProviderStatus()
    };
    hub.broadcast({ type: "llm_status", payload: this.status });
  }
}

async function cloudComplete(
  provider: CloudProvider,
  model: string,
  prompt: string,
  maxTokens: number
): Promise<string> {
  const key = getKey(provider);
  if (!key) throw new Error(`${provider} API key is not set`);

  if (provider === "anthropic") {
    const res = await fetch("https://api.anthropic.com/v1/messages", {
      method: "POST",
      headers: {
        "x-api-key": key,
        "anthropic-version": "2023-06-01",
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        model,
        max_tokens: maxTokens,
        system: SYSTEM_CLOUD,
        messages: [{ role: "user", content: prompt }]
      })
    });
    if (!res.ok) throw new Error(`Anthropic ${res.status}: ${(await res.text()).slice(0, 240)}`);
    const data = (await res.json()) as { content?: Array<{ text?: string }> };
    return data.content?.map((part) => part.text ?? "").join("") ?? "";
  }

  if (provider === "google") {
    const url = `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${encodeURIComponent(key)}`;
    const res = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        systemInstruction: { parts: [{ text: SYSTEM_CLOUD }] },
        contents: [{ role: "user", parts: [{ text: prompt }] }],
        generationConfig: { maxOutputTokens: maxTokens, temperature: 0.2 }
      })
    });
    if (!res.ok) throw new Error(`Gemini ${res.status}: ${(await res.text()).slice(0, 240)}`);
    const data = (await res.json()) as {
      candidates?: Array<{ content?: { parts?: Array<{ text?: string }> } }>;
    };
    return data.candidates?.[0]?.content?.parts?.map((part) => part.text ?? "").join("") ?? "";
  }

  const endpoint =
    provider === "openai"
      ? "https://api.openai.com/v1/chat/completions"
      : "https://api.x.ai/v1/chat/completions";
  const res = await fetch(endpoint, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${key}`,
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      model,
      temperature: 0.2,
      max_tokens: maxTokens,
      messages: [
        { role: "system", content: SYSTEM_CLOUD },
        { role: "user", content: prompt }
      ]
    })
  });
  if (!res.ok) {
    const name = provider === "openai" ? "OpenAI" : "SpaceXAI";
    throw new Error(`${name} ${res.status}: ${(await res.text()).slice(0, 240)}`);
  }
  const data = (await res.json()) as {
    choices?: Array<{ message?: { content?: string } }>;
  };
  return data.choices?.[0]?.message?.content ?? "";
}

async function downloadFile(
  url: string,
  dest: string,
  onProgress: (pct: number) => void
): Promise<void> {
  const tmp = `${dest}.partial`;
  const res = await fetch(url, {
    headers: { "User-Agent": "LocalSIEM/1.0" },
    redirect: "follow"
  });
  if (!res.ok || !res.body) {
    throw new Error(`Model download failed: HTTP ${res.status}`);
  }
  const total = Number(res.headers.get("content-length") || 0);
  const reader = res.body.getReader();
  const file = fs.createWriteStream(tmp);
  let received = 0;
  let lastPct = -1;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    file.write(Buffer.from(value));
    received += value.byteLength;
    if (total > 0) {
      const pct = Math.floor((received / total) * 100);
      if (pct !== lastPct && pct % 5 === 0) {
        lastPct = pct;
        onProgress(pct);
      }
    }
  }
  await new Promise<void>((resolve, reject) => {
    file.end(() => resolve());
    file.on("error", reject);
  });
  fs.renameSync(tmp, dest);
}
