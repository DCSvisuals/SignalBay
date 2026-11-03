import { Activity, CheckCircle2, ChevronDown, Cpu, Database, Download, KeyRound, Loader2, Radio, RefreshCw, Zap } from "lucide-react";
import { useEffect, useMemo, useRef, useState, type MouseEvent as ReactMouseEvent } from "react";
import { api } from "../lib/api";
import type { LlmOption, LlmStatus, PlatformStats } from "../types";
import { LlmSettingsPopup } from "./LlmSettingsPopup";

const FALLBACK_OPTIONS: LlmOption[] = [
  { id: "local-qwen", mode: "local", provider: "local", family: "qwen", label: "qwen 2.5-3b (8 GB RAM)", model: "qwen2.5-3b-instruct-q4_k_m.gguf" },
  { id: "local-qwen-7b", mode: "local", provider: "local", family: "qwen", label: "qwen 2.5-7b (16 GB RAM)", model: "qwen2.5-7b-instruct-q4_k_m.gguf" },
  { id: "local-qwen-14b", mode: "local", provider: "local", family: "qwen", label: "qwen 2.5-14b (32 GB RAM)", model: "qwen2.5-14b-instruct-q4_k_m.gguf" },
  { id: "local-phi-3.5", mode: "local", provider: "local", family: "phi", label: "Phi-3.5-mini (8 GB RAM)", model: "Phi-3.5-mini-instruct-Q4_K_M.gguf" },
  { id: "local-mistral-7b", mode: "local", provider: "local", family: "mistral", label: "Mistral 7b (16 GB RAM)", model: "Mistral-7B-Instruct-v0.3-Q4_K_M.gguf" },
  { id: "mlx-qwen-3b", mode: "local", provider: "local", family: "mlx", runtime: "mlx", label: "MLX Qwen 2.5 3B 4-bit", model: "mlx-community__Qwen2.5-3B-Instruct-4bit" },
  { id: "mlx-qwen-7b", mode: "local", provider: "local", family: "mlx", runtime: "mlx", label: "MLX Qwen 2.5 7B 4-bit", model: "mlx-community__Qwen2.5-7B-Instruct-4bit" },
  { id: "mlx-llama-3b", mode: "local", provider: "local", family: "mlx", runtime: "mlx", label: "MLX Llama 3.2 3B 4-bit", model: "mlx-community__Llama-3.2-3B-Instruct-4bit" },
  { id: "mlx-phi-3.5", mode: "local", provider: "local", family: "mlx", runtime: "mlx", label: "MLX Phi-3.5 mini 4-bit", model: "mlx-community__Phi-3.5-mini-instruct-4bit" },
  { id: "mlx-mistral-7b", mode: "local", provider: "local", family: "mlx", runtime: "mlx", label: "MLX Mistral 7B 4-bit", model: "mlx-community__Mistral-7B-Instruct-v0.3-4bit" },
  { id: "cloud-anthropic", mode: "cloud", provider: "anthropic", family: "cloud", label: "Claude", model: "claude-sonnet-4-5" },
  { id: "cloud-openai", mode: "cloud", provider: "openai", family: "cloud", label: "ChatGPT", model: "gpt-4o" },
  { id: "cloud-google", mode: "cloud", provider: "google", family: "cloud", label: "Gemini", model: "gemini-2.0-flash" },
  { id: "cloud-xai", mode: "cloud", provider: "xai", family: "cloud", label: "Grok", model: "grok-4.6" }
];

const GROUPS: Array<{ family: string; label: string }> = [
  { family: "qwen", label: "Local LLMs: Qwen Instruct" },
  { family: "phi", label: "Local LLMs: Phi" },
  { family: "mistral", label: "Local LLMs: Mistral Instruct" },
  { family: "other-local", label: "Local LLMs: Other GGUF" },
  { family: "mlx", label: "Local LLMs: MLX" },
  { family: "cloud", label: "Cloud LLMs" }
];

interface Props {
  connected: boolean;
  stats: PlatformStats | null;
  llm: LlmStatus | null;
  onRefresh: () => void;
}

export function TopBar({ connected, stats, llm, onRefresh }: Props) {
  const [clock, setClock] = useState(() => new Date());
  const [busy, setBusy] = useState(false);
  const [showKeys, setShowKeys] = useState(false);
  const [openMenu, setOpenMenu] = useState(false);
  const [addSource, setAddSource] = useState("");
  const [addError, setAddError] = useState("");
  const menuRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const id = window.setInterval(() => setClock(new Date()), 1000);
    return () => window.clearInterval(id);
  }, []);

  const options = llm?.options?.length ? llm.options : FALLBACK_OPTIONS;
  const selectedId = llm?.selectedId ?? "local-qwen";
  const grouped = useMemo(
    () =>
      GROUPS.map((group) => ({
        ...group,
        items: options.filter((item) => (item.family ?? (item.mode === "cloud" ? "cloud" : "other-local")) === group.family)
      })).filter((group) => group.items.length > 0),
    [options]
  );

  const setEngine = async (id: string) => {
    setBusy(true);
    try {
      window.localStorage.setItem("localsiem.llm", id);
      await api.setLlm(id);
      onRefresh();
    } finally {
      setBusy(false);
    }
  };

  useEffect(() => {
    const saved = window.localStorage.getItem("localsiem.llm");
    if (saved && saved !== "local-qwen" && saved !== llm?.selectedId) {
      void api.setLlm(saved).then(() => onRefresh()).catch(() => undefined);
    }
  }, []);

  const sync = async () => {
    setBusy(true);
    try {
      await api.sync();
      onRefresh();
    } finally {
      setBusy(false);
    }
  };

  const needsKey = (item: LlmOption) => {
    if (item.provider === "local") return false;
    return llm?.providers?.[item.provider]?.configured === false;
  };

  useEffect(() => {
    const onDoc = (event: globalThis.MouseEvent) => {
      if (!menuRef.current?.contains(event.target as Node)) setOpenMenu(false);
    };
    document.addEventListener("mousedown", onDoc);
    return () => document.removeEventListener("mousedown", onDoc);
  }, []);

  const selected = options.find((item) => item.id === selectedId) ?? options[0];
  const downloadingId = llm?.downloadingId ?? null;

  const addModel = async () => {
    const source = addSource.trim();
    if (!source) return;
    setBusy(true);
    setAddError("");
    try {
      await api.importLlm(source);
      setAddSource("");
      onRefresh();
    } catch (err) {
      const raw = err instanceof Error ? err.message : "Could not add that model";
      try {
        const parsed = JSON.parse(raw) as { error?: string };
        setAddError(parsed.error || raw);
      } catch {
        setAddError(raw);
      }
    } finally {
      setBusy(false);
    }
  };

  const downloadModel = async (event: ReactMouseEvent, id: string) => {
    event.stopPropagation();
    setBusy(true);
    try {
      await api.downloadLlm(id);
      onRefresh();
    } finally {
      setBusy(false);
    }
  };

  return (
    <header className="topbar">
      <div className="brand">
        <div className="mark" aria-hidden>
          <span />
          <span />
        </div>
        <div>
          <div className="wordmark">Signalbay</div>
          <div className="tagline">macOS Web-SIEM · Apple Silicon · offline</div>
        </div>
      </div>
      <div className="status-pills">
        <span className={`pill ${connected ? "live" : "down"}`}>
          <Radio size={12} />
          {connected ? "WS live" : "WS reconnecting"}
        </span>
        <span className="pill" title="Syslog collectors">
          <Activity size={12} />
          UDP :{stats?.udpPort ?? "—"} · TCP :{stats?.tcpPort ?? "—"} · TLS :{stats?.tlsPort ?? "—"} · RELP :{stats?.relpPort ?? "—"}
        </span>
        <span className="pill">
          <Database size={12} />
          {stats?.events ?? 0} events · {stats?.incidents ?? 0} incidents
        </span>
        <span className={`pill ${llm?.mode === "cloud" ? "cloud" : llm?.metal || llm?.state === "ready" ? "metal" : ""}`}>
          <Cpu size={12} />
          {llm?.mode === "cloud" ? "Cloud" : llm?.gpu === "mlx" ? "MLX" : llm?.metal ? "Metal GPU" : llm?.gpu ?? "GPU"}
          {llm?.state ? ` · ${llm.state}` : ""}
        </span>
        <span className="pill">
          <Zap size={12} />
          {stats?.eps ?? 0} eps
        </span>
      </div>
      <div className="top-actions">
        <div className="llm-picker" ref={menuRef}>
          <span>LLM</span>
          <button
            type="button"
            className="llm-trigger"
            disabled={busy}
            onClick={() => {
              setOpenMenu((open) => {
                if (!open) onRefresh();
                return !open;
              });
            }}
          >
            <span>{selected?.label ?? "Select"}</span>
            <ChevronDown size={12} />
          </button>
          {openMenu && (
            <div className="llm-menu" role="listbox">
              {grouped.map((group) => (
                <div key={group.family} className="llm-group">
                  <div className="llm-group-label">{group.label}</div>
                  {group.items.map((item) => {
                    const local = item.provider === "local";
                    const cached = Boolean(item.cached);
                    const pulling = downloadingId === item.id;
                    return (
                      <div
                        key={item.id}
                        className={item.id === selectedId ? "llm-row on" : "llm-row"}
                        role="option"
                        aria-selected={item.id === selectedId}
                        onClick={() => {
                          setOpenMenu(false);
                          void setEngine(item.id);
                        }}
                      >
                        <span>
                          {item.label}
                          {needsKey(item) ? " · add API" : ""}
                        </span>
                        {local && (
                          <button
                            type="button"
                            className="llm-dl"
                            title={cached ? "Already downloaded" : item.runtime === "mlx" ? "Download this MLX model" : "Download this GGUF"}
                            disabled={cached || pulling || busy}
                            onClick={(event) => {
                              if (cached) {
                                event.stopPropagation();
                                return;
                              }
                              void downloadModel(event, item.id);
                            }}
                          >
                            {pulling ? (
                              <Loader2 size={14} className="spin" />
                            ) : cached ? (
                              <CheckCircle2 size={14} />
                            ) : (
                              <Download size={14} />
                            )}
                          </button>
                        )}
                      </div>
                    );
                  })}
                </div>
              ))}
              <form
                className="llm-add"
                onSubmit={(event) => {
                  event.preventDefault();
                  void addModel();
                }}
              >
                <label htmlFor="llm-add-source">Add a local model</label>
                <div>
                  <input
                    id="llm-add-source"
                    value={addSource}
                    placeholder="GGUF path, MLX folder, or Hugging Face model"
                    onChange={(event) => setAddSource(event.target.value)}
                  />
                  <button type="submit" disabled={busy || !addSource.trim()}>
                    Add
                  </button>
                </div>
                <p className={addError ? "err" : ""}>
                  {addError || "GGUF file (50 MB or larger), an MLX folder, or a Hugging Face model such as mlx-community/Qwen2.5-3B-Instruct-4bit."}
                </p>
              </form>
            </div>
          )}
        </div>
        <button className="ghost" onClick={() => setShowKeys(true)}>
          <KeyRound size={13} />
          APIs
        </button>
        <button className="ghost" onClick={() => void sync()} disabled={busy}>
          <RefreshCw size={13} />
          Sync CISA
        </button>
        <time className="clock">
          {clock.toLocaleTimeString([], { hour12: false })}
        </time>
      </div>
      {showKeys && (
        <LlmSettingsPopup
          llm={llm}
          onClose={() => setShowKeys(false)}
          onSaved={onRefresh}
        />
      )}
    </header>
  );
}
