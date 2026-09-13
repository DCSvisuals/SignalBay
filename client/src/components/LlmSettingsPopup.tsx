import { X } from "lucide-react";
import { useEffect, useState } from "react";
import { createPortal } from "react-dom";
import { api } from "../lib/api";
import type { LlmStatus } from "../types";

interface Props {
  llm: LlmStatus | null;
  onClose: () => void;
  onSaved: () => void;
}

export function LlmSettingsPopup({ llm, onClose, onSaved }: Props) {
  const [values, setValues] = useState({
    openai: "",
    openaiModel: "",
    anthropic: "",
    anthropicModel: "",
    google: "",
    googleModel: "",
    xai: "",
    xaiModel: ""
  });
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  const save = async () => {
    setBusy(true);
    setError(null);
    try {
      const patch: Record<string, string> = {};
      for (const [key, value] of Object.entries(values)) {
        if (value.trim()) patch[key] = value.trim();
      }
      await api.saveLlmKeys(patch);
      onSaved();
      onClose();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not save keys");
    } finally {
      setBusy(false);
    }
  };

  return createPortal(
    <div className="popup-overlay keys-overlay" onClick={onClose} role="presentation">
      <div
        className="popup-card keys-card"
        role="dialog"
        aria-modal="true"
        aria-labelledby="llm-keys-title"
        onClick={(event) => event.stopPropagation()}
      >
        <header className="popup-head">
          <div>
            <p className="popup-kicker">Cloud providers</p>
            <h3 id="llm-keys-title">Add API keys</h3>
          </div>
          <button className="ghost" onClick={onClose} aria-label="Close">
            <X size={14} />
          </button>
        </header>
        <p className="muted">
          Paste a provider key. You do not pick a model in the dropdown — optional model names
          below override the default (ChatGPT gpt-4o, Claude Sonnet, Gemini 2.0 Flash, Grok 4.6).
          Keys stay on this Mac. Local GGUFs do not need a key.
        </p>
        <div className="key-fields">
          <label className="key-field">
            <span>
              ChatGPT / OpenAI
              {llm?.providers?.openai?.configured ? (
                <em> saved {llm.providers.openai.hint}</em>
              ) : (
                <em> not configured</em>
              )}
            </span>
            <input
              type="password"
              autoComplete="off"
              placeholder={llm?.providers?.openai?.configured ? "••••••••  (paste to replace)" : "OpenAI API key"}
              value={values.openai}
              onChange={(event) => setValues((prev) => ({ ...prev, openai: event.target.value }))}
            />
            <input
              type="text"
              autoComplete="off"
              placeholder="Optional model (gpt-4o, gpt-4.1, o3-mini, …)"
              value={values.openaiModel}
              onChange={(event) => setValues((prev) => ({ ...prev, openaiModel: event.target.value }))}
            />
            <small>One key covers every OpenAI model. Leave the model blank to use the default.</small>
          </label>
          <label className="key-field">
            <span>
              Claude / Anthropic
              {llm?.providers?.anthropic?.configured ? (
                <em> saved {llm.providers.anthropic.hint}</em>
              ) : (
                <em> not configured</em>
              )}
            </span>
            <input
              type="password"
              autoComplete="off"
              placeholder={
                llm?.providers?.anthropic?.configured ? "••••••••  (paste to replace)" : "Anthropic API key"
              }
              value={values.anthropic}
              onChange={(event) => setValues((prev) => ({ ...prev, anthropic: event.target.value }))}
            />
            <input
              type="text"
              autoComplete="off"
              placeholder="Optional model (claude-sonnet-4-5, claude-opus-4-5, …)"
              value={values.anthropicModel}
              onChange={(event) =>
                setValues((prev) => ({ ...prev, anthropicModel: event.target.value }))
              }
            />
          </label>
          <label className="key-field">
            <span>
              Gemini / Google
              {llm?.providers?.google?.configured ? (
                <em> saved {llm.providers.google.hint}</em>
              ) : (
                <em> not configured</em>
              )}
            </span>
            <input
              type="password"
              autoComplete="off"
              placeholder={llm?.providers?.google?.configured ? "••••••••  (paste to replace)" : "Gemini API key"}
              value={values.google}
              onChange={(event) => setValues((prev) => ({ ...prev, google: event.target.value }))}
            />
            <input
              type="text"
              autoComplete="off"
              placeholder="Optional model (gemini-2.0-flash, gemini-2.5-pro, …)"
              value={values.googleModel}
              onChange={(event) => setValues((prev) => ({ ...prev, googleModel: event.target.value }))}
            />
          </label>
          <label className="key-field">
            <span>
              Grok / xAI
              {llm?.providers?.xai?.configured ? (
                <em> saved {llm.providers.xai.hint}</em>
              ) : (
                <em> not configured</em>
              )}
            </span>
            <input
              type="password"
              autoComplete="off"
              placeholder={llm?.providers?.xai?.configured ? "••••••••  (paste to replace)" : "xAI API key"}
              value={values.xai}
              onChange={(event) => setValues((prev) => ({ ...prev, xai: event.target.value }))}
            />
            <input
              type="text"
              autoComplete="off"
              placeholder="Optional model (grok-4.6, …)"
              value={values.xaiModel}
              onChange={(event) => setValues((prev) => ({ ...prev, xaiModel: event.target.value }))}
            />
          </label>
        </div>
        {error && <p className="engine-note">{error}</p>}
        <div className="triage-actions" style={{ marginTop: 12 }}>
          <button className="ghost" onClick={onClose}>
            Cancel
          </button>
          <button className="primary" disabled={busy} onClick={() => void save()}>
            {busy ? "Saving…" : "Save keys"}
          </button>
        </div>
      </div>
    </div>,
    document.body
  );
}
