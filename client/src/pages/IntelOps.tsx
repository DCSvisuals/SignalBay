import { useEffect, useState } from "react";
import { api } from "../lib/api";
import type { IocRecord } from "../types";

interface Detection {
  id: string;
  name: string;
  summary: string;
  enabled: boolean;
}

interface ExceptionRow {
  id: string;
  kind: string;
  value: string;
  note: string;
  enabled: boolean;
}

export function IntelOps() {
  const [rules, setRules] = useState("[]");
  const [iocs, setIocs] = useState<IocRecord[]>([]);
  const [detections, setDetections] = useState<Detection[]>([]);
  const [exceptions, setExceptions] = useState<ExceptionRow[]>([]);
  const [value, setValue] = useState("");
  const [kind, setKind] = useState("ip");
  const [note, setNote] = useState("");
  const [days, setDays] = useState("30");
  const [exKind, setExKind] = useState("process");
  const [exValue, setExValue] = useState("");
  const [msg, setMsg] = useState<string | null>(null);

  const load = () => {
    void api.customRules().then((rows) => setRules(JSON.stringify(rows, null, 2)));
    void api.iocs().then(setIocs);
    void api.detections().then(setDetections);
    void api.exceptions().then(setExceptions);
  };

  useEffect(() => {
    load();
  }, []);

  return (
    <div className="reports-grid intel-grid">
      <article className="panel">
        <header className="panel-head">
          <div>
            <h2>Built-in detections</h2>
            <p>Turn a behavior rule off when it does not belong on this Mac. Disabled rules stay in the list.</p>
          </div>
        </header>
        <div className="ops-list">
          {detections.map((rule) => (
            <label className="ops-row" key={rule.id}>
              <span>
                <strong>{rule.name}</strong>
                <small>{rule.summary}</small>
              </span>
              <input
                type="checkbox"
                checked={rule.enabled}
                onChange={(event) => {
                  const enabled = event.target.checked;
                  setDetections((prev) => prev.map((row) => (row.id === rule.id ? { ...row, enabled } : row)));
                  void api.setDetection(rule.id, enabled).catch((err) =>
                    setMsg(err instanceof Error ? err.message : "Could not save detection")
                  );
                }}
              />
            </label>
          ))}
        </div>
        <header className="panel-head">
          <div>
            <h2>Exceptions</h2>
            <p>A process exception suppresses every detection for that process. A rule exception matches the rule id.</p>
          </div>
        </header>
        <form
          className="hunt-form"
          onSubmit={(event) => {
            event.preventDefault();
            if (!exValue.trim()) return;
            const next = [
              ...exceptions,
              { id: `ex-${Date.now()}`, kind: exKind, value: exValue.trim(), note: "", enabled: true }
            ];
            void api.saveExceptions(next).then((saved) => {
              setExceptions(saved);
              setExValue("");
            });
          }}
        >
          <select value={exKind} onChange={(e) => setExKind(e.target.value)}>
            <option value="host">host</option>
            <option value="process">process</option>
            <option value="src_ip">src ip</option>
            <option value="rule">rule id</option>
          </select>
          <input value={exValue} onChange={(e) => setExValue(e.target.value)} placeholder="sshd or 203.0.113.10" />
          <button className="primary" type="submit">Add exception</button>
        </form>
        <div className="ops-list">
          {exceptions.map((row) => (
            <div className="ops-row" key={row.id}>
              <span>
                <strong>{row.kind}</strong> {row.value}
              </span>
              <button
                className="ghost"
                onClick={() =>
                  void api.saveExceptions(exceptions.filter((item) => item.id !== row.id)).then(setExceptions)
                }
              >
                Remove
              </button>
            </div>
          ))}
        </div>
      </article>
      <article className="panel">
        <header className="panel-head">
          <div>
            <h2>Threat intel IOCs</h2>
            <p>IPs and hashes match exactly. Domains match on a boundary. Short strings are rejected.</p>
          </div>
        </header>
        <form
          className="hunt-form"
          onSubmit={(event) => {
            event.preventDefault();
            if (!value.trim()) return;
            void api
              .addIoc({
                kind,
                value: value.trim(),
                note: note || null,
                expiresInDays: Number(days) || undefined
              })
              .then((rows) => {
                setIocs(rows);
                setValue("");
                setNote("");
                setMsg(null);
              })
              .catch((err) => setMsg(err instanceof Error ? err.message : "IOC rejected"));
          }}
        >
          <select value={kind} onChange={(e) => setKind(e.target.value)}>
            <option value="ip">ip</option>
            <option value="domain">domain</option>
            <option value="hash">hash</option>
            <option value="other">other</option>
          </select>
          <input value={value} onChange={(e) => setValue(e.target.value)} placeholder="203.0.113.10" />
          <input value={note} onChange={(e) => setNote(e.target.value)} placeholder="note" />
          <input value={days} onChange={(e) => setDays(e.target.value)} placeholder="expires in days" />
          <button className="primary" type="submit">Add IOC</button>
        </form>
        {msg && <p className="muted pad">{msg}</p>}
        <div className="ops-list">
          {iocs.map((row) => (
            <div className="ops-row" key={row.id}>
              <span>
                <strong>{row.kind}</strong> {row.value}
                {row.expiresAt ? ` · until ${row.expiresAt.slice(0, 10)}` : ""}
              </span>
              <button className="ghost" onClick={() => void api.deleteIoc(row.id).then(setIocs)}>
                Remove
              </button>
            </div>
          ))}
        </div>
        <header className="panel-head">
          <div>
            <h2>Custom detection rules</h2>
            <p>JSON array. Optional response is block_ip, kill_pid, or quarantine. A response still waits for confirmation.</p>
          </div>
          <button
            className="primary"
            onClick={() => {
              try {
                const parsed = JSON.parse(rules) as unknown;
                if (!Array.isArray(parsed)) throw new Error("must be an array");
                void api
                  .saveCustomRules(parsed)
                  .then((saved) => {
                    setRules(JSON.stringify(saved, null, 2));
                    setMsg("Rules saved");
                  })
                  .catch((err) => setMsg(err instanceof Error ? err.message : "invalid JSON"));
              } catch (err) {
                setMsg(err instanceof Error ? err.message : "invalid JSON");
              }
            }}
          >
            Save rules
          </button>
        </header>
        <textarea className="rules-editor" value={rules} onChange={(e) => setRules(e.target.value)} spellCheck={false} />
      </article>
    </div>
  );
}
