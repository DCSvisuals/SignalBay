import { useEffect, useState } from "react";
import { api } from "../lib/api";
import type { IocRecord } from "../types";

export function IntelOps() {
  const [rules, setRules] = useState("[]");
  const [iocs, setIocs] = useState<IocRecord[]>([]);
  const [value, setValue] = useState("");
  const [kind, setKind] = useState("ip");
  const [note, setNote] = useState("");
  const [msg, setMsg] = useState<string | null>(null);

  const load = () => {
    void api.customRules().then((rows) => setRules(JSON.stringify(rows, null, 2)));
    void api.iocs().then(setIocs);
  };

  useEffect(() => {
    load();
  }, []);

  return (
    <div className="reports-grid">
      <article className="panel">
        <header className="panel-head">
          <div>
            <h2>Custom detection rules</h2>
            <p>JSON array in Application Support. Pattern is a JavaScript regex.</p>
          </div>
          <button
            className="primary"
            onClick={() => {
              try {
                const parsed = JSON.parse(rules) as unknown;
                if (!Array.isArray(parsed)) throw new Error("must be an array");
                void api.saveCustomRules(parsed).then((saved) => {
                  setRules(JSON.stringify(saved, null, 2));
                  setMsg("Rules saved");
                });
              } catch (err) {
                setMsg(err instanceof Error ? err.message : "invalid JSON");
              }
            }}
          >
            Save rules
          </button>
        </header>
        <textarea className="rules-editor" value={rules} onChange={(e) => setRules(e.target.value)} spellCheck={false} />
        {msg && <p className="muted">{msg}</p>}
      </article>
      <article className="panel">
        <header className="panel-head">
          <div>
            <h2>Threat intel IOCs</h2>
            <p>IPs, domains, or hashes. Matched on ingest against message and source IP.</p>
          </div>
        </header>
        <form
          className="hunt-form"
          onSubmit={(event) => {
            event.preventDefault();
            if (!value.trim()) return;
            void api.addIoc({ kind, value: value.trim(), note: note || null }).then((rows) => {
              setIocs(rows);
              setValue("");
              setNote("");
            });
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
          <button className="primary" type="submit">
            Add IOC
          </button>
        </form>
        <div className="ops-list">
          {iocs.map((row) => (
            <div className="ops-row" key={row.id}>
              <span>
                <strong>{row.kind}</strong> {row.value}
              </span>
              <button className="ghost" onClick={() => void api.deleteIoc(row.id).then(setIocs)}>
                Remove
              </button>
            </div>
          ))}
        </div>
      </article>
    </div>
  );
}
