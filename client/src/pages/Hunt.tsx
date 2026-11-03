import { useState } from "react";
import { api } from "../lib/api";
import type { LogEvent, LogTransport } from "../types";

const CATEGORIES = ["", "auth", "fim", "threat", "network", "host"];

export function Hunt() {
  const [q, setQ] = useState("");
  const [from, setFrom] = useState("");
  const [to, setTo] = useState("");
  const [transport, setTransport] = useState("");
  const [app, setApp] = useState("");
  const [user, setUser] = useState("");
  const [src, setSrc] = useState("");
  const [category, setCategory] = useState("");
  const [rows, setRows] = useState<LogEvent[]>([]);
  const [busy, setBusy] = useState(false);
  const [selected, setSelected] = useState<LogEvent | null>(null);
  const [entity, setEntity] = useState<Awaited<ReturnType<typeof api.entity>> | null>(null);

  const run = async () => {
    setBusy(true);
    try {
      const found = await api.hunt({
        q: q || undefined,
        from: from ? new Date(from).toISOString() : undefined,
        to: to ? new Date(to).toISOString() : undefined,
        transport: transport || undefined,
        app: app || undefined,
        user: user || undefined,
        src: src || undefined,
        category: category || undefined
      });
      setRows(found);
      setSelected(null);
      setEntity(null);
    } finally {
      setBusy(false);
    }
  };

  const openEntity = async (row: LogEvent, kind: "host" | "user" | "ip") => {
    const value = kind === "host" ? row.hostname : kind === "user" ? row.userName : row.srcIp;
    if (!value) return;
    setSelected(row);
    setEntity(await api.entity(kind, value));
  };

  return (
    <article className="panel hunt-panel">
      <header className="panel-head">
        <div>
          <h2>Historical hunt</h2>
          <p>Search retained events by words, user, source IP, and category. Times use the log timestamp.</p>
        </div>
        <button className="primary" disabled={busy} onClick={() => void run()}>
          {busy ? "Searching…" : "Search"}
        </button>
      </header>
      <form
        className="hunt-form"
        onSubmit={(event) => {
          event.preventDefault();
          void run();
        }}
      >
        <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="words in the message" />
        <input type="datetime-local" value={from} onChange={(e) => setFrom(e.target.value)} />
        <input type="datetime-local" value={to} onChange={(e) => setTo(e.target.value)} />
        <select value={transport} onChange={(e) => setTransport(e.target.value)}>
          <option value="">any transport</option>
          {(["udp", "tcp", "tls", "relp", "host"] as LogTransport[]).map((item) => (
            <option key={item} value={item}>
              {item}
            </option>
          ))}
        </select>
        <select value={category} onChange={(e) => setCategory(e.target.value)}>
          {CATEGORIES.map((item) => (
            <option key={item || "any"} value={item}>
              {item || "any category"}
            </option>
          ))}
        </select>
        <input value={app} onChange={(e) => setApp(e.target.value)} placeholder="process" />
        <input value={user} onChange={(e) => setUser(e.target.value)} placeholder="user" />
        <input value={src} onChange={(e) => setSrc(e.target.value)} placeholder="source IP" />
      </form>
      <div className="hunt-layout">
        <div className="hunt-table-wrap">
          <table className="hunt-table">
            <thead>
              <tr>
                <th>Event time</th>
                <th>Tx</th>
                <th>Host</th>
                <th>User</th>
                <th>Source</th>
                <th>Action</th>
                <th>Message</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((row) => (
                <tr
                  key={row.id}
                  className={selected?.id === row.id ? "selected" : ""}
                  onClick={() => void openEntity(row, row.hostname ? "host" : "ip")}
                >
                  <td>{(row.eventTime || row.receivedAt).slice(11, 19)}</td>
                  <td>{row.transport}</td>
                  <td>{row.hostname}</td>
                  <td>{row.userName}</td>
                  <td>{row.srcIp}</td>
                  <td>{row.action}</td>
                  <td title={row.message}>{row.message}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {rows.length === 0 && <div className="empty compact">No rows. Run a search against retained logs.</div>}
        </div>
        <aside className="entity-card">
          {!entity && <div className="empty compact">Click a row to open that host, user, or address.</div>}
          {entity && (
            <>
              <h3>
                {entity.kind} · {entity.value}
              </h3>
              <p className="muted">
                {entity.eventCount} events · {entity.openIncidents} open incidents
              </p>
              <p className="muted">
                {entity.firstSeen ? new Date(entity.firstSeen).toLocaleString() : "—"} →{" "}
                {entity.lastSeen ? new Date(entity.lastSeen).toLocaleString() : "—"}
              </p>
              <ul className="ops-list">
                {entity.actions.map((row) => (
                  <li className="ops-row" key={row.action}>
                    <span>{row.action}</span>
                    <strong>{row.n}</strong>
                  </li>
                ))}
              </ul>
              {selected?.userName && entity.kind !== "user" && (
                <button className="ghost" onClick={() => void openEntity(selected, "user")}>
                  Pivot to user {selected.userName}
                </button>
              )}
              {selected?.srcIp && entity.kind !== "ip" && (
                <button className="ghost" onClick={() => void openEntity(selected, "ip")}>
                  Pivot to {selected.srcIp}
                </button>
              )}
            </>
          )}
        </aside>
      </div>
    </article>
  );
}
