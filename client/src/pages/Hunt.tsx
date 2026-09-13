import { useState } from "react";
import { api } from "../lib/api";
import type { LogEvent, LogTransport } from "../types";

export function Hunt() {
  const [q, setQ] = useState("");
  const [from, setFrom] = useState("");
  const [to, setTo] = useState("");
  const [transport, setTransport] = useState("");
  const [app, setApp] = useState("");
  const [rows, setRows] = useState<LogEvent[]>([]);
  const [busy, setBusy] = useState(false);

  const run = async () => {
    setBusy(true);
    try {
      const found = await api.hunt({
        q: q || undefined,
        from: from ? new Date(from).toISOString() : undefined,
        to: to ? new Date(to).toISOString() : undefined,
        transport: transport || undefined,
        app: app || undefined
      });
      setRows(found);
    } finally {
      setBusy(false);
    }
  };

  return (
    <article className="panel hunt-panel">
      <header className="panel-head">
        <div>
          <h2>Historical hunt</h2>
          <p>Search SQLite across retained events (not just the live tail).</p>
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
        <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="query (host, process, IP, message)" />
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
        <input value={app} onChange={(e) => setApp(e.target.value)} placeholder="process" />
      </form>
      <div className="hunt-table-wrap">
        <table className="hunt-table">
          <thead>
            <tr>
              <th>Time</th>
              <th>Tx</th>
              <th>Host</th>
              <th>Process</th>
              <th>Message</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((row) => (
              <tr key={row.id}>
                <td>{row.receivedAt.slice(11, 19)}</td>
                <td>{row.transport}</td>
                <td>{row.hostname}</td>
                <td>{row.appName}</td>
                <td title={row.message}>{row.message}</td>
              </tr>
            ))}
          </tbody>
        </table>
        {rows.length === 0 && <div className="empty compact">No rows. Run a search against retained logs.</div>}
      </div>
    </article>
  );
}
