import { FileWarning, PackageSearch, ShieldBan } from "lucide-react";
import { useEffect, useState } from "react";
import { api } from "../lib/api";
import { newsForCves } from "../lib/cveNews";
import type { FimRecord, InventoryHit, NewsItem, ResponseAction } from "../types";
import { InventoryCvePopup } from "./InventoryCvePopup";
import { SplitPane } from "./SplitPane";

interface Props {
  fim: FimRecord[];
  inventoryHits: InventoryHit[];
  responses: ResponseAction[];
  news?: NewsItem[];
  demoMode?: boolean;
  onResponseUpdate: (item: ResponseAction) => void;
}

export function SiemOps({
  fim,
  inventoryHits,
  responses,
  news = [],
  demoMode,
  onResponseUpdate
}: Props) {
  const pending = responses.filter((row) => row.status === "pending");
  const decided = responses.filter((row) => row.status !== "pending").slice(0, 8);
  const [pf, setPf] = useState<{ ready: boolean; detail: string } | null>(null);
  useEffect(() => {
    void api.pfStatus().then(setPf).catch(() => undefined);
  }, [responses]);
  const [selectedHit, setSelectedHit] = useState<InventoryHit | null>(null);
  const [hitArticles, setHitArticles] = useState<NewsItem[]>([]);
  const [hitLoading, setHitLoading] = useState(false);

  const openHit = (row: InventoryHit) => {
    setSelectedHit(row);
    setHitArticles(newsForCves(news, [row.cve]).matches);
    setHitLoading(true);
    void api
      .newsByCves([row.cve])
      .then((rows) => setHitArticles(rows.length ? rows : newsForCves(news, [row.cve]).matches))
      .catch(() => undefined)
      .finally(() => setHitLoading(false));
  };

  const decide = async (id: number, confirm: boolean) => {
    const updated = await api.confirmResponse(id, confirm);
    onResponseUpdate(updated);
  };
  const undo = async (id: number) => {
    const updated = await api.undoResponse(id);
    onResponseUpdate(updated);
  };

  return (
    <div className="siem-ops">
      <SplitPane
        axis="vertical"
        defaultRatio={0.42}
        minFirst={120}
        minSecond={140}
        storageKey="localsiem.split.ops"
        stackBelow={1100}
      >
        <SplitPane
          axis="horizontal"
          defaultRatio={0.5}
          minFirst={120}
          minSecond={120}
          storageKey="localsiem.split.fim"
          stackBelow={720}
        >
          <article className="panel ops-panel">
            <header className="panel-head">
              <div>
                <h2>File Integrity</h2>
                <p>Watched launch agents, sshd_config, hosts</p>
              </div>
              <FileWarning size={14} />
            </header>
            <div className="ops-list">
              {fim.length === 0 && <div className="empty compact">No FIM changes.</div>}
              {fim.map((row) => (
                <div className="ops-row" key={row.id}>
                  <span className={`sev ${row.status === "changed" ? "high" : "info"}`}>{row.status}</span>
                  <span title={row.path}>{row.path.split("/").slice(-3).join("/")}</span>
                </div>
              ))}
            </div>
          </article>
          <article className="panel ops-panel">
            <header className="panel-head">
              <div>
                <h2>Inventory / KEV</h2>
                <p>Local apps matched to CISA KEV</p>
              </div>
              <PackageSearch size={14} />
            </header>
            <div className="ops-list">
              {inventoryHits.length === 0 && (
                <div className="empty compact">
                  {demoMode ? "Inventory runs on the live agent, not Demo." : "No KEV matches in inventory."}
                </div>
              )}
              {inventoryHits.map((row) => (
                <button
                  type="button"
                  className="ops-row"
                  key={row.id}
                  onClick={() => openHit(row)}
                  title={`Open ${row.cve}`}
                >
                  <span className="cve">{row.cve}</span>
                  <span>
                    {row.name}
                    {row.confidence ? ` · ${row.confidence}` : ""}
                  </span>
                </button>
              ))}
            </div>
          </article>
        </SplitPane>
        <article className="panel ops-panel">
          <header className="panel-head">
            <div>
              <h2>Active Response</h2>
              <p>
                {pf?.ready
                  ? "pf anchor localsiem is loaded. Confirm before block, kill, or quarantine."
                  : "A block is applied only when pf accepts the anchor. Confirm still asks first."}
              </p>
            </div>
            <ShieldBan size={14} />
          </header>
          <div className="ops-list">
            {pf && !pf.ready && <pre className="pf-note">{pf.detail}</pre>}
            {pending.length === 0 && decided.length === 0 && (
              <div className="empty compact">No pending actions.</div>
            )}
            {pending.map((row) => (
              <div className="ops-action" key={row.id}>
                <div>
                  <strong>{row.action.replace("_", " ")}</strong> {row.target}
                  <pre>{row.command}</pre>
                </div>
                <div className="demo-controls">
                  <button className="primary" onClick={() => void decide(row.id, true)}>
                    Confirm
                  </button>
                  <button className="ghost" onClick={() => void decide(row.id, false)}>
                    Deny
                  </button>
                </div>
              </div>
            ))}
            {decided.map((row) => (
              <div className="ops-action" key={`ex-${row.id}`}>
                <div>
                  <strong>
                    {row.status} · {row.action.replace("_", " ")}
                  </strong>{" "}
                  {row.target}
                  <pre>{row.output ?? row.status}</pre>
                </div>
                {row.action === "block_ip" && row.status === "executed" && (
                  <div className="demo-controls">
                    <button className="ghost" onClick={() => void undo(row.id)}>
                      Undo
                    </button>
                  </div>
                )}
              </div>
            ))}
          </div>
        </article>
      </SplitPane>
      {selectedHit && (
        <InventoryCvePopup
          hit={selectedHit}
          articles={hitArticles}
          loading={hitLoading}
          onClose={() => setSelectedHit(null)}
        />
      )}
    </div>
  );
}
