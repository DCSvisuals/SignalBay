import { useMemo, useState } from "react";
import type {
  FimRecord,
  Incident,
  InventoryHit,
  LlmStatus,
  LogEvent,
  LogTransport,
  NewsItem,
  PlatformStats,
  ResponseAction
} from "../types";
import { AiTriageViewport } from "./AiTriageViewport";
import { AnomalyExplorer } from "./AnomalyExplorer";
import { LiveLogStream } from "./LiveLogStream";
import { SiemOps } from "./SiemOps";
import { SplitPane } from "./SplitPane";

interface Props {
  events: LogEvent[];
  incidents: Incident[];
  query: string;
  setQuery: (value: string) => void;
  llm: LlmStatus | null;
  news: NewsItem[];
  demoMode?: boolean;
  demoStreaming?: Record<LogTransport, boolean>;
  onInject?: (transport: LogTransport) => void;
  onToggleStream?: (transport: LogTransport) => void;
  stats?: PlatformStats | null;
  onIncidentUpdate: (incident: Incident) => void;
  fim?: FimRecord[];
  inventoryHits?: InventoryHit[];
  responses?: ResponseAction[];
  onResponseUpdate?: (item: ResponseAction) => void;
  onCaseStatus?: (id: number, status: Incident["status"]) => void;
}

export function SiemDashboard({
  events,
  incidents,
  query,
  setQuery,
  llm,
  news,
  demoMode = false,
  demoStreaming,
  onInject,
  onToggleStream,
  stats = null,
  onIncidentUpdate,
  fim = [],
  inventoryHits = [],
  responses = [],
  onResponseUpdate,
  onCaseStatus
}: Props) {
  const [selectedId, setSelectedId] = useState<number | null>(null);
  const selected = useMemo(
    () => incidents.find((row) => row.id === selectedId) ?? incidents[0] ?? null,
    [incidents, selectedId]
  );

  return (
    <section className="siem-grid">
      <SplitPane
        axis="vertical"
        defaultRatio={0.42}
        minFirst={200}
        minSecond={240}
        storageKey="localsiem.split.rows"
        stackBelow={1100}
      >
        <SplitPane
          axis="horizontal"
          defaultRatio={1 / 3}
          minFirst={240}
          minSecond={320}
          storageKey="localsiem.split.top"
        >
          <AnomalyExplorer
            incidents={incidents}
            selectedId={selected?.id ?? null}
            onSelect={setSelectedId}
            demoMode={demoMode}
            onCaseStatus={onCaseStatus}
          />
          <AiTriageViewport
            incident={selected}
            llm={llm}
            news={news}
            onUpdated={onIncidentUpdate}
          />
        </SplitPane>
        <SplitPane
          axis="horizontal"
          defaultRatio={2 / 3}
          minFirst={320}
          minSecond={280}
          storageKey="localsiem.split.bottom"
        >
          <LiveLogStream
            events={events}
            query={query}
            setQuery={setQuery}
            demoMode={demoMode}
            demoStreaming={demoStreaming}
            onInject={onInject}
            onToggleStream={onToggleStream}
            ports={{
              udp: stats?.udpPort ?? null,
              tcp: stats?.tcpPort ?? null,
              tls: stats?.tlsPort ?? null,
              relp: stats?.relpPort ?? null
            }}
          />
          <SiemOps
            fim={fim}
            inventoryHits={inventoryHits}
            responses={responses}
            news={news}
            demoMode={demoMode}
            onResponseUpdate={onResponseUpdate ?? (() => undefined)}
          />
        </SplitPane>
      </SplitPane>
    </section>
  );
}
