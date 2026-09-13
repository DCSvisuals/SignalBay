import { useState } from "react";
import { Beaker, Crosshair, FileBarChart, Newspaper, Radar, Shield } from "lucide-react";
import { NewsHub } from "./components/NewsHub";
import { SiemDashboard } from "./components/SiemDashboard";
import { TopBar } from "./components/TopBar";
import { Hunt } from "./pages/Hunt";
import { IntelOps } from "./pages/IntelOps";
import { Reports } from "./pages/Reports";
import { usePlatform } from "./hooks/usePlatform";
import { api } from "./lib/api";
import type { EventOrigin } from "./types";

type Tab = "siem" | "hunt" | "reports" | "intel" | "demo" | "news";

export default function App() {
  const [tab, setTab] = useState<Tab>("siem");
  const origin: EventOrigin = tab === "demo" ? "demo" : "live";
  const platform = usePlatform(origin);

  return (
    <div className="app-shell">
      <div className="scanlines" aria-hidden />
      <TopBar
        connected={platform.connected}
        stats={platform.stats}
        llm={platform.llm}
        onRefresh={() => void platform.refresh()}
      />
      <nav className="tab-bar" aria-label="Primary">
        <button
          className={tab === "siem" ? "tab active" : "tab"}
          onClick={() => setTab("siem")}
        >
          <Radar size={15} />
          SIEM Live Dashboard
        </button>
        <button className={tab === "hunt" ? "tab active" : "tab"} onClick={() => setTab("hunt")}>
          <Crosshair size={15} />
          Hunt
        </button>
        <button className={tab === "reports" ? "tab active" : "tab"} onClick={() => setTab("reports")}>
          <FileBarChart size={15} />
          Reports
        </button>
        <button className={tab === "intel" ? "tab active" : "tab"} onClick={() => setTab("intel")}>
          <Shield size={15} />
          Rules & IOC
        </button>
        <button
          className={tab === "demo" ? "tab active" : "tab"}
          onClick={() => setTab("demo")}
        >
          <Beaker size={15} />
          Demo
        </button>
        <button
          className={tab === "news" ? "tab active" : "tab"}
          onClick={() => setTab("news")}
        >
          <Newspaper size={15} />
          Cyber News Threat Intel Hub
        </button>
      </nav>
      <main className="workspace">
        {tab === "hunt" ? (
          <Hunt />
        ) : tab === "reports" ? (
          <Reports />
        ) : tab === "intel" ? (
          <IntelOps />
        ) : tab === "news" ? (
          <NewsHub
            news={platform.news}
            llm={platform.llm}
            onNewsUpdate={(item) =>
              platform.setNews((prev) => {
                const rest = prev.filter((row) => row.id !== item.id);
                return [item, ...rest];
              })
            }
          />
        ) : (
          <SiemDashboard
            events={platform.events}
            incidents={platform.incidents}
            query={platform.query}
            setQuery={platform.setQuery}
            llm={platform.llm}
            news={platform.news}
            demoMode={tab === "demo"}
            demoStreaming={platform.demoStreaming}
            stats={platform.stats}
            onInject={(transport) =>
              void api.inject(8, transport).then(() => platform.refresh())
            }
            onToggleStream={(transport) =>
              void platform.setDemoStream(!platform.demoStreaming[transport], transport)
            }
            onIncidentUpdate={(incident) =>
              platform.setIncidents((prev) => {
                const rest = prev.filter((row) => row.id !== incident.id);
                return [incident, ...rest];
              })
            }
            fim={platform.fim}
            inventoryHits={platform.inventoryHits}
            responses={platform.responses}
            onResponseUpdate={(item) =>
              platform.setResponses((prev) => {
                const rest = prev.filter((row) => row.id !== item.id);
                return [item, ...rest];
              })
            }
            onCaseStatus={(id, status) =>
              void api.setIncidentStatus(id, status).then((incident) =>
                platform.setIncidents((prev) => {
                  const rest = prev.filter((row) => row.id !== incident.id);
                  return [incident, ...rest];
                })
              )
            }
          />
        )}
      </main>
    </div>
  );
}
