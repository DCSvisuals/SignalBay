import { ChevronDown, Search } from "lucide-react";
import { useEffect, useLayoutEffect, useMemo, useRef, useState } from "react";
import { groupEventsByHour, type GroupWindow, type LogGroup } from "../lib/groupLogs";
import type { LogEvent, LogTransport } from "../types";
import { LOG_TRANSPORTS } from "../types";
import { LogProcessPopup } from "./LogProcessPopup";

interface Ports {
  udp: number | null;
  tcp: number | null;
  tls: number | null;
  relp: number | null;
  host?: number | null;
}

interface Props {
  events: LogEvent[];
  query: string;
  setQuery: (value: string) => void;
  demoMode?: boolean;
  demoStreaming?: Record<LogTransport, boolean>;
  onInject?: (transport: LogTransport) => void;
  onToggleStream?: (transport: LogTransport) => void;
  ports?: Ports;
}

const ROW = 34;
const ACCORDION_ROW = 22;
const ACCORDION_CAP = 16;
const LANES: Array<{
  id: LogTransport;
  title: string;
  liveHint: string;
  demoHint: string;
}> = [
  {
    id: "udp",
    title: "UDP stream",
    liveHint: "RFC 5426 datagrams",
    demoHint: "Synthetic UDP only"
  },
  {
    id: "tcp",
    title: "TCP stream",
    liveHint: "RFC 6587 octet-counting / NL",
    demoHint: "Synthetic TCP only"
  },
  {
    id: "tls",
    title: "TLS stream",
    liveHint: "RFC 5425 syslog over TLS",
    demoHint: "Synthetic TLS only"
  },
  {
    id: "relp",
    title: "RELP stream",
    liveHint: "rsyslog Reliable Event Logging",
    demoHint: "Synthetic RELP only"
  },
  {
    id: "host",
    title: "Host stream",
    liveHint: "This Mac: sshd, sudo, FIM — not syslog UDP",
    demoHint: "Host sensor is live-only"
  }
];

type SeverityFilter = "all" | "critical" | "high" | "medium" | "info";

const FILTERS: Array<{ id: SeverityFilter; label: string }> = [
  { id: "all", label: "All" },
  { id: "critical", label: "Critical" },
  { id: "high", label: "High" },
  { id: "medium", label: "Medium" },
  { id: "info", label: "Info" }
];

const IDLE_STREAMS: Record<LogTransport, boolean> = {
  udp: false,
  tcp: false,
  tls: false,
  relp: false,
  host: false
};

export function LiveLogStream({
  events,
  query,
  setQuery,
  demoMode = false,
  demoStreaming = IDLE_STREAMS,
  onInject,
  onToggleStream,
  ports
}: Props) {
  const [transport, setTransport] = useState<LogTransport>("udp");
  const byTransport = useMemo(() => {
    const next: Record<LogTransport, LogEvent[]> = {
      udp: [],
      tcp: [],
      tls: [],
      relp: [],
      host: []
    };
    for (const event of events) {
      const lane = event.transport && LOG_TRANSPORTS.includes(event.transport) ? event.transport : "udp";
      next[lane].push(event);
    }
    return next;
  }, [events]);
  const lane = LANES.find((item) => item.id === transport) ?? LANES[0];
  const port = ports?.[lane.id] ?? null;

  return (
    <article className="panel live-panel">
      <header className="panel-head">
        <div>
          <h2>{demoMode ? "Demo Log Stream" : "Live Log Stream"}</h2>
          <p>
            {demoMode
              ? `Synthetic ${lane.id.toUpperCase()} only. Never mixed with real collector traffic.`
              : `One collector at a time · ${lane.id.toUpperCase()}${port ? ` :${port}` : ""} selected.`}
          </p>
        </div>
        {demoMode && (
          <div className="demo-controls">
            <button className="ghost" onClick={() => onInject?.(lane.id)}>
              Inject
            </button>
            <button
              className={demoStreaming[lane.id] ? "primary" : "ghost"}
              onClick={() => onToggleStream?.(lane.id)}
            >
              {demoStreaming[lane.id] ? "Stop" : "Stream"}
            </button>
          </div>
        )}
        <label className="search">
          <Search size={13} />
          <input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search host, app, message"
          />
        </label>
      </header>
      <div className="stream-tabs" role="tablist" aria-label="Collector transport">
        {LANES.map((item) => (
          <button
            key={item.id}
            type="button"
            role="tab"
            aria-selected={transport === item.id}
            className={`stream-tab ${item.id} ${transport === item.id ? "on" : ""}`}
            onClick={() => setTransport(item.id)}
          >
            {item.id.toUpperCase()}
            {ports?.[item.id] ? ` :${ports[item.id]}` : ""}
          </button>
        ))}
      </div>
      <TransportPane
        key={lane.id}
        transport={lane.id}
        port={port}
        events={byTransport[lane.id]}
        demoMode={demoMode}
      />
    </article>
  );
}

function TransportPane({
  transport,
  port,
  events,
  demoMode
}: {
  transport: LogTransport;
  port: number | null;
  events: LogEvent[];
  demoMode: boolean;
}) {
  const scroller = useRef<HTMLDivElement>(null);
  const [scrollTop, setScrollTop] = useState(0);
  const [height, setHeight] = useState(0);
  const [pinned, setPinned] = useState(true);
  const [selected, setSelected] = useState<LogGroup | null>(null);
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [filter, setFilter] = useState<SeverityFilter>("all");
  const [groupWindow, setGroupWindow] = useState<GroupWindow>("1h");

  const counts = useMemo(() => {
    const next = { all: events.length, critical: 0, high: 0, medium: 0, info: 0, low: 0 };
    for (const event of events) {
      next[event.severityLabel] += 1;
    }
    next.info += next.low;
    return next;
  }, [events]);

  const filtered = useMemo(() => {
    if (filter === "all") return events;
    if (filter === "info") {
      return events.filter((event) => event.severityLabel === "info" || event.severityLabel === "low");
    }
    return events.filter((event) => event.severityLabel === filter);
  }, [events, filter]);

  const groups = useMemo(() => groupEventsByHour(filtered, groupWindow), [filtered, groupWindow]);

  useLayoutEffect(() => {
    const el = scroller.current;
    if (!el) return;
    const measure = () => {
      const next = el.clientHeight;
      if (next > 0) {
        setHeight((prev) => (prev === next ? prev : next));
      }
    };
    measure();
    const raf = window.requestAnimationFrame(measure);
    const obs = new ResizeObserver(measure);
    obs.observe(el);
    window.addEventListener("resize", measure);
    return () => {
      window.cancelAnimationFrame(raf);
      obs.disconnect();
      window.removeEventListener("resize", measure);
    };
  }, [groups.length, expandedId]);

  useEffect(() => {
    if (pinned && scroller.current) {
      scroller.current.scrollTop = 0;
      setScrollTop(0);
    }
  }, [groups, pinned]);

  useEffect(() => {
    if (scroller.current) {
      scroller.current.scrollTop = 0;
      setScrollTop(0);
    }
  }, [filter]);

  const heights = useMemo(
    () => groups.map((group) => groupHeight(group, expandedId === group.id)),
    [groups, expandedId]
  );
  const totalHeight = useMemo(() => heights.reduce((sum, h) => sum + h, 0), [heights]);

  const visible = useMemo(() => {
    const viewportPx = height > 40 ? height : 280;
    let offset = 0;
    let start = 0;
    while (start < heights.length && offset + heights[start] < scrollTop - 8 * ROW) {
      offset += heights[start];
      start += 1;
    }
    let end = start;
    let span = 0;
    while (end < heights.length && span < viewportPx + 16 * ROW) {
      span += heights[end];
      end += 1;
    }
    return {
      start,
      offset,
      rows: groups.slice(start, end)
    };
  }, [groups, height, heights, scrollTop]);

  return (
    <section className={`stream-pane single ${transport}`}>
      <div className="log-legend" role="tablist" aria-label={`${transport} severity filter`}>
        {FILTERS.map((item) => (
          <button
            key={item.id}
            type="button"
            role="tab"
            aria-selected={filter === item.id}
            className={`sev-filter ${item.id} ${filter === item.id ? "on" : ""}`}
            onClick={() => setFilter(item.id)}
          >
            {item.label}
            <strong>{counts[item.id]}</strong>
          </button>
        ))}
        <button className={pinned ? "link on" : "link"} onClick={() => setPinned((v) => !v)}>
          {pinned ? "pinned" : "follow"}
        </button>
        <span className="window-label">Group</span>
        {(["live", "1m", "5m", "1h"] as GroupWindow[]).map((item) => (
          <button
            key={item}
            type="button"
            className={groupWindow === item ? "link on" : "link"}
            onClick={() => setGroupWindow(item)}
          >
            {item === "live" ? "Live" : item}
          </button>
        ))}
      </div>
      <div className="log-head" aria-hidden="false">
        <span className="sev-col">Sev</span>
        <span>{groupWindow === "1h" ? "Hour" : "Time"}</span>
        <span>Host</span>
        <span>Process</span>
        <span>Message</span>
        <span />
      </div>
      <div
        className="log-scroller"
        ref={scroller}
        onScroll={(e) => {
          const top = e.currentTarget.scrollTop;
          setScrollTop(top);
          setPinned(top < 24);
        }}
      >
        <div className="log-spacer" style={{ height: totalHeight }}>
          <div style={{ transform: `translateY(${visible.offset}px)` }}>
            {visible.rows.map((group) => {
              const open = expandedId === group.id;
              const event = group.latest;
              return (
                <div className={open ? "log-group open" : "log-group"} key={group.id}>
                  <button
                    type="button"
                    className={group.id === selected?.id ? "log-row selected" : "log-row"}
                    onClick={() => {
                      setPinned(false);
                      setSelected(group);
                    }}
                  >
                    <span className={`sev-bar ${event.severityLabel}`} />
                    <time>
                      {group.hourLabel}
                      {group.count > 1 ? <strong className="dup-count">×{group.count}</strong> : null}
                    </time>
                    <span className="host">{event.hostname ?? event.sourceIp ?? "—"}</span>
                    <span className="app" title="Open process details">
                      {event.appName ?? "syslog"}
                      {event.procId ? <em>:{event.procId}</em> : null}
                    </span>
                    <span className="msg" title={event.message}>
                      {event.message}
                    </span>
                    {group.count > 1 ? (
                      <span
                        className={open ? "acc-toggle on" : "acc-toggle"}
                        title="Show copies this hour"
                        onClick={(e) => {
                          e.stopPropagation();
                          setExpandedId(open ? null : group.id);
                        }}
                      >
                        <ChevronDown size={12} />
                      </span>
                    ) : (
                      <span />
                    )}
                  </button>
                  {open && (
                    <div className="log-accordion">
                      {group.events.slice(0, ACCORDION_CAP).map((row) => (
                        <button
                          type="button"
                          className="log-acc-row"
                          key={row.id}
                          onClick={() => {
                            setPinned(false);
                            setSelected(group);
                          }}
                        >
                          <time>{formatClock(row.receivedAt)}</time>
                          <span>{row.message}</span>
                        </button>
                      ))}
                      {group.count > ACCORDION_CAP ? (
                        <div className="log-acc-more">+{group.count - ACCORDION_CAP} more this hour</div>
                      ) : null}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </div>
        {filtered.length === 0 && (
          <div className="empty compact">
            {events.length === 0
              ? demoMode
                ? `No demo ${transport.toUpperCase()} logs yet. Inject or start this stream.`
                : `Waiting for live ${transport.toUpperCase()} on ${port ? `:${port}` : "the collector"}…`
              : `No ${filter === "all" ? "" : filter + " "}events in this ${transport.toUpperCase()} stream.`}
          </div>
        )}
      </div>
      {selected && (
        <LogProcessPopup
          event={selected.latest}
          events={events}
          hourCopies={selected.events}
          hourLabel={selected.hourLabel}
          onClose={() => setSelected(null)}
        />
      )}
    </section>
  );
}

function groupHeight(group: LogGroup, expanded: boolean): number {
  if (!expanded || group.count < 2) return ROW;
  const n = Math.min(group.events.length, ACCORDION_CAP);
  return ROW + 8 + n * ACCORDION_ROW + (group.count > ACCORDION_CAP ? 18 : 0);
}

function formatClock(iso: string): string {
  const d = new Date(iso);
  const pad = (n: number, w = 2) => String(n).padStart(w, "0");
  return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}.${pad(d.getMilliseconds(), 3)}`;
}
