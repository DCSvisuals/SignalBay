import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { api } from "../lib/api";
import type {
  EventOrigin,
  FimRecord,
  Incident,
  InventoryHit,
  LlmStatus,
  LogEvent,
  LogTransport,
  NewsItem,
  PlatformStats,
  ResponseAction,
  WsMessage
} from "../types";

const IDLE_STREAMS: Record<LogTransport, boolean> = {
  udp: false,
  tcp: false,
  tls: false,
  relp: false,
  host: false
};

function asStreamState(value: unknown): Record<LogTransport, boolean> {
  if (value && typeof value === "object") {
    const row = value as Record<string, unknown>;
    return {
      udp: Boolean(row.udp),
      tcp: Boolean(row.tcp),
      tls: Boolean(row.tls),
      relp: Boolean(row.relp),
      host: Boolean(row.host)
    };
  }
  if (value === true) return { udp: true, tcp: true, tls: true, relp: true, host: false };
  return { ...IDLE_STREAMS };
}

const MAX_EVENTS = 800;

export function usePlatform(origin: EventOrigin) {
  const [events, setEvents] = useState<LogEvent[]>([]);
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [news, setNews] = useState<NewsItem[]>([]);
  const [stats, setStats] = useState<PlatformStats | null>(null);
  const [llm, setLlm] = useState<LlmStatus | null>(null);
  const [connected, setConnected] = useState(false);
  const [query, setQuery] = useState("");
  const [demoStreaming, setDemoStreaming] = useState<Record<LogTransport, boolean>>(IDLE_STREAMS);
  const [fim, setFim] = useState<FimRecord[]>([]);
  const [inventoryHits, setInventoryHits] = useState<InventoryHit[]>([]);
  const [responses, setResponses] = useState<ResponseAction[]>([]);
  const wsRef = useRef<WebSocket | null>(null);
  const originRef = useRef(origin);
  originRef.current = origin;

  const hydrate = useCallback(async () => {
    const [eventRows, incidentRows, newsRows, snapshot, fimRows, hits, responseRows] =
      await Promise.all([
        api.events(query || undefined, origin),
        api.incidents(origin),
        api.news(),
        api.stats(),
        api.fim(origin),
        api.inventoryHits(),
        api.responses(origin)
      ]);
    setEvents(eventRows);
    setIncidents(incidentRows);
    setNews(newsRows);
    setStats(snapshot);
    setLlm(snapshot.llm);
    setFim(fimRows);
    setInventoryHits(hits);
    setResponses(responseRows);
  }, [query, origin]);

  useEffect(() => {
    void hydrate().catch((err) => console.warn("hydrate failed", err));
  }, [hydrate]);

  useEffect(() => {
    void api.demoStreamStatus().then((row) => setDemoStreaming(asStreamState(row.streaming))).catch(() => undefined);
  }, []);

  useEffect(() => {
    let closed = false;
    let retry: number | undefined;

    const connect = () => {
      const proto = window.location.protocol === "https:" ? "wss" : "ws";
      const socket = new WebSocket(`${proto}://${window.location.host}/ws`);
      wsRef.current = socket;
      socket.onopen = () => {
        if (!closed) setConnected(true);
      };
      socket.onclose = () => {
        setConnected(false);
        if (!closed) retry = window.setTimeout(connect, 1500);
      };
      socket.onerror = () => socket.close();
      socket.onmessage = (frame) => {
        try {
          const msg = JSON.parse(frame.data as string) as WsMessage;
          if (msg.type === "hello") {
            setStats(msg.payload.stats);
            setLlm(msg.payload.stats.llm);
          } else if (msg.type === "event") {
            if ((msg.payload.origin ?? "live") !== originRef.current) return;
            setEvents((prev) => {
              if (prev.some((row) => row.id === msg.payload.id)) return prev;
              return [msg.payload, ...prev].slice(0, MAX_EVENTS);
            });
          } else if (msg.type === "incident") {
            if ((msg.payload.origin ?? "live") !== originRef.current) return;
            setIncidents((prev) => {
              const rest = prev.filter((row) => row.id !== msg.payload.id);
              return [msg.payload, ...rest];
            });
          } else if (msg.type === "news") {
            setNews((prev) => {
              const rest = prev.filter((row) => row.id !== msg.payload.id);
              return [msg.payload, ...rest];
            });
          } else if (msg.type === "llm_status") {
            setLlm(msg.payload);
            setStats((prev) => (prev ? { ...prev, llm: msg.payload } : prev));
          } else if (msg.type === "stats") {
            setStats(msg.payload);
            setLlm(msg.payload.llm);
          } else if (msg.type === "fim") {
            if (msg.payload.origin !== originRef.current) return;
            setFim((prev) => {
              const rest = prev.filter((row) => row.path !== msg.payload.path);
              return [msg.payload, ...rest].slice(0, 80);
            });
          } else if (msg.type === "inventory_hit") {
            setInventoryHits((prev) => {
              if (prev.some((row) => row.id === msg.payload.id)) return prev;
              return [msg.payload, ...prev].slice(0, 80);
            });
          } else if (msg.type === "response") {
            if (msg.payload.origin !== originRef.current) return;
            setResponses((prev) => {
              const rest = prev.filter((row) => row.id !== msg.payload.id);
              return [msg.payload, ...rest].slice(0, 80);
            });
          }
        } catch {
          /* ignore malformed frames */
        }
      };
    };

    connect();
    return () => {
      closed = true;
      if (retry) window.clearTimeout(retry);
      wsRef.current?.close();
    };
  }, []);

  const filteredEvents = useMemo(() => {
    const scoped = events.filter((event) => (event.origin ?? "live") === origin);
    if (!query.trim()) return scoped;
    const q = query.toLowerCase();
    return scoped.filter((event) =>
      `${event.message} ${event.hostname ?? ""} ${event.appName ?? ""} ${event.raw}`
        .toLowerCase()
        .includes(q)
    );
  }, [events, query, origin]);

  const scopedIncidents = useMemo(
    () => incidents.filter((row) => (row.origin ?? "live") === origin),
    [incidents, origin]
  );

  const setDemoStream = async (enabled: boolean, transport: LogTransport) => {
    const result = await api.demoStream(enabled, transport);
    setDemoStreaming(asStreamState(result.streaming));
  };

  return {
    events: filteredEvents,
    incidents: scopedIncidents,
    news,
    stats,
    llm,
    connected,
    query,
    setQuery,
    refresh: hydrate,
    setIncidents,
    setNews,
    demoStreaming,
    setDemoStream,
    fim,
    inventoryHits,
    responses,
    setResponses
  };
}
