import { useMemo, useState } from "react";
import type { LlmStatus, NewsItem } from "../types";
import { AiSummaryCard } from "./AiSummaryCard";
import { HeadlineGrid } from "./HeadlineGrid";

interface Props {
  news: NewsItem[];
  llm: LlmStatus | null;
  onNewsUpdate: (item: NewsItem) => void;
}

export function NewsHub({ news, llm, onNewsUpdate }: Props) {
  const [selectedId, setSelectedId] = useState<number | null>(null);
  const selected = useMemo(
    () => news.find((row) => row.id === selectedId) ?? news[0] ?? null,
    [news, selectedId]
  );

  return (
    <section className="news-grid">
      <HeadlineGrid news={news} selectedId={selected?.id ?? null} onSelect={setSelectedId} />
      <AiSummaryCard item={selected} llm={llm} onUpdated={onNewsUpdate} />
    </section>
  );
}
