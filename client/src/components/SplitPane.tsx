import {
  Children,
  useCallback,
  useEffect,
  useRef,
  useState,
  type PointerEvent as ReactPointerEvent,
  type ReactNode
} from "react";

interface Props {
  axis: "horizontal" | "vertical";
  defaultRatio: number;
  minFirst?: number;
  minSecond?: number;
  storageKey: string;
  stackBelow?: number;
  children: ReactNode;
}

function readRatio(key: string, fallback: number): number {
  try {
    const raw = window.localStorage.getItem(key);
    const n = raw ? Number(raw) : NaN;
    if (Number.isFinite(n) && n >= 0.12 && n <= 0.88) return n;
  } catch {
    /* ignore */
  }
  return fallback;
}

export function SplitPane({
  axis,
  defaultRatio,
  minFirst = 160,
  minSecond = 160,
  storageKey,
  stackBelow = axis === "horizontal" ? 1100 : 0,
  children
}: Props) {
  const panes = Children.toArray(children).slice(0, 2);
  const box = useRef<HTMLDivElement>(null);
  const [ratio, setRatio] = useState(defaultRatio);
  const [dragging, setDragging] = useState(false);
  const [stacked, setStacked] = useState(false);
  const ratioRef = useRef(ratio);
  ratioRef.current = ratio;

  useEffect(() => {
    setRatio(readRatio(storageKey, defaultRatio));
  }, [storageKey, defaultRatio]);

  useEffect(() => {
    if (!stackBelow) {
      setStacked(false);
      return;
    }
    const mq = window.matchMedia(`(max-width: ${stackBelow}px)`);
    const sync = () => setStacked(mq.matches);
    sync();
    mq.addEventListener("change", sync);
    return () => mq.removeEventListener("change", sync);
  }, [stackBelow]);

  const persist = (value: number) => {
    try {
      window.localStorage.setItem(storageKey, String(value));
    } catch {
      /* ignore */
    }
  };

  const apply = useCallback(
    (clientX: number, clientY: number) => {
      const el = box.current;
      if (!el) return;
      const rect = el.getBoundingClientRect();
      const gutter = 8;
      const total = (axis === "horizontal" ? rect.width : rect.height) - gutter;
      if (total <= minFirst + minSecond) return;
      const pos = axis === "horizontal" ? clientX - rect.left : clientY - rect.top;
      const next = Math.min(1 - minSecond / total, Math.max(minFirst / total, pos / total));
      ratioRef.current = next;
      setRatio(next);
    },
    [axis, minFirst, minSecond]
  );

  const onPointerDown = (event: ReactPointerEvent<HTMLDivElement>) => {
    if (stacked || event.button !== 0) return;
    event.preventDefault();
    event.currentTarget.setPointerCapture(event.pointerId);
    setDragging(true);
    apply(event.clientX, event.clientY);
  };

  const onPointerMove = (event: ReactPointerEvent<HTMLDivElement>) => {
    if (!dragging) return;
    apply(event.clientX, event.clientY);
  };

  const endDrag = (event: ReactPointerEvent<HTMLDivElement>) => {
    if (!dragging) return;
    setDragging(false);
    persist(ratioRef.current);
    if (event.currentTarget.hasPointerCapture(event.pointerId)) {
      event.currentTarget.releasePointerCapture(event.pointerId);
    }
  };

  return (
    <div
      ref={box}
      className={`split ${axis}${stacked ? " stacked" : ""}${dragging ? " dragging" : ""}`}
    >
      <div
        className="split-pane"
        style={stacked ? undefined : { flex: `0 0 calc(${(ratio * 100).toFixed(3)}% - 4px)` }}
      >
        {panes[0]}
      </div>
      <div
        className="split-gutter"
        role="separator"
        aria-orientation={axis}
        aria-valuemin={12}
        aria-valuemax={88}
        aria-valuenow={Math.round(ratio * 100)}
        aria-label={axis === "horizontal" ? "Resize columns" : "Resize rows"}
        tabIndex={stacked ? -1 : 0}
        onPointerDown={onPointerDown}
        onPointerMove={onPointerMove}
        onPointerUp={endDrag}
        onPointerCancel={endDrag}
        onDoubleClick={() => {
          setRatio(defaultRatio);
          persist(defaultRatio);
        }}
        onKeyDown={(event) => {
          if (stacked) return;
          const step = event.shiftKey ? 0.06 : 0.02;
          const backward = axis === "horizontal" ? "ArrowLeft" : "ArrowUp";
          const forward = axis === "horizontal" ? "ArrowRight" : "ArrowDown";
          if (event.key !== backward && event.key !== forward) return;
          event.preventDefault();
          const next = Math.min(0.88, Math.max(0.12, ratioRef.current + (event.key === backward ? -step : step)));
          ratioRef.current = next;
          setRatio(next);
          persist(next);
        }}
      />
      <div className="split-pane" style={stacked ? undefined : { flex: "1 1 0%" }}>
        {panes[1]}
      </div>
    </div>
  );
}
