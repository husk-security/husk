import { cn } from "@huskdev/ui";
import {
  type CSSProperties,
  type ReactNode,
  useCallback,
  useEffect,
  useRef,
  useState,
} from "react";
import { useIsDesktop } from "./useIsDesktop";

/**
 * A draggable list|detail split shared by the Scan and Guide views so they
 * behave identically. Opens at an even half and stays there until the reader
 * drags it: the detail pane's own content decides nothing about its width, so
 * one long finding cannot swallow the list. The detail pane (on the right)
 * carries an explicit pixel width the user can drag; both panes keep a minimum
 * so neither collapses. Desktop only; below `lg` the panes stack and the handle
 * is hidden. The width is session-only (resets on reload) by design.
 *
 * Usage:
 *   const { containerRef, dragging, detailStyle, handle } = useResizableDetail();
 *   <div ref={containerRef} className={cn("flex flex-col lg:flex-row", dragging && "cursor-col-resize select-none")}>
 *     <div className="min-w-0 flex-1">{list}</div>
 *     {handle}
 *     <div className="min-w-0" style={detailStyle}>{detail}</div>
 *   </div>
 */
export function useResizableDetail({
  minList = 360,
  minDetail = 380,
  defaultFraction = 0.5,
}: {
  minList?: number;
  minDetail?: number;
  defaultFraction?: number;
} = {}): {
  containerRef: React.RefObject<HTMLDivElement | null>;
  isDesktop: boolean;
  dragging: boolean;
  detailStyle: CSSProperties | undefined;
  handle: ReactNode;
} {
  const isDesktop = useIsDesktop();
  const containerRef = useRef<HTMLDivElement | null>(null);
  const [containerWidth, setContainerWidth] = useState(0);
  const [detailWidth, setDetailWidth] = useState<number | null>(null);
  const [dragging, setDragging] = useState(false);

  const clamp = useCallback(
    (raw: number, cw: number) => {
      const max = Math.max(minDetail, cw - minList);
      return Math.round(Math.min(Math.max(raw, minDetail), max));
    },
    [minDetail, minList],
  );

  // Seed the width from the container once measurable, and re-clamp on resize so
  // a pane can never be crushed below its minimum.
  useEffect(() => {
    if (!isDesktop) return;
    const el = containerRef.current;
    if (!el) return;
    const sync = () => {
      const w = el.getBoundingClientRect().width;
      if (w === 0) return;
      setContainerWidth(w);
      setDetailWidth((prev) => clamp(prev ?? w * defaultFraction, w));
    };
    sync();
    window.addEventListener("resize", sync);
    return () => window.removeEventListener("resize", sync);
  }, [isDesktop, clamp, defaultFraction]);

  const onPointerMove = useCallback(
    (e: React.PointerEvent<HTMLDivElement>) => {
      if (!dragging) return;
      const el = containerRef.current;
      if (!el) return;
      const rect = el.getBoundingClientRect();
      // The detail pane is on the right, so its width is the distance from the
      // pointer to the container's right edge.
      setDetailWidth(clamp(rect.right - e.clientX, rect.width));
    },
    [dragging, clamp],
  );

  const onKeyDown = useCallback(
    (e: React.KeyboardEvent<HTMLDivElement>) => {
      const w = containerRef.current?.getBoundingClientRect().width;
      if (!w) return;
      const step = e.shiftKey ? 64 : 16;
      const cur = detailWidth ?? w * defaultFraction;
      let next: number | undefined;
      if (e.key === "ArrowLeft") next = cur + step;
      else if (e.key === "ArrowRight") next = cur - step;
      else if (e.key === "Home") next = w - minList;
      else if (e.key === "End") next = minDetail;
      if (next !== undefined) {
        e.preventDefault();
        setDetailWidth(clamp(next, w));
      }
    },
    [detailWidth, clamp, defaultFraction, minList, minDetail],
  );

  const reset = useCallback(() => {
    const w = containerRef.current?.getBoundingClientRect().width;
    if (w) setDetailWidth(clamp(w * defaultFraction, w));
  }, [clamp, defaultFraction]);

  const detailMax = Math.max(minDetail, containerWidth - minList);

  const handle = (
    // biome-ignore lint/a11y/useSemanticElements: a draggable window splitter has no native element; the WAI-ARIA separator role is the correct fit.
    <div
      role="separator"
      aria-orientation="vertical"
      aria-label="Resize the detail pane"
      aria-valuemin={minDetail}
      aria-valuemax={detailMax}
      aria-valuenow={detailWidth ?? 0}
      tabIndex={isDesktop ? 0 : -1}
      onKeyDown={onKeyDown}
      onPointerDown={(e) => {
        e.preventDefault();
        e.currentTarget.setPointerCapture(e.pointerId);
        setDragging(true);
      }}
      onPointerMove={onPointerMove}
      onPointerUp={(e) => {
        e.currentTarget.releasePointerCapture(e.pointerId);
        setDragging(false);
      }}
      onDoubleClick={reset}
      className={cn(
        "relative hidden shrink-0 cursor-col-resize touch-none self-stretch lg:block",
        "w-px bg-border before:absolute before:inset-y-0 before:-left-1 before:-right-1 before:content-['']",
        "hover:bg-accent focus-visible:bg-accent focus-visible:outline-none",
        dragging && "bg-accent",
      )}
    />
  );

  return {
    containerRef,
    isDesktop,
    dragging,
    // An even half until measured, so the pane always has a width of its own:
    // without one it is sized by its content, and a finding with a long path in
    // it would take the list's room the moment it was selected.
    detailStyle: isDesktop
      ? { width: detailWidth ?? "50%", flexShrink: 0 }
      : undefined,
    handle,
  };
}
