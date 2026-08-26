import { cn } from "@huskdev/ui";
import { Hexagon } from "lucide-react";
import type { Severity } from "@/lib/api";

// Severity → text-color class. Shared by the Findings list, the filter grid, and
// the Auto-fix rows so one severity reads identically everywhere.
export const SEV_TEXT: Record<Severity, string> = {
  critical: "text-severity-critical",
  high: "text-severity-high",
  medium: "text-severity-medium",
  low: "text-severity-low",
  info: "text-severity-info",
};
const SEV_LABEL: Record<Severity, string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  info: "Info",
};
// Filled-dot count per level (4 hexagons, descending). info shows 0 filled.
const SEV_DOTS: Record<Severity, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  info: 0,
};

/** Four-hexagon severity meter: filled dots colored by level, neutral label. */
export function SeverityBadge({
  severity,
  className,
}: {
  severity: Severity;
  className?: string;
}) {
  const filled = SEV_DOTS[severity];
  return (
    <span className={cn("inline-flex items-center gap-1.5", className)}>
      <span className="inline-flex items-center gap-0.5">
        {[0, 1, 2, 3].map((i) => (
          <Hexagon
            key={i}
            size={9}
            strokeWidth={2}
            fill={i < filled ? "currentColor" : "none"}
            className={i < filled ? SEV_TEXT[severity] : "text-border-strong"}
          />
        ))}
      </span>
      <span className="text-xs text-fg-muted">{SEV_LABEL[severity]}</span>
    </span>
  );
}
