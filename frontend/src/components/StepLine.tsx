/**
 * Renders a numeric step line from pre-sliced NumSegment[] as bare SVG <line>s,
 * meant to be dropped inside an existing <svg>. Each segment is a horizontal run
 * at its value; adjacent segments get a vertical connector. Non-adjacent segments
 * (a gap left by `laneNumSegments`) are left disconnected on purpose.
 */
import type { NumSegment } from "../lib/ipsec-graph";

interface Props {
  segments: NumSegment[];
  xFor: (t: number) => number;
  yFor: (v: number) => number;
  /** Colour per value; defaults to a single accent. */
  colorFor?: (v: number) => string;
  connectorColor?: string;
  strokeWidth?: number;
  title?: (s: NumSegment) => string;
}

export default function StepLine({
  segments,
  xFor,
  yFor,
  colorFor,
  connectorColor = "#475569",
  strokeWidth = 2.5,
  title,
}: Props) {
  return (
    <>
      {segments.map((s, i) => {
        const prev = i > 0 ? segments[i - 1] : null;
        const adjacent = prev !== null && Math.abs(prev.to - s.from) < 1;
        return (
          <g key={i}>
            {adjacent && prev && (
              <line
                x1={xFor(s.from)}
                x2={xFor(s.from)}
                y1={yFor(prev.value)}
                y2={yFor(s.value)}
                stroke={connectorColor}
                strokeWidth={strokeWidth}
              />
            )}
            <line
              x1={xFor(s.from)}
              x2={xFor(s.to)}
              y1={yFor(s.value)}
              y2={yFor(s.value)}
              stroke={colorFor ? colorFor(s.value) : "#38bdf8"}
              strokeWidth={strokeWidth}
              strokeLinecap="round"
            >
              {title && <title>{title(s)}</title>}
            </line>
          </g>
        );
      })}
    </>
  );
}
