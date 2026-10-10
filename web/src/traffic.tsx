import { useMemo } from "react";
import type { HistoryEvent } from "./api";
import { Empty } from "./components";
const outcomes = [
  { label: "Forwarded", color: "var(--chart-forwarded)" },
  { label: "Cached", color: "var(--chart-cache)" },
  { label: "Blocked", color: "var(--chart-blocked)" },
  { label: "Local", color: "var(--chart-other)" },
  { label: "Failed", color: "var(--chart-failure)" },
] as const;
function clock(timestamp: number) {
  return new Date(timestamp).toLocaleTimeString([], {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}
function category(event: HistoryEvent) {
  if (event.source === "failure") return 4;
  if (event.action === "block") return 2;
  if (["cache", "stale"].includes(event.source)) return 1;
  if (event.source === "rewrite") return 3;
  return 0;
}
export function Traffic({ events }: { events: HistoryEvent[] }) {
  const data = useMemo(() => {
    const valid = events
      .map((event) => ({ event, time: new Date(event.timestamp).getTime() }))
      .filter((row) => Number.isFinite(row.time));
    if (!valid.length) return null;
    const start = Math.min(...valid.map((row) => row.time));
    const end = Math.max(...valid.map((row) => row.time));
    const span = Math.max(1, end - start);
    const buckets = Array.from({ length: 16 }, (_, i) => ({
      time: start + (i * span) / 16,
      counts: [0, 0, 0, 0, 0],
    }));
    const totals = [0, 0, 0, 0, 0];
    for (const { event, time } of valid) {
      const index = Math.min(15, Math.floor(((time - start) / span) * 16));
      const bucket = buckets[index];
      const outcome = category(event);
      if (bucket) bucket.counts[outcome] = (bucket.counts[outcome] ?? 0) + 1;
      totals[outcome] = (totals[outcome] ?? 0) + 1;
    }
    return {
      start,
      end,
      buckets,
      totals,
      size: valid.length,
      max: Math.max(
        1,
        ...buckets.map((row) => row.counts.reduce((a, b) => a + b, 0)),
      ),
    };
  }, [events]);
  if (!data) return <Empty>No retained traffic yet.</Empty>;
  const range = `${clock(data.start)}–${clock(data.end)}`;
  return (
    <figure className="traffic-figure">
      <div className="traffic-caption">
        <strong>
          {data.size.toLocaleString()} <span>recorded queries</span>
        </strong>
        <span className="mono">{range}</span>
      </div>
      <svg
        viewBox="0 0 640 225"
        role="img"
        aria-label={`Recent query outcomes: ${data.size} retained events from ${range}. Counts are available in the table below.`}
      >
        {[0, 0.5, 1].map((fraction) => (
          <g key={fraction}>
            <line
              x1="48"
              x2="638"
              y1={188 - fraction * 160}
              y2={188 - fraction * 160}
              className="chart-grid"
            />
            <text
              x="40"
              y={192 - fraction * 160}
              textAnchor="end"
              className="chart-label"
            >
              {Math.round(data.max * fraction)}
            </text>
          </g>
        ))}
        {data.buckets.map((bucket, i) => {
          let offset = 0;
          return (
            <g key={i}>
              {bucket.counts.map((count, series) => {
                const height = (count / data.max) * 160;
                const y = 188 - offset - height;
                offset += height;
                return count ? (
                  <rect
                    key={series}
                    x={54 + i * 36}
                    y={y}
                    width="23"
                    height={height}
                    rx="2"
                    fill={outcomes[series]?.color}
                  >
                    <title>
                      {clock(bucket.time)} · {outcomes[series]?.label}: {count}
                    </title>
                  </rect>
                ) : null;
              })}
            </g>
          );
        })}
        <text x="48" y="217" className="chart-label">
          {clock(data.start)}
        </text>
        <text x="638" y="217" textAnchor="end" className="chart-label">
          {clock(data.end)}
        </text>
      </svg>
      <figcaption className="chart-legend">
        {outcomes.map((outcome, i) => (
          <span key={outcome.label}>
            <i style={{ background: outcome.color }} />
            {outcome.label}
            <b>{data.totals[i]}</b>
          </span>
        ))}
      </figcaption>
      <details className="chart-table">
        <summary>View counts as a table</summary>
        <div className="table-wrap">
          <table>
            <caption>
              16 equal time buckets across {range}; up to 500 retained events.
            </caption>
            <thead>
              <tr>
                <th>Bucket start</th>
                {outcomes.map((outcome) => (
                  <th key={outcome.label}>{outcome.label}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {data.buckets.map((bucket, i) => (
                <tr key={i}>
                  <td className="mono">{clock(bucket.time)}</td>
                  {bucket.counts.map((count, j) => (
                    <td key={j}>{count}</td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </details>
      <p className="sample-note">
        Retained sample, not total traffic. Older and dropped events are
        excluded.
      </p>
    </figure>
  );
}
