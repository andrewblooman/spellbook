import type { CSSProperties, ReactNode } from "react";

export function SectionHead({ title, sub }: { title: string; sub?: string }) {
  return (
    <div className="section-head">
      <h3>{title}</h3>
      {sub && <span className="note">{sub}</span>}
    </div>
  );
}

export function StatCard({
  label, value, hint, accent = "var(--arc)",
}: {
  label: string;
  value: ReactNode;
  hint?: string;
  accent?: string;
}) {
  return (
    <div className="panel pad stat-card" style={{ "--accent": accent } as CSSProperties}>
      <span className="eyebrow">{label}</span>
      <div className="stat-value">{value}</div>
      {hint && <span className="note">{hint}</span>}
    </div>
  );
}

export interface Segment {
  key: string;
  count: number;
  color: string;
}

/** A horizontal stacked bar with a legend — used for the severity distribution. */
export function DistributionBar({ segments }: { segments: Segment[] }) {
  const total = segments.reduce((n, s) => n + s.count, 0);
  if (total === 0) return <div className="empty">No data yet.</div>;
  return (
    <div>
      <div className="dist-bar">
        {segments.filter((s) => s.count > 0).map((s) => (
          <span
            key={s.key}
            className="dist-seg"
            style={{ width: `${(s.count / total) * 100}%`, background: s.color }}
            title={`${s.key}: ${s.count}`}
          />
        ))}
      </div>
      <div className="dist-legend">
        {segments.map((s) => (
          <span key={s.key} className="dist-legend-item">
            <span className="swatch" style={{ background: s.color }} />
            {s.key.toLowerCase()} <strong>{s.count}</strong>
          </span>
        ))}
      </div>
    </div>
  );
}

/** A pure-CSS donut (conic-gradient) with a centered total and a legend. */
export function Donut({ segments, centerLabel }: { segments: Segment[]; centerLabel?: string }) {
  const total = segments.reduce((n, s) => n + s.count, 0);
  let acc = 0;
  const stops =
    total === 0
      ? "var(--line) 0 100%"
      : segments
          .filter((s) => s.count > 0)
          .map((s) => {
            const start = (acc / total) * 360;
            acc += s.count;
            const end = (acc / total) * 360;
            return `${s.color} ${start}deg ${end}deg`;
          })
          .join(", ");
  return (
    <div className="donut-wrap">
      <div className="donut" style={{ background: `conic-gradient(${stops})` }}>
        <div className="donut-hole">
          <strong>{total}</strong>
          {centerLabel && <span>{centerLabel}</span>}
        </div>
      </div>
      <div className="dist-legend col">
        {segments.map((s) => (
          <span key={s.key} className="dist-legend-item">
            <span className="swatch" style={{ background: s.color }} />
            {s.key.toLowerCase().replace(/_/g, " ")} <strong>{s.count}</strong>
          </span>
        ))}
      </div>
    </div>
  );
}
