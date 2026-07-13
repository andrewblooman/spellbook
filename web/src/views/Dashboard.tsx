import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../api";
import type { FindingSummary, Run } from "../types";
import { VerdictBadge, StatusText } from "../components/Badge";
import { DistributionBar, Donut, SectionHead, StatCard } from "../components/ui";
import {
  computeStats, severityColor, verdictColor, type DashboardStats, type VerdictKey,
} from "../lib/stats";

const VERDICT_KEYS: VerdictKey[] = ["EXPLOITABLE", "NOT_EXPLOITABLE", "INCONCLUSIVE", "none"];

function fmtTime(iso: string | null): string {
  if (!iso) return "";
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? "" : d.toLocaleString();
}

export function Dashboard() {
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [err, setErr] = useState("");

  useEffect(() => {
    Promise.all([api.findings(), api.runs()])
      .then(([findings, runs]: [FindingSummary[], Run[]]) => setStats(computeStats(findings, runs)))
      .catch((e) => setErr(String(e.message ?? e)));
  }, []);

  return (
    <>
      <div className="pagehead">
        <span className="eyebrow">Overview</span>
        <h2>Dashboard</h2>
        <p>Exploitability posture across every ingested finding and validation run.</p>
      </div>

      {err && <div className="err">{err}</div>}
      {!stats && !err && <div className="empty">Summoning the numbers…</div>}

      {stats && (
        <>
          <div className="stat-grid">
            <StatCard label="Findings" value={stats.totals.findings} accent="var(--arc)" />
            <StatCard label="Validation runs" value={stats.totals.runs} accent="var(--deep)" />
            <StatCard label="Paths exercised" value={stats.totals.pathsExercised} accent="var(--ember)" />
            <StatCard
              label="Exploitable"
              value={stats.totals.exploitable}
              hint="findings with a proven path"
              accent="var(--sever)"
            />
          </div>

          <div className="dash-cols">
            <div className="panel pad">
              <SectionHead title="Verdicts" sub="across all runs" />
              <Donut
                centerLabel="runs"
                segments={VERDICT_KEYS.map((k) => ({
                  key: k === "none" ? "no verdict" : k,
                  count: stats.byVerdict[k],
                  color: verdictColor(k),
                }))}
              />
            </div>

            <div className="panel pad">
              <SectionHead title="Findings by severity" />
              <DistributionBar
                segments={stats.bySeverity.map((s) => ({
                  key: s.key, count: s.count, color: severityColor(s.key),
                }))}
              />
              <div style={{ marginTop: 22 }}>
                <SectionHead title="Runs by posture" />
                <DistributionBar
                  segments={[
                    { key: "external", count: stats.byPosture.external, color: "var(--arc)" },
                    { key: "internal", count: stats.byPosture.internal, color: "var(--deep)" },
                  ]}
                />
              </div>
            </div>
          </div>

          <div className="panel pad" style={{ marginTop: 18 }}>
            <SectionHead title="Recent activity" sub="latest validation runs" />
            {stats.recent.length === 0 ? (
              <div className="empty">No runs yet.</div>
            ) : (
              <div className="recent-list">
                {stats.recent.map((r) => (
                  <Link key={r.id} to={`/runs/${encodeURIComponent(r.id)}`} className="recent-row">
                    <span className={`badge ${r.posture === "external" ? "ext" : "int"}`}>
                      {r.posture}
                    </span>
                    <span className="recent-id mono">{r.id}</span>
                    <StatusText status={r.status} />
                    <VerdictBadge verdict={r.verdict} />
                    <span className="recent-time note">{fmtTime(r.created_at)}</span>
                  </Link>
                ))}
              </div>
            )}
          </div>
        </>
      )}
    </>
  );
}
