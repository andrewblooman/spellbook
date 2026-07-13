// Pure client-side aggregation for the dashboard — no network, easily testable.
import type { FindingSummary, Run } from "../types";

export type VerdictKey = "EXPLOITABLE" | "NOT_EXPLOITABLE" | "INCONCLUSIVE" | "none";

export interface DashboardStats {
  totals: { findings: number; runs: number; pathsExercised: number; exploitable: number };
  bySeverity: { key: string; count: number }[];
  byVerdict: Record<VerdictKey, number>;
  byPosture: { external: number; internal: number };
  recent: Run[];
}

const SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];

function verdictKey(v: string | null): VerdictKey {
  if (v === "EXPLOITABLE" || v === "NOT_EXPLOITABLE" || v === "INCONCLUSIVE") return v;
  return "none";
}

export function computeStats(findings: FindingSummary[], runs: Run[], recentN = 6): DashboardStats {
  const bySeverity = new Map<string, number>();
  for (const f of findings) {
    const key = (f.severity || "UNKNOWN").toUpperCase();
    bySeverity.set(key, (bySeverity.get(key) ?? 0) + 1);
  }

  const byVerdict: Record<VerdictKey, number> = {
    EXPLOITABLE: 0, NOT_EXPLOITABLE: 0, INCONCLUSIVE: 0, none: 0,
  };
  const byPosture = { external: 0, internal: 0 };
  const paths = new Set<string>();
  const exploitableFindings = new Set<string>();

  for (const r of runs) {
    byVerdict[verdictKey(r.verdict)] += 1;
    if (r.posture === "external") byPosture.external += 1;
    else if (r.posture === "internal") byPosture.internal += 1;
    if (r.attack_path_id) paths.add(r.attack_path_id);
    if (r.verdict === "EXPLOITABLE") exploitableFindings.add(r.finding_id);
  }

  const severityRank = (k: string) => {
    const i = SEVERITY_ORDER.indexOf(k);
    return i === -1 ? SEVERITY_ORDER.length : i;
  };

  return {
    totals: {
      findings: findings.length,
      runs: runs.length,
      pathsExercised: paths.size,
      exploitable: exploitableFindings.size,
    },
    bySeverity: [...bySeverity.entries()]
      .map(([key, count]) => ({ key, count }))
      .sort((a, b) => severityRank(a.key) - severityRank(b.key)),
    byVerdict,
    byPosture,
    recent: runs.slice(0, recentN),
  };
}

/** Map a severity/verdict/posture label to a theme token color for charts. */
export function severityColor(key: string): string {
  if (key === "CRITICAL" || key === "HIGH") return "var(--sever)";
  if (key === "MEDIUM") return "var(--ember)";
  if (key === "LOW" || key === "INFO") return "var(--deep)";
  return "var(--muted)";
}

export function verdictColor(key: VerdictKey): string {
  if (key === "EXPLOITABLE") return "var(--sever)";
  if (key === "NOT_EXPLOITABLE") return "var(--charge)";
  if (key === "INCONCLUSIVE") return "var(--ember)";
  return "var(--faint)";
}
