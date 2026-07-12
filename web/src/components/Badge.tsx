export function VerdictBadge({ verdict }: { verdict: string | null }) {
  if (!verdict) return <span className="badge muted">no verdict</span>;
  const cls = verdict === "EXPLOITABLE" ? "sev" : verdict === "NOT_EXPLOITABLE" ? "hold" : "ember";
  return <span className={`badge ${cls}`}>{verdict.replace(/_/g, " ").toLowerCase()}</span>;
}

export function StatusText({ status }: { status: string }) {
  const map: Record<string, string> = {
    running: "ember", pending: "muted", denied: "sev",
    completed: "hold", error: "sev", completed_no_verdict: "ember",
  };
  return <span className={`badge ${map[status] ?? "muted"}`}>{status.replace(/_/g, " ")}</span>;
}
