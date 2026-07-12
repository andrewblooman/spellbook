import { useCallback, useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { api } from "../api";
import { StepChain } from "../components/StepChain";
import { StatusText, VerdictBadge } from "../components/Badge";
import type { AttackPath, FindingDetail as FindingDetailT, Posture, Run, Tier } from "../types";

export function FindingDetail() {
  const { id = "" } = useParams();
  const [finding, setFinding] = useState<FindingDetailT | null>(null);
  const [paths, setPaths] = useState<Record<string, AttackPath>>({});
  const [runs, setRuns] = useState<Run[]>([]);
  const [err, setErr] = useState("");

  const load = useCallback(async () => {
    try {
      const f = await api.finding(id);
      setFinding(f);
      const detailed = await Promise.all(f.attack_paths.map((p) => api.attackPath(p.id)));
      setPaths(Object.fromEntries(detailed.map((p) => [p.id, p])));
      const allRuns = await api.runs();
      setRuns(allRuns.filter((r) => r.finding_id === id));
    } catch (e) {
      setErr((e as Error).message);
    }
  }, [id]);

  useEffect(() => { load(); }, [load]);

  if (err) return <div className="empty">{err} — <Link to="/">back to findings</Link></div>;
  if (!finding) return <div className="empty">Loading…</div>;

  return (
    <div>
      <div className="pagehead">
        <div className="eyebrow"><Link to="/">findings</Link> / {finding.id}</div>
        <h2>{finding.title || finding.id}</h2>
        <p className="mono note">
          <span className={`severity ${finding.severity}`}>{finding.severity}</span>
          {" · "}{finding.vector}{" · "}{finding.target}{" · "}{finding.cloud}
          {finding.project ? ` · ${finding.project}` : ""}{" · "}{finding.source}
        </p>
      </div>

      {finding.attack_paths.length === 0 && (
        <div className="empty">This finding has no attack path yet.</div>
      )}

      {finding.attack_paths.map((p) => {
        const path = paths[p.id] ?? p;
        return (
          <PathPanel
            key={p.id}
            findingId={finding.id}
            path={path}
            runs={runs.filter((r) => r.attack_path_id === p.id)}
            onRan={load}
          />
        );
      })}
    </div>
  );
}

function PathPanel({
  findingId, path, runs, onRan,
}: { findingId: string; path: AttackPath; runs: Run[]; onRan: () => Promise<void> }) {
  const [posture, setPosture] = useState<Posture>("external");
  const [tier, setTier] = useState<Tier>("active_noninvasive");
  const [auth, setAuth] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");

  async function launch() {
    setBusy(true); setErr("");
    try {
      const run = await api.startRun({
        finding_id: findingId, posture, tier, attack_path_id: path.id,
        authorization_id: tier === "active_invasive" ? auth || null : null,
      });
      if (run.status === "running") await api.completeRun(run.id);
      await onRan();
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="panel pad" style={{ marginBottom: 20 }}>
      <div style={{ display: "grid", gridTemplateColumns: "1fr 280px", gap: 28 }}>
        <div>
          <div className="eyebrow" style={{ marginBottom: 12 }}>
            attack path · {path.source}
          </div>
          <StepChain steps={path.steps} results={path.step_results ?? []} />
        </div>

        <div>
          <div className="eyebrow">validate</div>
          <label>Posture</label>
          <select value={posture} onChange={(e) => setPosture(e.target.value as Posture)}>
            <option value="external">external — shields up</option>
            <option value="internal">internal — shields down</option>
          </select>
          <label>Tier</label>
          <select value={tier} onChange={(e) => setTier(e.target.value as Tier)}>
            <option value="passive">passive</option>
            <option value="active_noninvasive">active · non-destructive</option>
            <option value="active_invasive">active · full exploit</option>
          </select>
          {tier === "active_invasive" && (
            <>
              <label>Authorization id</label>
              <input value={auth} onChange={(e) => setAuth(e.target.value)} placeholder="required for full exploit" />
            </>
          )}
          <button className="btn" style={{ marginTop: 16, width: "100%" }} onClick={launch} disabled={busy}>
            {busy ? "Validating…" : "Run validation"}
          </button>
          <div className="err" style={{ marginTop: 8 }}>{err}</div>
          <p className="note" style={{ fontSize: 12, marginTop: 4 }}>
            Runs the {posture} agent against this path's {posture} steps; the other posture's
            steps are validated by a separate run and merged here.
          </p>
        </div>
      </div>

      {runs.length > 0 && (
        <div style={{ marginTop: 20, borderTop: "1px solid var(--line)", paddingTop: 14 }}>
          <div className="eyebrow" style={{ marginBottom: 10 }}>runs</div>
          {runs.map((r) => (
            <div key={r.id} style={{ display: "flex", gap: 10, alignItems: "center", padding: "6px 0" }}>
              <span className={`badge ${r.posture === "external" ? "ext" : "int"}`}>{r.posture}</span>
              <span className="badge muted mono">{r.tier}</span>
              <StatusText status={r.status} />
              <VerdictBadge verdict={r.verdict} />
              {r.confidence != null && <span className="note mono">conf {r.confidence}</span>}
              {r.error && <span className="note mono" style={{ color: "var(--sever)" }}>{r.error.split(":")[0]}</span>}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
