import { useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { api } from "../api";
import type { FindingSummary } from "../types";

export function Findings() {
  const [findings, setFindings] = useState<FindingSummary[]>([]);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const nav = useNavigate();

  const load = () => api.findings().then(setFindings).catch((e) => setErr(String(e.message)));
  useEffect(() => { load(); }, []);

  async function ingest() {
    setBusy(true); setErr("");
    try {
      await api.ingestWiz(20);
      await load();
    } catch (e) {
      setErr(`Wiz ingest failed: ${(e as Error).message}`);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div>
      <div className="pagehead">
        <div className="eyebrow">queue</div>
        <h2>Findings</h2>
        <p>Every finding is a hypothesis about how you could be breached. Open one to see its
          attack path and test whether the chain actually holds.</p>
      </div>

      <div className="toolbar">
        <button className="btn" onClick={() => nav("/new")}>New manual test</button>
        <button className="btn ghost" onClick={ingest} disabled={busy}>
          {busy ? "Ingesting…" : "Ingest from Wiz"}
        </button>
        <div className="spacer" />
        <span className="err">{err}</span>
      </div>

      {findings.length === 0 ? (
        <div className="empty">
          No findings yet. Ingest from Wiz, or define a manual test for something you want to probe.
        </div>
      ) : (
        <div className="cards">
          {findings.map((f) => (
            <Link to={`/findings/${encodeURIComponent(f.id)}`} key={f.id} className="panel pad card">
              <div>
                <div className="title">{f.title || f.id}</div>
                <div className="meta">
                  <span className={`severity ${f.severity}`}>{f.severity || "—"}</span>
                  {" · "}{f.vector}{" · "}{f.target}{" · "}{f.source}
                </div>
              </div>
              <span className="badge muted mono">{f.id}</span>
            </Link>
          ))}
        </div>
      )}
    </div>
  );
}
