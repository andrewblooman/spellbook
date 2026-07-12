import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { api, type ManualStepInput } from "../api";
import type { Posture } from "../types";

const TECHNIQUES = [
  "public_exposure", "exploit_cve", "auth_bypass", "credential_theft",
  "iam_privesc", "lateral_move", "data_access",
];

function blankStep(): ManualStepInput {
  return { technique: "public_exposure", posture: "external", from_entity: "", to_entity: "" };
}

export function ManualBuilder() {
  const nav = useNavigate();
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);

  const [findingId, setFindingId] = useState("MF-1");
  const [title, setTitle] = useState("Untested attack path");
  const [severity, setSeverity] = useState("HIGH");
  const [vector, setVector] = useState("exposed_service");
  const [host, setHost] = useState("");
  const [assetId, setAssetId] = useState("");

  const [pathId, setPathId] = useState("MP-1");
  const [pathName, setPathName] = useState("");
  const [entry, setEntry] = useState("internet");
  const [impact, setImpact] = useState("");
  const [steps, setSteps] = useState<ManualStepInput[]>([blankStep()]);

  function patchStep(i: number, patch: Partial<ManualStepInput>) {
    setSteps((prev) => prev.map((s, j) => (j === i ? { ...s, ...patch } : s)));
  }

  async function submit() {
    setBusy(true); setErr("");
    try {
      await api.createManualPath({
        id: pathId,
        finding: { id: findingId, vector, severity, asset_id: assetId || findingId, host: host || undefined, title },
        name: pathName || title,
        entry_point: entry,
        impact,
        steps,
      });
      nav(`/findings/${encodeURIComponent(findingId)}`);
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div>
      <div className="pagehead">
        <div className="eyebrow">compose</div>
        <h2>New manual test</h2>
        <p>Describe an attack path you want to probe — one that Wiz hasn't flagged. Each step is a
          move an attacker would make; Spellbook will validate whether it actually works.</p>
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 20 }}>
        <div className="panel pad">
          <div className="eyebrow">finding</div>
          <div className="grid2">
            <div><label>Finding id</label><input value={findingId} onChange={(e) => setFindingId(e.target.value)} /></div>
            <div><label>Severity</label>
              <select value={severity} onChange={(e) => setSeverity(e.target.value)}>
                {["CRITICAL", "HIGH", "MEDIUM", "LOW"].map((s) => <option key={s}>{s}</option>)}
              </select>
            </div>
          </div>
          <label>Title</label><input value={title} onChange={(e) => setTitle(e.target.value)} />
          <div className="grid2">
            <div><label>Vector</label>
              <select value={vector} onChange={(e) => setVector(e.target.value)}>
                {["exposed_service", "cve", "misconfig", "iam"].map((v) => <option key={v}>{v}</option>)}
              </select>
            </div>
            <div><label>Target host</label><input value={host} onChange={(e) => setHost(e.target.value)} placeholder="api.acme.com" /></div>
          </div>
          <label>Asset id</label><input value={assetId} onChange={(e) => setAssetId(e.target.value)} placeholder="gcp/vm/web-1" />
        </div>

        <div className="panel pad">
          <div className="eyebrow">path</div>
          <div className="grid2">
            <div><label>Path id</label><input value={pathId} onChange={(e) => setPathId(e.target.value)} /></div>
            <div><label>Name</label><input value={pathName} onChange={(e) => setPathName(e.target.value)} placeholder={title} /></div>
          </div>
          <div className="grid2">
            <div><label>Entry point</label><input value={entry} onChange={(e) => setEntry(e.target.value)} /></div>
            <div><label>Impact</label><input value={impact} onChange={(e) => setImpact(e.target.value)} placeholder="prod database" /></div>
          </div>
        </div>
      </div>

      <div className="panel pad" style={{ marginTop: 20 }}>
        <div style={{ display: "flex", alignItems: "center", marginBottom: 12 }}>
          <div className="eyebrow">steps</div>
          <div className="spacer" />
          <button className="btn ghost" onClick={() => setSteps((s) => [...s, blankStep()])}>+ add step</button>
        </div>

        {steps.map((step, i) => (
          <div key={i} style={{ display: "grid", gridTemplateColumns: "28px 1.3fr 1fr 1fr 1fr 28px", gap: 8, alignItems: "end", marginBottom: 8 }}>
            <div className="mono" style={{ color: "var(--faint)", paddingBottom: 10 }}>{String(i).padStart(2, "0")}</div>
            <div>
              {i === 0 && <label>Technique</label>}
              <select value={step.technique} onChange={(e) => patchStep(i, { technique: e.target.value })}>
                {TECHNIQUES.map((t) => <option key={t}>{t}</option>)}
              </select>
            </div>
            <div>
              {i === 0 && <label>Posture</label>}
              <select value={step.posture} onChange={(e) => patchStep(i, { posture: e.target.value as Posture })}>
                <option value="external">external</option>
                <option value="internal">internal</option>
              </select>
            </div>
            <div>
              {i === 0 && <label>From</label>}
              <input value={step.from_entity} onChange={(e) => patchStep(i, { from_entity: e.target.value })} />
            </div>
            <div>
              {i === 0 && <label>To</label>}
              <input value={step.to_entity} onChange={(e) => patchStep(i, { to_entity: e.target.value })} />
            </div>
            <button className="btn ghost" style={{ padding: "9px 0" }}
              onClick={() => setSteps((s) => s.filter((_, j) => j !== i))} disabled={steps.length === 1}>×</button>
          </div>
        ))}
      </div>

      <div className="toolbar" style={{ marginTop: 20 }}>
        <button className="btn" onClick={submit} disabled={busy}>{busy ? "Saving…" : "Create test"}</button>
        <span className="err">{err}</span>
      </div>
    </div>
  );
}
