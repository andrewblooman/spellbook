import type { AttackPath, FindingDetail, FindingSummary, Posture, Run, Tier } from "./types";

async function req<T>(method: string, path: string, body?: unknown): Promise<T> {
  const init: RequestInit = { method };
  if (body !== undefined) {
    init.headers = { "content-type": "application/json" };
    init.body = JSON.stringify(body);
  }
  const r = await fetch(path, init);
  const ct = r.headers.get("content-type") || "";
  const data = ct.includes("application/json") ? await r.json().catch(() => ({})) : {};
  if (!r.ok) throw new Error((data as { detail?: string }).detail || `HTTP ${r.status}`);
  return data as T;
}

export interface ManualStepInput {
  technique: string;
  posture: Posture;
  from_entity?: string;
  to_entity?: string;
  description?: string;
  suggested_tool?: string | null;
}

export const api = {
  findings: () => req<FindingSummary[]>("GET", "/findings"),
  finding: (id: string) => req<FindingDetail>("GET", `/findings/${encodeURIComponent(id)}`),
  attackPath: (id: string) => req<AttackPath>("GET", `/attack-paths/${encodeURIComponent(id)}`),
  runs: () => req<Run[]>("GET", "/runs"),
  run: (id: string) => req<Run>("GET", `/runs/${encodeURIComponent(id)}`),

  ingestWiz: (first = 20) => req<{ ingested: string[] }>("POST", "/wiz/ingest", { first }),

  createManualPath: (payload: {
    id: string;
    finding: { id: string; vector: string; severity: string; asset_id: string; host?: string; title?: string };
    name: string;
    entry_point: string;
    impact: string;
    steps: ManualStepInput[];
  }) => req<{ id: string; finding_id: string }>("POST", "/attack-paths", payload),

  startRun: (payload: {
    finding_id: string;
    posture: Posture;
    tier: Tier;
    attack_path_id?: string | null;
    authorization_id?: string | null;
  }) => req<Run>("POST", "/runs", payload),
};
