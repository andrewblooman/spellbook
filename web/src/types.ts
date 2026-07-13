export type Posture = "external" | "internal";
export type Tier = "passive" | "active_noninvasive" | "active_invasive";
export type StepStatus = "validated" | "refuted" | "inconclusive" | "skipped";

export interface FindingSummary {
  id: string;
  source: string;
  vector: string;
  severity: string;
  title: string;
  host: string | null;
  target: string;
  cloud: string;
  project: string | null;
}

export interface AttackStep {
  index: number;
  technique: string;
  description: string;
  from_entity: string;
  to_entity: string;
  posture: Posture;
  suggested_tool: string | null;
  tier: Tier;
}

export interface StepResult {
  step_index: number;
  status: StepStatus;
  tool: string;
  observation: string;
  interpretation: string;
}

export interface AttackPath {
  id: string;
  finding_id: string;
  name: string;
  source: string;
  entry_point: string;
  impact: string;
  steps: AttackStep[];
  step_results?: StepResult[];
}

export interface FindingDetail extends FindingSummary {
  attack_paths: AttackPath[];
}

export interface Run {
  id: string;
  finding_id: string;
  attack_path_id: string | null;
  posture: Posture;
  tier: Tier;
  status: string;
  created_at: string | null;
  verdict: string | null;
  confidence: number | null;
  error: string | null;
  step_results: StepResult[];
  evidence: { tool: string; target: string; observation: string; interpretation: string }[];
  audit: { ts: string; tool: string; target: string; tier: string; allowed: boolean; reason: string }[];
}
