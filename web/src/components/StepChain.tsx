import type { AttackStep, StepResult, StepStatus } from "../types";
import "./StepChain.css";

type LinkStatus = StepStatus | "pending";

function statusFor(index: number, results: StepResult[]): LinkStatus {
  const r = results.find((x) => x.step_index === index);
  return r ? r.status : "pending";
}

function summarise(steps: AttackStep[], results: StepResult[]) {
  const broken = steps.find((s) => statusFor(s.index, results) === "refuted");
  if (broken) {
    return { cls: "broken", text: `Chain breaks at step ${broken.index} — ${broken.technique}.` };
  }
  const statuses = steps.map((s) => statusFor(s.index, results));
  const anyPending = statuses.some((s) => s === "pending" || s === "inconclusive");
  const validated = statuses.filter((s) => s === "validated").length;
  if (!anyPending && validated === steps.length) {
    return { cls: "held", text: "Chain holds end to end — every step validated." };
  }
  return { cls: "partial", text: `Chain partially validated — ${validated}/${steps.length} steps confirmed.` };
}

export function StepChain({ steps, results = [] }: { steps: AttackStep[]; results?: StepResult[] }) {
  if (steps.length === 0) return <p className="note">This path has no steps yet.</p>;
  const summary = summarise(steps, results);
  const firstBreak = steps.find((s) => statusFor(s.index, results) === "refuted")?.index;

  return (
    <div>
      <div className={`chain-summary ${summary.cls}`}>{summary.text}</div>
      <div className="chain">
        <div className="terminal">
          <span className="cap"><span className="orb" /></span>
          <span>entry · {steps[0]?.from_entity || "internet"}</span>
        </div>

        {steps.map((step) => {
          const status = statusFor(step.index, results);
          const result = results.find((r) => r.step_index === step.index);
          return (
            <div className="link" key={step.index} data-status={status} data-posture={step.posture}>
              <div className="chain-rail">
                <span className="conduit" />
                <span className="node" />
              </div>
              <div className="body">
                <div className="head">
                  <span className="idx">{String(step.index).padStart(2, "0")}</span>
                  <span className="tech">{step.technique.replace(/_/g, " ")}</span>
                  <span className={`badge ${step.posture === "external" ? "ext" : "int"}`}>
                    {step.posture === "external" ? "shields up" : "shields down"}
                  </span>
                  <StatusPill status={status} />
                  {step.index === firstBreak && <span className="breakflag">⚡ chain breaks</span>}
                </div>
                {(step.from_entity || step.to_entity) && (
                  <div className="flow">
                    {step.from_entity || "—"}
                    <span className="arrow">→</span>
                    {step.to_entity || "—"}
                    {step.suggested_tool && <span> · tool: {step.suggested_tool}</span>}
                  </div>
                )}
                {step.description && <div className="obs">{step.description}</div>}
                {result?.observation && (
                  <div className="obs">
                    <span className="sv">{result.observation}</span>
                    {result.interpretation && <> — {result.interpretation}</>}
                  </div>
                )}
              </div>
            </div>
          );
        })}

        <div className="terminal impact">
          <span className="cap"><span className="orb" /></span>
          <span>impact · {steps[steps.length - 1]?.to_entity || "crown jewels"}</span>
        </div>
      </div>
    </div>
  );
}

function StatusPill({ status }: { status: LinkStatus }) {
  const map: Record<LinkStatus, { cls: string; text: string }> = {
    validated: { cls: "hold", text: "validated" },
    refuted: { cls: "sev", text: "refuted" },
    inconclusive: { cls: "ember", text: "inconclusive" },
    skipped: { cls: "muted", text: "skipped" },
    pending: { cls: "muted", text: "not run" },
  };
  const { cls, text } = map[status];
  return <span className={`badge ${cls}`}>{text}</span>;
}
