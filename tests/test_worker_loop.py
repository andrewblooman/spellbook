"""The Claude Agent SDK validation loop, driven by a fake query fn.

No live model and no `claude` CLI: the injectable ``QueryFn`` yields scripted
messages, so the option wiring, verdict parsing, and error paths are verified in
isolation — the same seam the Gemini client's ``InteractionsBackend`` provided.
"""

import json
from types import SimpleNamespace

import anyio

from spellbook.control.agent.schema import VerdictLabel
from spellbook.control.ingest.model import (
    Asset, AttackPath, AttackStep, Finding, Posture, Source, Vector,
)
from spellbook.runner.dispatch import RunContext
from spellbook.worker.loop import AgentValidator, build_options, extract_final_text

_VERDICT_JSON = json.dumps({
    "label": "EXPLOITABLE", "confidence": 0.9, "summary": "open and unauthenticated",
    "evidence_chain": [{"tool": "http_probe", "target": "api.acme.com",
                        "observation": "200 no auth", "interpretation": "admin exposed"}],
    "reproduction": "GET /admin", "attack_path": [],
})


def _finding():
    return Finding(id="F1", source=Source.MANUAL, vector=Vector.EXPOSED_SERVICE, severity="HIGH",
                   title="exposed admin", asset=Asset(id="a1", host="api.acme.com"))


def _ctx(posture=Posture.EXTERNAL):
    return RunContext(posture=posture, scope_allowlist={"acme.com"})


def _scripted_query(*messages, capture=None):
    async def query_fn(*, prompt, options):
        if capture is not None:
            capture["prompt"] = prompt
            capture["options"] = options
        for m in messages:
            yield m
    return query_fn


def _run(validator, *, posture=Posture.EXTERNAL, attack_path=None):
    return anyio.run(lambda: validator.run(
        finding=_finding(), posture=posture, ctx=_ctx(posture), attack_path=attack_path))


def test_build_options_locks_agent_to_runner_tools():
    opts = build_options(_ctx(), model="claude-opus-4-8")
    assert opts.model == "claude-opus-4-8"
    assert opts.permission_mode == "default"  # never bypassPermissions
    assert "runner" in opts.mcp_servers
    assert opts.allowed_tools and all(t.startswith("mcp__runner__") for t in opts.allowed_tools)
    assert "Bash" in opts.disallowed_tools
    assert "SHIELDS UP" in opts.system_prompt


def test_result_message_verdict_is_parsed():
    validator = AgentValidator(query_fn=_scripted_query(
        SimpleNamespace(content=[SimpleNamespace(text="working…")]),
        SimpleNamespace(result=_VERDICT_JSON),
    ))
    run = _run(validator)
    assert run.error is None
    assert run.verdict.label is VerdictLabel.EXPLOITABLE
    assert run.verdict.evidence_chain[0].tool == "http_probe"


def test_bad_json_sets_parse_error():
    validator = AgentValidator(query_fn=_scripted_query(SimpleNamespace(result="not json")))
    run = _run(validator)
    assert run.verdict is None and run.error == "verdict_parse_failed"


def test_query_exception_is_surfaced():
    async def boom(*, prompt, options):
        raise RuntimeError("cli missing")
        yield  # pragma: no cover - makes this an async generator

    run = _run(AgentValidator(query_fn=boom))
    assert run.verdict is None and run.error.startswith("agent_error")


def test_prompt_carries_attack_path_and_posture():
    capture = {}
    validator = AgentValidator(
        query_fn=_scripted_query(SimpleNamespace(result=_VERDICT_JSON), capture=capture))
    path = AttackPath(id="P1", finding_id="F1", name="chain",
                      steps=[AttackStep(index=0, technique="public_exposure",
                                        posture=Posture.EXTERNAL)])
    _run(validator, posture=Posture.INTERNAL, attack_path=path)
    assert "Attack path" in capture["prompt"]
    assert "step 0 [external] public_exposure" in capture["prompt"]
    assert "SHIELDS DOWN" in capture["options"].system_prompt


def test_extract_final_text_prefers_result_then_assistant_text():
    assert extract_final_text([SimpleNamespace(result="final")]) == "final"
    assert extract_final_text([
        SimpleNamespace(content=[SimpleNamespace(text="a"), SimpleNamespace(text="b")]),
    ]) == "ab"
    assert extract_final_text([SimpleNamespace(foo=1)]) is None
