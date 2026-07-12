"""Tests for the Gemini agent client's launch/poll/parse orchestration.

Uses a fake Interactions backend — no network, no genai SDK — so the state
machine and verdict parsing are verified independently of the live API.
"""

from types import SimpleNamespace

import pytest

from spellbook.control.agent.google_agent import (
    GoogleAgentClient,
    RunnerEndpoint,
)
from spellbook.control.agent.schema import Verdict, VerdictLabel
from spellbook.control.ingest.model import Asset, Finding, Posture, Source, Vector

_VERDICT_JSON = (
    '{"label":"EXPLOITABLE","confidence":0.9,"summary":"open and unauthenticated",'
    '"evidence_chain":[{"tool":"http_probe","target":"api.acme.com",'
    '"observation":"200 no auth","interpretation":"admin panel exposed"}],'
    '"reproduction":"GET /admin","attack_path":[]}'
)


class FakeInteractions:
    """Simulates client.interactions: create returns an id; get walks a status script."""

    def __init__(self, statuses, *, output_text=None):
        self.statuses = list(statuses)
        self.output_text = output_text
        self.created_kwargs = None
        self._i = -1

    def create(self, **kwargs):
        self.created_kwargs = kwargs
        return SimpleNamespace(id="int_123")

    def get(self, interaction_id):
        self._i = min(self._i + 1, len(self.statuses) - 1)
        status = self.statuses[self._i]
        text = self.output_text if status == "completed" else None
        return SimpleNamespace(id=interaction_id, status=status, output_text=text)


def _finding():
    return Finding(
        id="F1", source=Source.MANUAL, vector=Vector.EXPOSED_SERVICE, severity="HIGH",
        title="exposed admin", asset=Asset(id="a1", host="api.acme.com"),
    )


def _runner():
    return RunnerEndpoint(url="https://runner.internal/mcp", auth_header={"Authorization": "Bearer x"})


def test_launch_passes_background_and_tools():
    backend = FakeInteractions(["running"])
    client = GoogleAgentClient(backend)
    iid = client.launch(finding=_finding(), posture=Posture.EXTERNAL, runner=_runner())
    assert iid == "int_123"
    kw = backend.created_kwargs
    assert kw["background"] is True
    assert kw["response_mime_type"] == "application/json"
    # remote-MCP runner + google_search registered
    assert any("mcp" in t for t in kw["tools"])
    assert "SHIELDS UP" in kw["system_instruction"]


def test_poll_completes_and_parses_verdict():
    backend = FakeInteractions(["running", "completed"], output_text=_VERDICT_JSON)
    client = GoogleAgentClient(backend, poll_interval=0)
    iid = client.launch(finding=_finding(), posture=Posture.EXTERNAL, runner=_runner())
    run = client.run_to_completion(iid, sleep=lambda _s: None)
    assert run.done and run.status == "completed"
    assert isinstance(run.verdict, Verdict)
    assert run.verdict.label is VerdictLabel.EXPLOITABLE
    assert run.verdict.evidence_chain[0].tool == "http_probe"


def test_completed_with_bad_json_sets_parse_error():
    backend = FakeInteractions(["completed"], output_text="not json")
    client = GoogleAgentClient(backend)
    run = client.poll_once("int_123")
    assert run.verdict is None and run.error == "verdict_parse_failed"


def test_failed_status_is_terminal_with_error():
    backend = FakeInteractions(["failed"])
    client = GoogleAgentClient(backend)
    run = client.run_to_completion("int_123", sleep=lambda _s: None)
    assert run.done and run.verdict is None and run.error


def test_poll_timeout_when_never_terminal():
    backend = FakeInteractions(["running"])  # always running
    client = GoogleAgentClient(backend, max_polls=3)
    run = client.run_to_completion("int_123", sleep=lambda _s: None)
    assert not run.done and run.error == "poll_timeout"


def test_internal_posture_prompt_requests_attack_path():
    backend = FakeInteractions(["running"])
    client = GoogleAgentClient(backend)
    client.launch(finding=_finding(), posture=Posture.INTERNAL, runner=_runner())
    assert "SHIELDS DOWN" in backend.created_kwargs["system_instruction"]
