"""Google Managed Agent (Gemini Interactions API) client.

Drives a validation run: launch a background interaction that reasons over the
finding and calls the runner's tools via a **remote MCP** endpoint, poll it to
completion, and parse the final JSON into a :class:`Verdict`.

The Interactions API surface is reached through an injected ``backend`` (a thin
Protocol), so the orchestration/state-machine here is unit-tested with a fake and
the genai coupling lives in one adapter (:class:`GenAIInteractionsBackend`).

⚠️  The exact ``ToolParam`` shape for remote-MCP registration and the terminal
Interaction field names are not fully pinned in the SDK docs yet — the two spots
that need live verification are marked ``# VERIFY (live SDK)``.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Protocol

from spellbook.control.agent import prompts
from spellbook.control.agent.schema import Verdict
from spellbook.control.ingest.model import Finding, Posture

# Interaction statuses we treat as terminal.
COMPLETED = "completed"
TERMINAL = {COMPLETED, "failed", "cancelled", "expired"}


@dataclass(frozen=True)
class RunnerEndpoint:
    """A remote-MCP attack-runner the agent may call."""

    url: str
    auth_header: dict[str, str]  # e.g. {"Authorization": "Bearer <short-lived>"}


@dataclass
class AgentRun:
    interaction_id: str
    status: str
    verdict: Verdict | None = None
    raw_output: str | None = None
    error: str | None = None

    @property
    def done(self) -> bool:
        return self.status in TERMINAL


class InteractionsBackend(Protocol):
    """The slice of ``client.interactions`` this client depends on."""

    def create(self, **kwargs: Any) -> Any: ...
    def get(self, interaction_id: str) -> Any: ...


class GoogleAgentClient:
    def __init__(
        self,
        backend: InteractionsBackend,
        *,
        model: str = "gemini-2.5-pro",
        poll_interval: float = 2.0,
        max_polls: int = 300,
    ) -> None:
        self.backend = backend
        self.model = model
        self.poll_interval = poll_interval
        self.max_polls = max_polls

    # --- launch -----------------------------------------------------------
    def launch(
        self,
        *,
        finding: Finding,
        posture: Posture,
        runner: RunnerEndpoint,
        extra_tools: list[Any] | None = None,
    ) -> str:
        """Create a background interaction; return its id for polling."""
        interaction = self.backend.create(
            model=self.model,
            background=True,
            system_instruction=prompts.system_prompt(posture),
            tools=self._build_tools(runner) + list(extra_tools or []),
            response_mime_type="application/json",
            input=prompts.finding_input(finding),
        )
        return interaction.id

    def _build_tools(self, runner: RunnerEndpoint) -> list[dict]:
        # VERIFY (live SDK): confirm the remote-MCP ToolParam key/shape.
        return [
            {"mcp": {"server_url": runner.url, "headers": runner.auth_header}},
            {"google_search": {}},
        ]

    # --- poll -------------------------------------------------------------
    def poll_once(self, interaction_id: str) -> AgentRun:
        interaction = self.backend.get(interaction_id)
        status = getattr(interaction, "status", "unknown")
        run = AgentRun(interaction_id=interaction_id, status=status)
        if status == COMPLETED:
            text = self._extract_text(interaction)
            run.raw_output = text
            run.verdict = self._parse_verdict(text)
            if run.verdict is None:
                run.error = "verdict_parse_failed"
        elif status in TERMINAL:
            run.error = getattr(interaction, "error", status)
        return run

    def run_to_completion(self, interaction_id: str, *, sleep=time.sleep) -> AgentRun:
        """Poll until terminal or ``max_polls`` exhausted."""
        run = self.poll_once(interaction_id)
        polls = 0
        while not run.done and polls < self.max_polls:
            sleep(self.poll_interval)
            run = self.poll_once(interaction_id)
            polls += 1
        if not run.done:
            run.error = "poll_timeout"
        return run

    # --- parse ------------------------------------------------------------
    @staticmethod
    def _extract_text(interaction: Any) -> str | None:
        # VERIFY (live SDK): confirm which field carries the final output text.
        for attr in ("output_text", "text"):
            value = getattr(interaction, attr, None)
            if value:
                return value
        return None

    @staticmethod
    def _parse_verdict(text: str | None) -> Verdict | None:
        if not text:
            return None
        try:
            return Verdict.model_validate_json(text)
        except ValueError:
            return None


def GenAIInteractionsBackend(genai_client: Any) -> InteractionsBackend:  # noqa: N802
    """Adapt a ``google.genai`` client's ``.interactions`` to InteractionsBackend."""
    return genai_client.interactions  # type: ignore[return-value]  # VERIFY (live SDK)
