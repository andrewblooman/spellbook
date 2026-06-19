"""Session loops: interactive (steerable) investigation.

Milestone 0 implements the interactive loop with ``ClaudeSDKClient`` — the
bidirectional client is what lets the human steer (inject instructions) and
interrupt mid-run. The unattended ``query()`` loop is left for a later milestone.
"""

from __future__ import annotations

from claude_agent_sdk import (
    AssistantMessage,
    ClaudeSDKClient,
    ResultMessage,
    TextBlock,
    ToolResultBlock,
    ToolUseBlock,
)

from spellbook.agent.options import build_options
from spellbook.agent.prompts import opening_prompt
from spellbook.case.store import CaseStore


async def _stream(client: ClaudeSDKClient) -> None:
    """Render assistant text + tool activity for one response turn."""
    async for message in client.receive_response():
        if isinstance(message, AssistantMessage):
            for block in message.content:
                if isinstance(block, TextBlock):
                    print(block.text, end="", flush=True)
                elif isinstance(block, ToolUseBlock):
                    print(f"\n  ⚙ {block.name}({_brief(block.input)})", flush=True)
                elif isinstance(block, ToolResultBlock):
                    print("  ✓ tool result", flush=True)
        elif isinstance(message, ResultMessage):
            print()  # end the turn cleanly


def _brief(tool_input) -> str:
    if isinstance(tool_input, dict):
        cmd = tool_input.get("command") or tool_input.get("skill") or ""
        return (cmd[:80] + "…") if len(str(cmd)) > 80 else str(cmd)
    return ""


async def investigate(store: CaseStore) -> None:
    opts = build_options(store, mode="interactive")
    store.append_audit("SESSION start interactive")
    async with ClaudeSDKClient(options=opts) as client:
        await client.query(opening_prompt(store.case))
        await _stream(client)
        while True:
            try:
                user = input("\nspellbook› ").strip()
            except (EOFError, KeyboardInterrupt):
                break
            if user in {"/quit", "/q", "exit"}:
                break
            if user == "/interrupt":
                await client.interrupt()
                continue
            if not user:
                continue
            await client.query(user)
            await _stream(client)
    store.append_audit("SESSION end interactive")
