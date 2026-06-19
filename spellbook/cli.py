"""Spellbook CLI — Wiz security-issue triage.

Milestone 0 implements `investigate` (interactive, steerable). The remaining
verbs are declared so the command surface is visible, but raise until later
milestones.
"""

from __future__ import annotations

import anyio
import json
import sys
from pathlib import Path

import typer

from spellbook.agent.session import investigate as run_investigate
from spellbook.case.store import CaseStore
from spellbook.menu import MenuSelection, launch_menu
from spellbook.mcp.servers import wiz_configured

app = typer.Typer(
    name="spellbook",
    help="Triage Wiz security issues with an evidence-backed, safety-gated agent.",
    no_args_is_help=False,
    add_completion=False,
)


def _run_investigation(issue_id: str, subject_file: Path | None) -> None:
    store = CaseStore.open_or_resume(case_id=issue_id, wiz_issue_id=issue_id, mode="interactive")

    if subject_file is not None:
        store.case.subject = json.loads(subject_file.read_text())
        store.save()
        store.append_audit(f"SUBJECT loaded from file {subject_file}")
        typer.echo(f"Loaded subject for {issue_id} from {subject_file}")
    elif not store.case.subject and not wiz_configured():
        typer.secho(
            "No subject and no Wiz MCP credentials (WIZ_CLIENT_ID/WIZ_CLIENT_SECRET).\n"
            "Set them to ingest from Wiz, or pass --subject-file for offline triage.",
            fg=typer.colors.YELLOW,
        )
        raise typer.Exit(code=1)
    else:
        # Wiz MCP is configured: the agent ingests the subject via the Wiz issue tool
        # during the opening turn (the soc-analyst skill drives it).
        store.append_audit("SUBJECT ingestion delegated to agent via Wiz MCP")

    typer.echo(f"Case dir: {store.dir}")
    anyio.run(run_investigate, store)


def _launch_selection(selection: MenuSelection | None) -> None:
    if selection is None:
        raise typer.Exit()
    _run_investigation(selection.issue_id, selection.subject_file)


def _should_launch_menu(invoked_subcommand: str | None, stdin_tty: bool, stdout_tty: bool) -> bool:
    return invoked_subcommand is None and stdin_tty and stdout_tty


@app.callback(invoke_without_command=True)
def main(ctx: typer.Context) -> None:
    """Launch the numbered terminal menu when started without a subcommand."""
    if not _should_launch_menu(ctx.invoked_subcommand, sys.stdin.isatty(), sys.stdout.isatty()):
        if ctx.invoked_subcommand is None:
            typer.echo(ctx.get_help())
            raise typer.Exit()
        return
    _launch_selection(launch_menu(wiz_available=wiz_configured()))
    raise typer.Exit()


@app.command()
def menu():
    """Open the numbered terminal launcher."""
    _launch_selection(launch_menu(wiz_available=wiz_configured()))


@app.command()
def investigate(
    issue_id: str = typer.Argument(..., help="Wiz issue id, e.g. WIZ-12345"),
    subject_file: Path = typer.Option(
        None, "--subject-file",
        help="JSON file describing the subject (dev fallback when Wiz MCP creds are unset).",
        exists=True, dir_okay=False, readable=True,
    ),
):
    """Open or resume a case and run an interactive, steerable investigation."""
    _run_investigation(issue_id, subject_file)


def _not_yet(name: str):
    raise typer.Exit(
        typer.style(f"`{name}` is planned for a later milestone (Milestone 0 ships `investigate`).",
                    fg=typer.colors.YELLOW)
    )


@app.command()
def run(issue_id: str):
    """Unattended, passive-only triage (Milestone 3)."""
    _not_yet("run")


@app.command()
def batch(query: str = typer.Option(..., "--query")):
    """Auto-triage a set of issues from a Wiz filter (Milestone 3)."""
    _not_yet("batch")


@app.command(name="show")
def case_show(case_id: str):
    """Render a case file + verdict (Milestone 1)."""
    _not_yet("show")


@app.command()
def replay(case_id: str):
    """Deterministically re-run a recorded case (Milestone 1+)."""
    _not_yet("replay")


@app.command()
def export(case_id: str, fmt: str = typer.Option("md", "--format")):
    """Export a case as md/json/sarif (Milestone 1)."""
    _not_yet("export")


@app.command()
def remediate(case_id: str, as_: str = typer.Option(..., "--as", help="pr|linear-ticket")):
    """Draft a remediation PR/ticket after review (Milestone 3)."""
    _not_yet("remediate")


if __name__ == "__main__":
    app()
