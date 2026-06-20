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

from datetime import datetime, timezone

from spellbook.agent.session import chat as run_chat
from spellbook.agent.session import investigate as run_investigate
from spellbook.banner import banner
from spellbook.case.model import Case, Verdict
from spellbook.case.store import CASES_ROOT, CaseStore
from spellbook.collect import CheckError, run_gitleaks
from spellbook.config import load_settings, save_settings, settings_path
from spellbook.menu import edit_settings, launch_menu
from spellbook.mcp.servers import wiz_configured
from spellbook.wiz.auth import ensure_wiz_auth
from spellbook.wiz.cache import build_cache, fetch_top_issues, is_fresh, load_cache, save_cache

app = typer.Typer(
    name="spellbook",
    help="Triage Wiz security issues with an evidence-backed, safety-gated agent.",
    no_args_is_help=False,
    add_completion=False,
)


def _run_investigation(issue_id: str, subject_file: Path | None = None,
                       subject: dict | None = None) -> None:
    store = CaseStore.open_or_resume(case_id=issue_id, wiz_issue_id=issue_id, mode="interactive")

    if subject is not None:
        store.case.subject = subject
        store.save()
        store.append_audit("SUBJECT loaded from cached top-issues list")
        typer.echo(f"Loaded cached subject for {issue_id}")
    elif subject_file is not None:
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
    _maybe_record_verdict(store)


_VERDICT_STATUSES = {"confirmed", "refuted", "inconclusive"}


def _maybe_record_verdict(store: CaseStore) -> None:
    """After a session, optionally capture the analyst's verdict onto the case."""
    if not sys.stdin.isatty():
        return
    if not typer.confirm("\nRecord a verdict for this case now?", default=False):
        return
    status = typer.prompt("Verdict (confirmed/refuted/inconclusive)",
                          default="inconclusive").strip().lower()
    if status not in _VERDICT_STATUSES:
        typer.secho("Unknown status — verdict not recorded.", fg=typer.colors.YELLOW)
        return
    rationale = typer.prompt("Rationale (cite evidence ids, e.g. E001)", default="").strip()
    store.case.verdict = Verdict(status=status, rationale=rationale)
    store.save()
    store.append_audit(f"VERDICT {status}\t{rationale!r}")
    typer.echo(f"Verdict recorded: {status}")


def _run_chat() -> None:
    """Open a free-form analyst chat backed by a scratch case (gate + audit apply)."""
    scratch_id = "chat-" + datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    store = CaseStore.open_or_resume(case_id=scratch_id, wiz_issue_id="(chat)", mode="interactive")
    typer.echo(f"Scratch case: {store.dir}")
    anyio.run(run_chat, store)


def _run_collect() -> None:
    """Run a deterministic check on a local repo and record it as case evidence."""
    issue_id = typer.prompt("Case id to attach evidence to (e.g. WIZ-12345)").strip()
    if not issue_id:
        typer.secho("No case id — cancelled.", fg=typer.colors.YELLOW)
        return
    source = typer.prompt("Local path to the repo to scan").strip()

    store = CaseStore.open_or_resume(case_id=issue_id, wiz_issue_id=issue_id, mode="interactive")
    typer.echo("Running gitleaks (redacted)…")
    try:
        command, output = run_gitleaks(Path(source))
    except CheckError as exc:
        typer.secho(str(exc), fg=typer.colors.YELLOW)
        return

    item = store.append_evidence(tool="gitleaks", command=command,
                                 side_effect="passive", raw=output)
    store.append_audit(f"MANUAL evidence {item.id} via gitleaks on {source!r}")
    typer.echo(f"Saved evidence {item.id} → {store.dir / item.raw_ref}")
    typer.echo(output.strip()[:1000] or "(no output)")


def _load_or_fetch_issues(settings, wiz_available: bool, refresh: bool) -> list:
    """Return the top-issues list, fetching from Wiz when needed. Never raises."""
    cache = load_cache()
    # Always honour the current count when serving cached issues, so lowering the
    # count is reflected immediately rather than only after the next live fetch.
    cached = cache.issues[: settings.issue_count] if cache else []
    if not wiz_available:
        return cached
    if not refresh and not settings.auto_fetch:
        return cached
    if not refresh and is_fresh(cache, settings):
        return cached

    typer.echo("Fetching top issues from Wiz…")
    try:
        issues = anyio.run(fetch_top_issues, settings)
    except Exception as exc:  # fetch failures must never crash the launcher
        typer.secho(f"Could not fetch issues: {exc}", fg=typer.colors.YELLOW)
        return cached
    save_cache(build_cache(settings, issues))
    return issues


def _menu_loop() -> None:
    """Stateful launcher: auth, fetch/cache, then dispatch menu actions."""
    typer.echo(banner())
    settings = load_settings()
    wiz_available = wiz_configured()
    issues = _load_or_fetch_issues(settings, wiz_available, refresh=False)

    while True:
        selection = launch_menu(wiz_available=wiz_available, settings=settings, issues=issues)
        action = selection.action

        if action == "quit":
            return
        if action == "settings":
            settings = edit_settings(settings)
            save_settings(settings)
            typer.echo("Settings saved.")
            # Reflect the new count/severity in the displayed feed right away.
            issues = _load_or_fetch_issues(settings, wiz_available, refresh=False)
        elif action == "authenticate":
            if ensure_wiz_auth():
                wiz_available = wiz_configured()
                issues = _load_or_fetch_issues(settings, wiz_available, refresh=True)
        elif action == "refresh":
            issues = _load_or_fetch_issues(settings, wiz_available, refresh=True)
        elif action == "chat":
            _run_chat()
        elif action == "collect":
            _run_collect()
        elif action == "investigate":
            _run_investigation(selection.issue_id, selection.subject_file, selection.subject)
            # Session ended — fall through to redraw the launcher.


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
    _menu_loop()
    raise typer.Exit()


@app.command()
def menu():
    """Open the numbered terminal launcher."""
    _menu_loop()


@app.command()
def settings():
    """Edit launcher preferences (top-issue count, minimum severity, auto-fetch)."""
    current = load_settings()
    updated = edit_settings(current)
    save_settings(updated)
    typer.echo(f"Settings saved to {settings_path()}")


@app.command()
def chat():
    """Open a free-form, safety-gated chat with the analyst AI."""
    _run_chat()


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


def _load_case(case_id: str) -> Case:
    path = CASES_ROOT / case_id / "case.json"
    if not path.exists():
        typer.secho(f"No case {case_id} (looked in {path}).", fg=typer.colors.YELLOW)
        raise typer.Exit(code=1)
    return Case.model_validate_json(path.read_text())


@app.command(name="show")
def case_show(case_id: str):
    """Render a case: subject, evidence chain, and verdict."""
    case = _load_case(case_id)
    typer.echo(f"Case {case.id}  (Wiz {case.wiz_issue_id})  mode={case.mode}")
    typer.echo(f"Created: {case.created_at}")
    typer.echo("Subject:")
    typer.echo(json.dumps(case.subject, indent=2) if case.subject else "  (none)")
    typer.echo(f"\nEvidence ({len(case.evidence)}):")
    for item in case.evidence:
        typer.echo(f"  {item.id}  {item.tool:<22} {item.side_effect:<18} {item.command[:60]}")
    if not case.evidence:
        typer.echo("  (none)")
    if case.verdict:
        verdict = case.verdict
        typer.echo(f"\nVerdict: {verdict.status.upper()}  "
                   f"(risk={verdict.risk_score}, confidence={verdict.confidence})")
        if verdict.rationale:
            typer.echo(f"  {verdict.rationale}")
    else:
        typer.echo("\nVerdict: (none recorded)")


@app.command()
def verdict(
    case_id: str,
    status: str = typer.Option(..., "--status", help="confirmed|refuted|inconclusive"),
    rationale: str = typer.Option("", "--rationale", help="cite evidence ids"),
):
    """Record a verdict on an existing case."""
    if status.lower() not in _VERDICT_STATUSES:
        typer.secho(f"status must be one of {sorted(_VERDICT_STATUSES)}.",
                    fg=typer.colors.YELLOW)
        raise typer.Exit(code=1)
    case = _load_case(case_id)
    store = CaseStore(case)
    store.case.verdict = Verdict(status=status.lower(), rationale=rationale)
    store.save()
    store.append_audit(f"VERDICT {status.lower()}\t{rationale!r}")
    typer.echo(f"Verdict recorded for {case_id}: {status.lower()}")


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
