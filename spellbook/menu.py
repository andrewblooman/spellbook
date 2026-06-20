"""Numbered terminal launcher for the Spellbook CLI.

Pure and I/O-injectable: this module never touches the network, disk, or the
agent. It receives the current state (whether Wiz is configured, the user's
``Settings``, and any cached top issues) and returns the *action* the user chose.
``cli.py`` — the impure shell — performs auth, fetching, and persistence, then
loops back here. That split is what keeps the launcher unit-testable without a TTY.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from spellbook.config import SEVERITIES, Settings


@dataclass(frozen=True)
class MenuSelection:
    # action ∈ investigate | chat | collect | settings | authenticate | refresh | quit
    action: str
    issue_id: str | None = None
    subject_file: Path | None = None
    subject: dict | None = None


def launch_menu(wiz_available: bool, settings: Settings, issues=None,
                input_fn=input, output_fn=print) -> MenuSelection:
    """Show the launcher and return the chosen action."""
    issues = list(issues or [])
    while True:
        _show_menu(wiz_available, settings, issues, output_fn)
        choice = _prompt("Select an option: ", input_fn)
        if choice is None:
            return MenuSelection(action="quit")
        choice = choice.strip().lower()

        if choice in {"q", "quit", "exit"}:
            return MenuSelection(action="quit")
        if choice == "h":
            _show_help(output_fn)
            continue
        if choice == "s":
            return MenuSelection(action="settings")
        if choice == "c":
            return MenuSelection(action="chat")
        if choice == "e":
            return MenuSelection(action="collect")
        if choice == "a":
            return MenuSelection(action="authenticate")
        if choice == "r":
            if not wiz_available:
                output_fn("Wiz is not configured. Choose 'a' to authenticate first.")
                continue
            return MenuSelection(action="refresh")

        # Numbered pick from the cached top-issues list.
        if choice.isdigit():
            index = int(choice) - 1
            if 0 <= index < len(issues):
                picked = issues[index]
                return MenuSelection(
                    action="investigate", issue_id=picked.id, subject=picked.subject,
                )
            output_fn("No issue with that number.")
            continue

        if choice == "f":
            issue_id = _prompt_issue_id(input_fn, output_fn)
            if issue_id is None:
                continue
            subject_file = _prompt_subject_file(input_fn, output_fn)
            if subject_file is None:
                continue
            return MenuSelection(
                action="investigate", issue_id=issue_id, subject_file=subject_file,
            )
        if choice == "w":
            if not wiz_available:
                output_fn("Wiz is not configured. Choose 'a' to authenticate first.")
                continue
            issue_id = _prompt_issue_id(input_fn, output_fn)
            if issue_id is None:
                continue
            return MenuSelection(action="investigate", issue_id=issue_id)

        output_fn("Invalid selection.")


def _show_menu(wiz_available: bool, settings: Settings, issues, output_fn) -> None:
    output_fn("")
    output_fn("Spellbook")
    if not wiz_available:
        output_fn("  (Wiz not configured — choose 'a' to authenticate)")
    if issues:
        sev = settings.min_severity.lower()
        output_fn(f"Top Wiz issues ({sev}+, {len(issues)}):")
        for number, issue in enumerate(issues, start=1):
            label = issue.title or issue.resource or issue.id
            severity = f"{issue.severity:<8}" if issue.severity else ""
            output_fn(f"  {number}. {issue.id}  {severity}{label}")
    else:
        output_fn("No cached issues. Authenticate ('a') and refresh ('r') to load them.")
    output_fn("Actions:")
    output_fn("  f. Investigate from subject file")
    output_fn("  w. Investigate by Wiz issue id")
    output_fn("  e. Collect evidence manually (run a check)")
    output_fn("  c. Chat with the analyst AI")
    output_fn("  r. Refresh top issues")
    output_fn("  s. Settings")
    output_fn("  a. Authenticate to Wiz")
    output_fn("  h. Help")
    output_fn("  q. Quit")


def _show_help(output_fn) -> None:
    output_fn("")
    output_fn("Spellbook help")
    output_fn("- Pick a numbered issue to open a case with that issue pre-loaded.")
    output_fn("- 'f' starts offline triage from a subject JSON file.")
    output_fn("- 'w' starts Wiz-backed triage for an issue id you type.")
    output_fn("- 'e' runs a deterministic check (e.g. gitleaks) on a repo and saves evidence.")
    output_fn("- 'c' opens a free-form, safety-gated chat with the analyst AI.")
    output_fn("- 'a' authenticates to Wiz; 'r' refreshes the top-issues list.")
    output_fn("- 's' edits how many issues to pull and the minimum severity.")
    output_fn("- Direct commands still work, e.g.:")
    output_fn("  spellbook investigate WIZ-123 --subject-file sample_subject.json")


def edit_settings(settings: Settings, input_fn=input, output_fn=print) -> Settings:
    """Pure settings editor: prompt for each field, keep current on blank/invalid."""
    output_fn("")
    output_fn("Settings (press Enter to keep the current value)")

    count = settings.issue_count
    raw = _prompt(f"Number of top issues 1-10 [{count}]: ", input_fn)
    if raw and raw.strip():
        try:
            candidate = int(raw.strip())
        except ValueError:
            output_fn("Not a number — keeping current.")
        else:
            if 1 <= candidate <= 10:
                count = candidate
            else:
                output_fn("Out of range 1-10 — keeping current.")

    severity = settings.min_severity
    raw = _prompt(f"Minimum severity {SEVERITIES} [{severity}]: ", input_fn)
    if raw and raw.strip():
        candidate = raw.strip().upper()
        if candidate in SEVERITIES:
            severity = candidate
        else:
            output_fn("Unknown severity — keeping current.")

    auto = settings.auto_fetch
    raw = _prompt(f"Auto-fetch issues on startup? y/n [{'y' if auto else 'n'}]: ", input_fn)
    if raw and raw.strip():
        answer = raw.strip().lower()
        if answer in {"y", "yes"}:
            auto = True
        elif answer in {"n", "no"}:
            auto = False
        else:
            output_fn("Answer y or n — keeping current.")

    return Settings(issue_count=count, min_severity=severity, auto_fetch=auto)


def _prompt_issue_id(input_fn, output_fn) -> str | None:
    issue_id = _prompt("Enter the Wiz issue id (for example WIZ-12345): ", input_fn)
    if issue_id is None:
        return None
    issue_id = issue_id.strip()
    if issue_id:
        return issue_id
    output_fn("Issue id cannot be empty.")
    return None


def _prompt_subject_file(input_fn, output_fn) -> Path | None:
    raw = _prompt("Enter the path to the subject JSON file [sample_subject.json]: ", input_fn)
    if raw is None:
        return None
    raw = raw.strip() or "sample_subject.json"
    path = Path(raw).expanduser()
    if path.is_file():
        return path
    output_fn(f"{path} does not exist or is not a readable file.")
    return None


def _prompt(message: str, input_fn) -> str | None:
    try:
        return input_fn(message)
    except (EOFError, KeyboardInterrupt):
        return None
