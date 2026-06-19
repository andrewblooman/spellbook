"""Numbered terminal launcher for the Spellbook CLI."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class MenuSelection:
    issue_id: str
    subject_file: Path | None = None


def launch_menu(wiz_available: bool, input_fn=input, output_fn=print) -> MenuSelection | None:
    """Collect launch options from a numbered terminal menu."""
    while True:
        _show_menu(wiz_available, output_fn)
        choice = _prompt("Select an option: ", input_fn)
        if choice is None:
            return None
        choice = choice.strip().lower()

        if choice in {"4", "q", "quit", "exit"}:
            return None
        if choice == "3":
            _show_help(output_fn)
            continue
        if choice == "2" and not wiz_available:
            output_fn(
                "Wiz is not configured. Set WIZ_CLIENT_ID and WIZ_CLIENT_SECRET, or use "
                "option 1 for offline triage."
            )
            continue
        if choice not in {"1", "2"}:
            output_fn("Invalid selection. Enter 1, 2, 3, or 4.")
            continue

        issue_id = _prompt_issue_id(input_fn, output_fn)
        if issue_id is None:
            continue
        if choice == "2":
            return MenuSelection(issue_id=issue_id)

        subject_file = _prompt_subject_file(input_fn, output_fn)
        if subject_file is None:
            continue
        return MenuSelection(issue_id=issue_id, subject_file=subject_file)


def _show_menu(wiz_available: bool, output_fn) -> None:
    wiz_label = "Investigate with Wiz credentials"
    if not wiz_available:
        wiz_label += " (not configured)"
    output_fn("")
    output_fn("Spellbook")
    output_fn("1. Investigate from subject file")
    output_fn(f"2. {wiz_label}")
    output_fn("3. Help")
    output_fn("4. Exit")


def _show_help(output_fn) -> None:
    output_fn("")
    output_fn("Spellbook help")
    output_fn("- Choose an option by typing its number and pressing Enter.")
    output_fn("- Option 1 starts offline triage from a subject JSON file.")
    output_fn("- Option 2 starts Wiz-backed triage when WIZ_CLIENT_ID and WIZ_CLIENT_SECRET are set.")
    output_fn("- Direct commands still work, for example:")
    output_fn("  spellbook investigate WIZ-123 --subject-file sample_subject.json")


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
