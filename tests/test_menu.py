from spellbook.config import Settings
from spellbook.menu import MenuSelection, edit_settings, launch_menu
from spellbook.wiz.cache import CachedIssue


def test_launch_menu_offline_file_flow(tmp_path):
    subject = tmp_path / "subject.json"
    subject.write_text("{}")
    answers = iter(["f", "WIZ-123", str(subject)])
    output = []

    selection = launch_menu(
        wiz_available=False,
        settings=Settings(),
        issues=[],
        input_fn=lambda _: next(answers),
        output_fn=output.append,
    )

    assert selection == MenuSelection(
        action="investigate", issue_id="WIZ-123", subject_file=subject,
    )
    assert any("Investigate from subject file" in line for line in output)


def test_pick_cached_issue_returns_subject():
    issue = CachedIssue(id="WIZ-9", title="Exposed key", severity="HIGH",
                        subject={"id": "WIZ-9", "severity": "HIGH"})
    answers = iter(["1"])
    output = []

    selection = launch_menu(
        wiz_available=True,
        settings=Settings(),
        issues=[issue],
        input_fn=lambda _: next(answers),
        output_fn=output.append,
    )

    assert selection.action == "investigate"
    assert selection.issue_id == "WIZ-9"
    assert selection.subject == {"id": "WIZ-9", "severity": "HIGH"}


def test_settings_action():
    answers = iter(["s"])
    output = []
    selection = launch_menu(
        wiz_available=True, settings=Settings(), issues=[],
        input_fn=lambda _: next(answers), output_fn=output.append,
    )
    assert selection == MenuSelection(action="settings")


def test_authenticate_action():
    answers = iter(["a"])
    selection = launch_menu(
        wiz_available=False, settings=Settings(), issues=[],
        input_fn=lambda _: next(answers), output_fn=lambda _: None,
    )
    assert selection == MenuSelection(action="authenticate")


def test_refresh_blocked_when_wiz_unavailable():
    answers = iter(["r", "q"])
    output = []
    selection = launch_menu(
        wiz_available=False, settings=Settings(), issues=[],
        input_fn=lambda _: next(answers), output_fn=output.append,
    )
    assert selection == MenuSelection(action="quit")
    assert any("authenticate first" in line for line in output)


def test_chat_action():
    selection = launch_menu(
        wiz_available=False, settings=Settings(), issues=[],
        input_fn=lambda _: next(iter(["c"])), output_fn=lambda _: None,
    )
    assert selection == MenuSelection(action="chat")


def test_collect_action():
    selection = launch_menu(
        wiz_available=False, settings=Settings(), issues=[],
        input_fn=lambda _: next(iter(["e"])), output_fn=lambda _: None,
    )
    assert selection == MenuSelection(action="collect")


def test_quit_action():
    answers = iter(["q"])
    selection = launch_menu(
        wiz_available=True, settings=Settings(), issues=[],
        input_fn=lambda _: next(answers), output_fn=lambda _: None,
    )
    assert selection == MenuSelection(action="quit")


def test_help_then_quit():
    answers = iter(["h", "q"])
    output = []
    selection = launch_menu(
        wiz_available=True, settings=Settings(), issues=[],
        input_fn=lambda _: next(answers), output_fn=output.append,
    )
    assert selection == MenuSelection(action="quit")
    assert any("Spellbook help" in line for line in output)


def test_edit_settings_updates_fields():
    answers = iter(["3", "CRITICAL", "n"])
    updated = edit_settings(
        Settings(), input_fn=lambda _: next(answers), output_fn=lambda _: None,
    )
    assert updated.issue_count == 3
    assert updated.min_severity == "CRITICAL"
    assert updated.auto_fetch is False


def test_edit_settings_keeps_current_on_blank_or_invalid():
    answers = iter(["", "BOGUS", ""])
    output = []
    base = Settings(issue_count=5, min_severity="HIGH", auto_fetch=True)
    updated = edit_settings(
        base, input_fn=lambda _: next(answers), output_fn=output.append,
    )
    assert updated == base
    assert any("Unknown severity" in line for line in output)
