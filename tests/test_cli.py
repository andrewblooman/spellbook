from typer.testing import CliRunner

from spellbook import cli


runner = CliRunner()


def test_should_launch_menu_when_no_subcommand_and_tty():
    assert cli._should_launch_menu(None, True, True) is True


def test_should_not_launch_menu_when_subcommand_present():
    assert cli._should_launch_menu("investigate", True, True) is False


def test_no_args_noninteractive_shows_help():
    result = runner.invoke(cli.app, [])
    assert result.exit_code == 0
    assert "Usage:" in result.output
    assert "investigate" in result.output


def test_menu_command_delegates_to_loop(monkeypatch):
    called = {"value": False}

    def fake_menu_loop():
        called["value"] = True

    monkeypatch.setattr(cli, "_menu_loop", fake_menu_loop)

    result = runner.invoke(cli.app, ["menu"])
    assert result.exit_code == 0
    assert called["value"] is True


def test_menu_loop_dispatches_investigate(monkeypatch):
    from spellbook.config import Settings
    from spellbook.menu import MenuSelection

    monkeypatch.setattr(cli, "load_settings", lambda: Settings())
    monkeypatch.setattr(cli, "wiz_configured", lambda: False)
    monkeypatch.setattr(cli, "_load_or_fetch_issues", lambda *a, **k: [])

    selections = iter([
        MenuSelection(action="investigate", issue_id="WIZ-1", subject={"x": 1}),
        MenuSelection(action="quit"),
    ])
    monkeypatch.setattr(cli, "launch_menu", lambda **kw: next(selections))

    ran = {}

    def fake_run(issue_id, subject_file=None, subject=None):
        ran["issue_id"] = issue_id
        ran["subject"] = subject

    monkeypatch.setattr(cli, "_run_investigation", fake_run)

    cli._menu_loop()
    assert ran == {"issue_id": "WIZ-1", "subject": {"x": 1}}


def test_load_or_fetch_truncates_cached_to_issue_count(monkeypatch):
    from spellbook.config import Settings
    from spellbook.wiz.cache import CachedIssue, IssueCache

    cached = IssueCache(
        fetched_at="2026-06-20T10:00:00+00:00",
        settings_fingerprint="5:HIGH",
        issues=[CachedIssue(id=f"WIZ-{n}") for n in range(5)],
    )
    monkeypatch.setattr(cli, "load_cache", lambda: cached)

    # wiz unavailable → serve cache, but honour the lowered count.
    result = cli._load_or_fetch_issues(Settings(issue_count=2), wiz_available=False, refresh=False)
    assert [i.id for i in result] == ["WIZ-0", "WIZ-1"]


def test_menu_loop_settings_persists(monkeypatch):
    from spellbook.config import Settings
    from spellbook.menu import MenuSelection

    monkeypatch.setattr(cli, "load_settings", lambda: Settings())
    monkeypatch.setattr(cli, "wiz_configured", lambda: False)
    monkeypatch.setattr(cli, "_load_or_fetch_issues", lambda *a, **k: [])

    selections = iter([
        MenuSelection(action="settings"),
        MenuSelection(action="quit"),
    ])
    monkeypatch.setattr(cli, "launch_menu", lambda **kw: next(selections))
    monkeypatch.setattr(cli, "edit_settings", lambda s: Settings(issue_count=2))

    saved = {}
    monkeypatch.setattr(cli, "save_settings", lambda s: saved.update(count=s.issue_count))

    cli._menu_loop()
    assert saved == {"count": 2}
