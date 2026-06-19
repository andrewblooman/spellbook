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


def test_menu_command_delegates_to_launcher(monkeypatch):
    called = {"value": False}

    def fake_launch_selection(selection):
        called["value"] = True

    def fake_launch_menu(*, wiz_available):
        return None

    monkeypatch.setattr(cli, "_launch_selection", fake_launch_selection)
    monkeypatch.setattr(cli, "launch_menu", fake_launch_menu)

    result = runner.invoke(cli.app, ["menu"])
    assert result.exit_code == 0
    assert called["value"] is True
