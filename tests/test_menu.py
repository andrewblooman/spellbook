from spellbook.menu import MenuSelection, launch_menu


def test_launch_menu_offline_flow(tmp_path):
    subject = tmp_path / "subject.json"
    subject.write_text("{}")
    answers = iter(["1", "WIZ-123", str(subject)])
    output = []

    selection = launch_menu(
        wiz_available=False,
        input_fn=lambda _: next(answers),
        output_fn=output.append,
    )

    assert selection == MenuSelection(issue_id="WIZ-123", subject_file=subject)
    assert "1. Investigate from subject file" in output


def test_launch_menu_rejects_unconfigured_wiz_then_exits():
    answers = iter(["2", "4"])
    output = []

    selection = launch_menu(
        wiz_available=False,
        input_fn=lambda _: next(answers),
        output_fn=output.append,
    )

    assert selection is None
    assert any("Wiz is not configured" in line for line in output)


def test_launch_menu_shows_help_then_exits():
    answers = iter(["3", "4"])
    output = []

    selection = launch_menu(
        wiz_available=True,
        input_fn=lambda _: next(answers),
        output_fn=output.append,
    )

    assert selection is None
    assert any("Spellbook help" in line for line in output)
