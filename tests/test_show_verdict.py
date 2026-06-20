from typer.testing import CliRunner

from spellbook import cli
from spellbook.case import store as store_mod
from spellbook.case.model import Case, EvidenceItem

runner = CliRunner()


def _seed_case(root, case_id="WIZ-1", verdict=None):
    case = Case(
        id=case_id, wiz_issue_id=case_id, mode="interactive",
        subject={"type": "exposed_secret", "repo": "https://github.com/acme/x"},
        evidence=[EvidenceItem(id="E001", tool="gitleaks", command="gitleaks detect",
                               side_effect="passive")],
        verdict=verdict,
    )
    (root / case_id).mkdir(parents=True, exist_ok=True)
    (root / case_id / "case.json").write_text(case.model_dump_json(indent=2))


def _isolate(monkeypatch, tmp_path):
    monkeypatch.setattr(cli, "CASES_ROOT", tmp_path)
    monkeypatch.setattr(store_mod, "CASES_ROOT", tmp_path)


def test_show_missing_case(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    result = runner.invoke(cli.app, ["show", "WIZ-404"])
    assert result.exit_code == 1
    assert "No case WIZ-404" in result.output


def test_show_renders_case(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    _seed_case(tmp_path)
    result = runner.invoke(cli.app, ["show", "WIZ-1"])
    assert result.exit_code == 0
    assert "Case WIZ-1" in result.output
    assert "E001" in result.output
    assert "gitleaks" in result.output
    assert "Verdict: (none recorded)" in result.output


def test_verdict_records_and_show_reflects_it(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    _seed_case(tmp_path)

    result = runner.invoke(
        cli.app, ["verdict", "WIZ-1", "--status", "confirmed", "--rationale", "E001 proves it"],
    )
    assert result.exit_code == 0

    shown = runner.invoke(cli.app, ["show", "WIZ-1"])
    assert "Verdict: CONFIRMED" in shown.output
    assert "E001 proves it" in shown.output


def test_verdict_rejects_bad_status(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    _seed_case(tmp_path)
    result = runner.invoke(cli.app, ["verdict", "WIZ-1", "--status", "maybe"])
    assert result.exit_code == 1
    assert "status must be one of" in result.output
