import pytest

from spellbook import config
from spellbook.config import Settings, load_settings, save_settings, settings_path


@pytest.fixture
def isolated_config(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    return tmp_path


def test_defaults_when_missing(isolated_config):
    settings = load_settings()
    assert settings == Settings()
    assert settings.issue_count == 5
    assert settings.min_severity == "HIGH"
    assert settings.auto_fetch is True


def test_round_trip(isolated_config):
    save_settings(Settings(issue_count=3, min_severity="MEDIUM", auto_fetch=False))
    loaded = load_settings()
    assert loaded.issue_count == 3
    assert loaded.min_severity == "MEDIUM"
    assert loaded.auto_fetch is False
    assert settings_path().exists()


def test_corrupt_file_falls_back_to_defaults(isolated_config):
    path = settings_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("not json{")
    assert load_settings() == Settings()


def test_count_out_of_range_rejected():
    with pytest.raises(ValueError):
        Settings(issue_count=0)
    with pytest.raises(ValueError):
        Settings(issue_count=11)


def test_unknown_severity_rejected():
    with pytest.raises(ValueError):
        Settings(min_severity="urgent")


def test_severity_normalised_to_upper():
    assert Settings(min_severity="high").min_severity == "HIGH"


def test_severities_at_or_above():
    assert Settings(min_severity="CRITICAL").severities_at_or_above() == ["CRITICAL"]
    assert Settings(min_severity="HIGH").severities_at_or_above() == ["CRITICAL", "HIGH"]
    assert Settings(min_severity="MEDIUM").severities_at_or_above() == config.SEVERITIES
