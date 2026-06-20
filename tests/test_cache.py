from datetime import datetime, timedelta, timezone

import pytest

from spellbook.config import Settings
from spellbook.wiz import cache
from spellbook.wiz.cache import (
    CachedIssue,
    build_cache,
    is_fresh,
    load_cache,
    parse_issues,
    save_cache,
)


@pytest.fixture
def isolated_cache(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path))
    return tmp_path


def test_parse_issues_from_fenced_block():
    text = """Here are the issues:
```json
[{"id": "WIZ-1", "title": "Exposed key", "severity": "high", "type": "secret",
  "resource": "repo"}]
```
done"""
    issues = parse_issues(text)
    assert len(issues) == 1
    assert issues[0].id == "WIZ-1"
    assert issues[0].severity == "HIGH"
    assert issues[0].subject["title"] == "Exposed key"


def test_parse_issues_from_bare_array():
    text = '[{"id": "WIZ-2"}, {"name": "WIZ-3"}]'
    issues = parse_issues(text)
    assert [i.id for i in issues] == ["WIZ-2", "WIZ-3"]


def test_parse_issues_skips_entries_without_id():
    text = '[{"title": "no id"}, {"id": "WIZ-9"}]'
    assert [i.id for i in parse_issues(text)] == ["WIZ-9"]


def test_parse_issues_handles_garbage():
    assert parse_issues("no json here") == []
    assert parse_issues("[not valid json}") == []


def test_cache_round_trip(isolated_cache):
    assert load_cache() is None
    issues = [CachedIssue(id="WIZ-1", severity="HIGH")]
    save_cache(build_cache(Settings(), issues))
    loaded = load_cache()
    assert loaded is not None
    assert loaded.issues[0].id == "WIZ-1"


def test_is_fresh_true_within_ttl_and_matching_settings():
    settings = Settings(issue_count=5, min_severity="HIGH")
    cached = build_cache(settings, [])
    assert is_fresh(cached, settings) is True


def test_is_fresh_false_on_settings_change():
    cached = build_cache(Settings(issue_count=5, min_severity="HIGH"), [])
    assert is_fresh(cached, Settings(issue_count=3, min_severity="HIGH")) is False


def test_is_fresh_false_when_stale():
    cached = build_cache(Settings(), [])
    old = (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat()
    cached.fetched_at = old
    assert is_fresh(cached, Settings(), ttl_seconds=3600) is False


def test_is_fresh_none_cache():
    assert is_fresh(None, Settings()) is False


def test_is_fresh_naive_timestamp_treated_as_stale():
    # A hand-edited timestamp without tz offset must not crash is_fresh.
    cached = build_cache(Settings(), [])
    cached.fetched_at = "2026-06-20T10:00:00"  # naive, no offset
    assert is_fresh(cached, Settings()) is False
