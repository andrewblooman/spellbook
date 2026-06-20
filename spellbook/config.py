"""User preferences for the Spellbook launcher.

Unlike Wiz credentials (which are environment-only and never persisted), these
are non-secret UI preferences — how many top issues to pull and at what minimum
severity, and whether to auto-fetch them on startup. Stored as JSON under the
XDG config dir so they survive across runs and repos.
"""

from __future__ import annotations

import os
from pathlib import Path

from pydantic import BaseModel, Field, field_validator

# Ordered most→least severe. Index gives the threshold for "at least this severe".
SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM"]


class Settings(BaseModel):
    issue_count: int = Field(default=5, ge=1, le=10)
    min_severity: str = "HIGH"
    auto_fetch: bool = True

    @field_validator("min_severity")
    @classmethod
    def _known_severity(cls, value: str) -> str:
        upper = value.upper()
        if upper not in SEVERITIES:
            raise ValueError(f"min_severity must be one of {SEVERITIES}")
        return upper

    def severities_at_or_above(self) -> list[str]:
        """The severity levels included by this threshold (most→least severe)."""
        return SEVERITIES[: SEVERITIES.index(self.min_severity) + 1]


def xdg_base(env_var: str, fallback: Path) -> Path:
    """Resolve an XDG base dir, ignoring relative values per the XDG spec.

    The spec requires absolute paths and says relative ones must be ignored;
    enforcing that also keeps a stray ``../`` in the env var from escaping the
    intended location.
    """
    value = os.environ.get(env_var)
    if value and os.path.isabs(value):
        # resolve() normalises away any ".." segments, so a crafted value can't
        # traverse outside the directory it names.
        return Path(value).resolve()
    return fallback


def _config_home() -> Path:
    return xdg_base("XDG_CONFIG_HOME", Path.home() / ".config") / "spellbook"


def settings_path() -> Path:
    return _config_home() / "settings.json"


def load_settings() -> Settings:
    """Load settings, falling back to defaults if missing or unreadable."""
    path = settings_path()
    if not path.exists():
        return Settings()
    try:
        return Settings.model_validate_json(path.read_text())
    except (ValueError, OSError):
        # Corrupt or unreadable config should never block the launcher.
        return Settings()


def save_settings(settings: Settings) -> None:
    path = settings_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(settings.model_dump_json(indent=2))
