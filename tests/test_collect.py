import shutil
import subprocess
from pathlib import Path

import pytest

from spellbook import collect
from spellbook.collect import CheckError, run_gitleaks


def test_run_gitleaks_missing_binary(monkeypatch, tmp_path):
    monkeypatch.setattr(collect.shutil, "which", lambda _: None)
    with pytest.raises(CheckError, match="not installed"):
        run_gitleaks(tmp_path)


def test_run_gitleaks_missing_source(monkeypatch):
    monkeypatch.setattr(collect.shutil, "which", lambda _: "/usr/bin/gitleaks")
    with pytest.raises(CheckError, match="does not exist"):
        run_gitleaks(Path("/no/such/path/xyz"))


def test_run_gitleaks_captures_output(monkeypatch, tmp_path):
    monkeypatch.setattr(collect.shutil, "which", lambda _: "/usr/bin/gitleaks")

    class _Proc:
        stdout = "leaks found: 0\n"
        stderr = ""

    monkeypatch.setattr(collect.subprocess, "run", lambda *a, **k: _Proc())
    command, output = run_gitleaks(tmp_path)
    assert command.startswith("gitleaks detect --source")
    assert "--redact" in command
    assert "leaks found: 0" in output


def test_run_gitleaks_timeout(monkeypatch, tmp_path):
    monkeypatch.setattr(collect.shutil, "which", lambda _: "/usr/bin/gitleaks")

    def boom(*a, **k):
        raise subprocess.TimeoutExpired(cmd="gitleaks", timeout=1)

    monkeypatch.setattr(collect.subprocess, "run", boom)
    with pytest.raises(CheckError, match="timed out"):
        run_gitleaks(tmp_path)
