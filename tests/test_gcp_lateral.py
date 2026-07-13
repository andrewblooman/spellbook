"""Tests for the M1 internal lateral-movement tools.

Exercises each ``gcp_lateral`` tool against a fake :class:`GcpBackend` (no live
GCP), and through the shared ``dispatch`` to confirm posture (INTERNAL-only) and
scope enforcement. Verifies the raw access token never leaves the runner.
"""

import socket

import pytest

from spellbook.safety.classify import ACTIVE_NONINVASIVE
from spellbook.control.ingest.model import Posture
from spellbook.runner.audit import AuditSink
from spellbook.runner.dispatch import RunContext, dispatch
from spellbook.runner.tools import gcp_lateral, registry
from spellbook.runner.tools.gcp_backend import GcpIdentity, GcpToken, set_backend


class FakeGcpBackend:
    """A stand-in for the metadata/IAM surface, driven entirely from memory."""

    def __init__(self, *, granted=None, token="super-secret-token"):
        self._granted = granted if granted is not None else ["iam.serviceAccounts.actAs"]
        self._token = token
        self.tested_with: tuple[str, list[str]] | None = None

    def identity(self) -> GcpIdentity:
        return GcpIdentity(
            email="sa@proj.iam.gserviceaccount.com",
            project_id="proj",
            numeric_project_id="12345",
            zone="us-central1-a",
            scopes=("https://www.googleapis.com/auth/cloud-platform",),
        )

    def access_token(self) -> GcpToken:
        return GcpToken(value=self._token, expires_in=3599)

    def test_permissions(self, resource, permissions):
        self.tested_with = (resource, list(permissions))
        return list(self._granted)


@pytest.fixture
def fake_backend():
    backend = FakeGcpBackend()
    set_backend(backend)
    yield backend
    set_backend(None)  # reset to the lazy real default


def _internal_ctx(**kw):
    base = dict(posture=Posture.INTERNAL, scope_allowlist={"10.0.0.0/24"}, audit=AuditSink())
    base.update(kw)
    return RunContext(**base)


# --- registration ---------------------------------------------------------
def test_lateral_tools_registered_internal_only():
    for name in ("metadata_token", "iam_blast_radius", "east_west_reach"):
        tool = registry.get(name)
        assert tool.tier == ACTIVE_NONINVASIVE
        assert tool.postures == frozenset({Posture.INTERNAL})


# --- metadata_token -------------------------------------------------------
def test_metadata_token_returns_identity_and_masks_token(fake_backend):
    out = gcp_lateral.metadata_token("10.0.0.5", {})
    assert out["service_account"] == "sa@proj.iam.gserviceaccount.com"
    assert out["project_id"] == "proj"
    assert out["token_available"] is True
    # The raw token is never returned — only a short fingerprint.
    assert out["token_fingerprint"] and out["token_fingerprint"] != "super-secret-token"
    assert "super-secret-token" not in repr(out)


# --- iam_blast_radius -----------------------------------------------------
def test_iam_blast_radius_reports_granted_and_escalation(fake_backend):
    out = gcp_lateral.iam_blast_radius("10.0.0.5", {})
    assert out["resource"] == "proj"                      # defaulted from identity
    assert out["granted"] == ["iam.serviceAccounts.actAs"]
    assert out["blast_radius"] == 1
    assert out["escalation_possible"] is True             # iam.* granted

def test_iam_blast_radius_no_escalation_when_only_read(fake_backend):
    fake_backend._granted = ["storage.objects.get"]
    out = gcp_lateral.iam_blast_radius("10.0.0.5", {"resource": "other-proj"})
    assert out["resource"] == "other-proj"                # explicit resource honored
    assert out["escalation_possible"] is False


# --- east_west_reach ------------------------------------------------------
def test_east_west_reach_reports_open_ports(monkeypatch):
    opened = []

    def fake_connect(addr, timeout):
        host, port = addr
        if port in (22, 443):
            opened.append(port)
            return _Closable()
        raise OSError("refused")

    monkeypatch.setattr(socket, "create_connection", fake_connect)
    out = gcp_lateral.east_west_reach("10.0.0.5", {"ports": [22, 80, 443]})
    assert out["open_ports"] == [22, 443]
    assert out["scanned"] == [22, 80, 443]


class _Closable:
    def close(self):
        pass


# --- enforcement through dispatch -----------------------------------------
def test_metadata_token_denied_in_external_posture(fake_backend):
    ctx = RunContext(posture=Posture.EXTERNAL, scope_allowlist={"10.0.0.0/24"}, audit=AuditSink())
    res = dispatch(ctx, "metadata_token", "10.0.0.5")
    assert res.allowed is False and "posture_mismatch" in res.reason

def test_lateral_tool_denied_out_of_scope(fake_backend):
    ctx = _internal_ctx()
    res = dispatch(ctx, "iam_blast_radius", "192.168.1.9")   # not in 10.0.0.0/24
    assert res.allowed is False and "out_of_scope" in res.reason
    assert fake_backend.tested_with is None                  # handler never ran

def test_lateral_tool_runs_in_scope_internal(fake_backend):
    ctx = _internal_ctx()
    res = dispatch(ctx, "metadata_token", "10.0.0.5")
    assert res.allowed is True
    assert res.observation["service_account"] == "sa@proj.iam.gserviceaccount.com"
    assert ctx.audit.events[-1].allowed is True
