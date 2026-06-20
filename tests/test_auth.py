import httpx
import pytest

from spellbook.wiz import auth
from spellbook.wiz.auth import WizAuthError, ensure_wiz_auth, exchange_token


class _FakeResponse:
    def __init__(self, status_code, payload):
        self.status_code = status_code
        self._payload = payload

    def json(self):
        return self._payload


def test_exchange_token_success(monkeypatch):
    captured = {}

    def fake_post(url, data, headers, timeout):
        captured["url"] = url
        captured["data"] = data
        return _FakeResponse(200, {"access_token": "tok-123"})

    monkeypatch.setattr(auth.httpx, "post", fake_post)
    monkeypatch.delenv("WIZ_TOKEN_URL", raising=False)
    token = exchange_token("cid", "secret")
    assert token == "tok-123"
    assert captured["data"]["grant_type"] == "client_credentials"
    assert captured["data"]["client_id"] == "cid"


def test_exchange_token_falls_back_to_second_endpoint(monkeypatch):
    monkeypatch.delenv("WIZ_TOKEN_URL", raising=False)
    seen = []

    def fake_post(url, data, headers, timeout):
        seen.append(url)
        # Reject the first (Cognito) endpoint, accept the second (Auth0).
        if url == auth.WIZ_ENDPOINTS[0][0]:
            return _FakeResponse(401, {})
        return _FakeResponse(200, {"access_token": "tok-auth0"})

    monkeypatch.setattr(auth.httpx, "post", fake_post)
    token = exchange_token("cid", "secret")
    assert token == "tok-auth0"
    assert seen == [auth.WIZ_ENDPOINTS[0][0], auth.WIZ_ENDPOINTS[1][0]]


def test_exchange_token_respects_explicit_override(monkeypatch):
    monkeypatch.setenv("WIZ_TOKEN_URL", "https://custom.example/oauth/token")
    seen = []

    def fake_post(url, data, headers, timeout):
        seen.append(url)
        return _FakeResponse(200, {"access_token": "tok"})

    monkeypatch.setattr(auth.httpx, "post", fake_post)
    assert exchange_token("cid", "secret") == "tok"
    assert seen == ["https://custom.example/oauth/token"]


def test_exchange_token_rejected(monkeypatch):
    monkeypatch.setattr(auth.httpx, "post",
                        lambda *a, **kw: _FakeResponse(401, {}))
    with pytest.raises(WizAuthError):
        exchange_token("cid", "bad")


def test_exchange_token_network_error(monkeypatch):
    def boom(*a, **kw):
        raise httpx.ConnectError("no route")

    monkeypatch.setattr(auth.httpx, "post", boom)
    with pytest.raises(WizAuthError):
        exchange_token("cid", "secret")


def test_ensure_wiz_auth_prompts_and_sets_env(monkeypatch):
    monkeypatch.delenv("WIZ_CLIENT_ID", raising=False)
    monkeypatch.delenv("WIZ_CLIENT_SECRET", raising=False)
    monkeypatch.setattr(auth, "exchange_token", lambda cid, secret: "tok")

    ok = ensure_wiz_auth(
        input_fn=lambda _: "my-id",
        secret_fn=lambda _: "my-secret",
        output_fn=lambda _: None,
    )

    assert ok is True
    assert auth.os.environ["WIZ_CLIENT_ID"] == "my-id"
    assert auth.os.environ["WIZ_CLIENT_SECRET"] == "my-secret"


def test_ensure_wiz_auth_failure_does_not_set_env(monkeypatch):
    monkeypatch.delenv("WIZ_CLIENT_ID", raising=False)
    monkeypatch.delenv("WIZ_CLIENT_SECRET", raising=False)

    def fail(cid, secret):
        raise WizAuthError("nope")

    monkeypatch.setattr(auth, "exchange_token", fail)
    ok = ensure_wiz_auth(
        input_fn=lambda _: "my-id",
        secret_fn=lambda _: "my-secret",
        output_fn=lambda _: None,
    )

    assert ok is False
    assert "WIZ_CLIENT_ID" not in auth.os.environ


def test_ensure_wiz_auth_clears_invalid_env_creds(monkeypatch):
    monkeypatch.setenv("WIZ_CLIENT_ID", "stale-id")
    monkeypatch.setenv("WIZ_CLIENT_SECRET", "stale-secret")

    def fail(cid, secret):
        raise WizAuthError("nope")

    monkeypatch.setattr(auth, "exchange_token", fail)
    ok = ensure_wiz_auth(input_fn=lambda _: None, secret_fn=lambda _: None,
                         output_fn=lambda _: None)

    assert ok is False
    # Invalid env creds are dropped so a later attempt can reprompt.
    assert "WIZ_CLIENT_ID" not in auth.os.environ
    assert "WIZ_CLIENT_SECRET" not in auth.os.environ


def test_ensure_wiz_auth_validates_existing_env(monkeypatch):
    monkeypatch.setenv("WIZ_CLIENT_ID", "env-id")
    monkeypatch.setenv("WIZ_CLIENT_SECRET", "env-secret")
    seen = {}
    monkeypatch.setattr(auth, "exchange_token",
                        lambda cid, secret: seen.update(cid=cid) or "tok")

    ok = ensure_wiz_auth(input_fn=lambda _: None, output_fn=lambda _: None)
    assert ok is True
    assert seen["cid"] == "env-id"
