"""Interactive Wiz authentication (OAuth2 client-credentials).

Wiz service-to-service auth is a client-credentials grant: a client id + secret
are exchanged at the token endpoint for a short-lived bearer token. There is no
browser/authorization-code login for service accounts.

We use the token exchange to *validate* credentials the user enters, then place
them in ``os.environ`` for the running process so ``mcp_servers()`` can hand them
to ``mcp-server-wiz``. Credentials and tokens are kept **session-only** — never
written to disk (the case store and config never see them).

A Wiz tenant's service account sits behind one of two identity providers, each
with its own token endpoint + audience:

    Cognito : https://auth.app.wiz.io/oauth/token   audience "wiz-api"
    Auth0   : https://auth.wiz.io/oauth/token       audience "beyond-api"

We don't make the user know which they're on — ``exchange_token`` tries each
endpoint in turn and returns on the first that accepts the credentials. A single
explicit override via ``WIZ_TOKEN_URL`` (+ optional ``WIZ_AUDIENCE``) short-circuits
the auto-detection for tenants on a non-standard host.
"""

from __future__ import annotations

import getpass
import os

import httpx

# (token_url, audience) pairs to try, in order. Covers both Wiz IdPs.
WIZ_ENDPOINTS = [
    ("https://auth.app.wiz.io/oauth/token", "wiz-api"),    # Cognito
    ("https://auth.wiz.io/oauth/token", "beyond-api"),     # Auth0
]


class WizAuthError(Exception):
    """Raised when a Wiz token exchange fails (bad creds, network, etc.)."""


def _endpoints() -> list[tuple[str, str]]:
    """The endpoints to try. An explicit WIZ_TOKEN_URL override wins outright."""
    override = os.environ.get("WIZ_TOKEN_URL")
    if override:
        return [(override, os.environ.get("WIZ_AUDIENCE", WIZ_ENDPOINTS[0][1]))]
    return WIZ_ENDPOINTS


def _post_token(url: str, aud: str, client_id: str, client_secret: str,
                timeout: float) -> tuple[str | None, str]:
    """Try one endpoint. Returns (token, detail); token is None on failure."""
    try:
        response = httpx.post(
            url,
            data={
                "grant_type": "client_credentials",
                "client_id": client_id,
                "client_secret": client_secret,
                "audience": aud,
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=timeout,
        )
    except httpx.HTTPError as exc:
        return None, f"{url}: could not connect ({exc})"

    if response.status_code != 200:
        return None, f"{url}: HTTP {response.status_code}"
    token = response.json().get("access_token")
    if not token:
        return None, f"{url}: no access_token in response"
    return token, url


def exchange_token(client_id: str, client_secret: str, *,
                   timeout: float = 15.0) -> str:
    """Exchange client credentials for a bearer token, trying both Wiz IdPs.

    Raises WizAuthError only if every candidate endpoint rejects the credentials.
    """
    failures: list[str] = []
    for url, aud in _endpoints():
        token, detail = _post_token(url, aud, client_id, client_secret, timeout)
        if token:
            return token
        failures.append(detail)
    raise WizAuthError(
        "Wiz rejected the credentials at every known endpoint. Check the client "
        "id/secret and that the service account is enabled. Tried: "
        + "; ".join(failures)
    )


def ensure_wiz_auth(input_fn=input, output_fn=print, secret_fn=getpass.getpass) -> bool:
    """Make Wiz usable for this session, prompting + validating if needed.

    Returns True when WIZ_CLIENT_ID/SECRET are present and validated. On success
    the (validated) credentials live in os.environ for the process only. The secret
    is read via ``secret_fn`` (getpass — non-echoing) so it never appears on screen.
    """
    client_id = os.environ.get("WIZ_CLIENT_ID")
    client_secret = os.environ.get("WIZ_CLIENT_SECRET")
    from_env = bool(client_id and client_secret)

    if not from_env:
        output_fn(
            "Authenticate to Wiz (OAuth2 client-credentials). "
            "Credentials are used for this session only and never written to disk."
        )
        client_id = _prompt("Wiz client id: ", input_fn)
        client_secret = _prompt("Wiz client secret: ", secret_fn)
        if not (client_id and client_secret):
            output_fn("Authentication cancelled — no credentials entered.")
            return False

    try:
        exchange_token(client_id, client_secret)
    except WizAuthError as exc:
        output_fn(f"Wiz authentication failed: {exc}")
        if from_env:
            # Drop the invalid env creds so the next attempt reprompts instead of
            # silently re-validating the same bad values (wiz_configured() would
            # otherwise keep reporting true).
            os.environ.pop("WIZ_CLIENT_ID", None)
            os.environ.pop("WIZ_CLIENT_SECRET", None)
        return False

    # Validated: expose to the session so mcp_servers() picks them up.
    os.environ["WIZ_CLIENT_ID"] = client_id
    os.environ["WIZ_CLIENT_SECRET"] = client_secret
    output_fn("Authenticated to Wiz.")
    return True


def _prompt(message: str, input_fn) -> str | None:
    try:
        value = input_fn(message)
    except (EOFError, KeyboardInterrupt):
        return None
    return value.strip() if value else None
