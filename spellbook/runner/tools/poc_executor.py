"""Injectable execution primitives for the M2 PoC catalog.

A proof-of-concept needs to actually *touch* the target — send an HTTP request or
a raw TCP payload — but that live coupling is hidden behind a :class:`PocExecutor`
Protocol so the catalog PoCs are unit-tested against a fake (no network). Same
injection discipline as :mod:`~spellbook.runner.tools.gcp_backend`.

The primitives are deliberately narrow (a bounded HTTP call, a bounded TCP
send/recv): a catalog PoC composes these to *prove* exploitability, never to run
an arbitrary agent-supplied command. The one live-verify site is marked
``# VERIFY (live)``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol


@dataclass(frozen=True)
class HttpResult:
    status: int
    headers: dict[str, str] = field(default_factory=dict)
    body: str = ""
    error: str | None = None


class PocExecutor(Protocol):
    """The bounded side-effecting primitives a catalog PoC may use."""

    def http(self, method: str, url: str, *, headers: dict | None = None,
             timeout: float = 5.0) -> HttpResult: ...

    def tcp_send(self, host: str, port: int, payload: bytes, *,
                 read_bytes: int = 256, timeout: float = 3.0) -> bytes: ...


class LiveExecutor:
    """Real executor: ``httpx`` for HTTP, a raw socket for TCP. Never used in tests."""

    def http(self, method: str, url: str, *, headers: dict | None = None,
             timeout: float = 5.0) -> HttpResult:
        import httpx

        try:
            resp = httpx.request(method, url, headers=headers, timeout=timeout,
                                 follow_redirects=False)
        except httpx.HTTPError as exc:
            return HttpResult(status=0, error=str(exc))
        # VERIFY (live): confirm header casing/body truncation is acceptable downstream.
        return HttpResult(status=resp.status_code, headers=dict(resp.headers),
                          body=resp.text[:2048])

    def tcp_send(self, host: str, port: int, payload: bytes, *,
                 read_bytes: int = 256, timeout: float = 3.0) -> bytes:
        import socket

        with socket.create_connection((host, port), timeout=timeout) as conn:
            conn.sendall(payload)
            return conn.recv(read_bytes)


_executor: PocExecutor | None = None


def set_executor(executor: PocExecutor | None) -> None:
    """Inject the executor (tests pass a fake; ``None`` resets to the live default)."""
    global _executor
    _executor = executor


def get_executor() -> PocExecutor:
    global _executor
    if _executor is None:
        _executor = LiveExecutor()
    return _executor
