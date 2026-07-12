"""Owned-asset scope checks for validation *targets*.

The legacy :mod:`spellbook.safety.scope` answers "does this shell *command* touch
only owned hosts?". The exploitability platform needs a slightly different
question: "is this *target* (a host, an IP, or a CIDR that a runner tool is about
to hit) inside our owned-asset allowlist?".

Targets come in three shapes, all handled here:

- **hostnames** — matched by exact or subdomain suffix (reusing
  :func:`spellbook.safety.scope.host_allowed`, the single source of truth);
- **IP addresses** — in scope if contained in any allowlisted CIDR (or an exact
  IP entry);
- **CIDRs** — in scope if they are a subnet of an allowlisted CIDR.

Default-deny: a target that matches nothing is out of scope. The allowlist is the
union of the caller-supplied set (derived from the Wiz-owned asset inventory) and
``SPELLBOOK_SCOPE`` from the environment.
"""

from __future__ import annotations

import ipaddress

from spellbook.safety.scope import host_allowed, scope_from_env

_IpOrNet = ipaddress.IPv4Address | ipaddress.IPv6Address | ipaddress.IPv4Network | ipaddress.IPv6Network


def _as_ip(token: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(token)
    except ValueError:
        return None


def _as_net(token: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network | None:
    try:
        return ipaddress.ip_network(token, strict=False)
    except ValueError:
        return None


def target_in_scope(target: str, allowlist: set[str]) -> bool:
    """True if ``target`` is covered by the owned-asset ``allowlist``.

    ``allowlist`` entries may be hostnames/domains, IPs, or CIDRs. The check is
    default-deny.
    """
    allow = {a.strip().lower() for a in (set(allowlist) | scope_from_env()) if a.strip()}
    if not allow:
        return False
    t = target.strip().lower()
    if not t:
        return False

    # Exact match against any allowlist entry (host, ip, or cidr string).
    if t in allow:
        return True

    ip = _as_ip(t)
    if ip is not None:
        return any((net := _as_net(a)) is not None and ip in net for a in allow)

    net_t = _as_net(t)
    if net_t is not None:  # target is a CIDR: must be a subnet of an allowed CIDR
        return any(
            (net_a := _as_net(a)) is not None
            and net_t.version == net_a.version
            and net_t.subnet_of(net_a)
            for a in allow
        )

    # Otherwise treat the target as a hostname.
    return host_allowed(t, allow)
