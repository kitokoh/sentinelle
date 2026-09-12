"""THE GUARDRAIL.

Decides whether a target is inside the authorized lab scope.

Allowed by default (scope_status == "allowed"):
  * IP addresses that are RFC1918 (10/8, 172.16/12, 192.168/16), loopback
    (127/8, ::1) or link-local (169.254/16, fe80::/10), plus IPv6 ULA (fc00::/7).
  * CIDR networks FULLY contained within one of those ranges.
  * Hostnames ending in .lab / .local / .test / .internal / .example.

Anything public is "denied" UNLESS a non-empty `authorization_reference`
string is provided (e.g. a signed engagement letter ID). In that case the
target is "allowed" and the reference is stored on the Target row for audit.

This module NEVER performs DNS resolution — hostnames are validated purely
by suffix, so an attacker cannot smuggle a public IP through a DNS lookup.
"""

import ipaddress
from typing import Optional

ALLOWED_HOSTNAME_SUFFIXES = (".lab", ".local", ".test", ".internal", ".example")

_ALLOWED_NETWORKS = (
    # RFC1918
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    # Loopback
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
    # Link-local
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("fe80::/10"),
    # IPv6 unique-local (private addressing)
    ipaddress.ip_network("fc00::/7"),
)


def _has_authorization(authorization_reference: Optional[str]) -> bool:
    """An authorization reference counts only if it is a non-empty string."""
    return isinstance(authorization_reference, str) and bool(authorization_reference.strip())


def _ip_is_internal(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    # `in` safely returns False on address-family mismatch.
    return any(address in network for network in _ALLOWED_NETWORKS)


def _network_is_internal(network: ipaddress.IPv4Network | ipaddress.IPv6Network) -> bool:
    # subnet_of raises TypeError on version mismatch — guard explicitly.
    return any(
        network.version == allowed.version and network.subnet_of(allowed)
        for allowed in _ALLOWED_NETWORKS
    )


def validate_target(value: str, kind: str, authorization_reference: Optional[str] = None) -> str:
    """Return the scope_status ("allowed" | "denied") for a target.

    Raises ValueError when the value is malformed for the given kind.
    Never performs DNS resolution.
    """
    internal = False

    if kind == "ip":
        try:
            address = ipaddress.ip_address(value.strip())
        except ValueError as exc:
            raise ValueError(f"Invalid IP address: {value!r}") from exc
        internal = _ip_is_internal(address)

    elif kind == "cidr":
        try:
            network = ipaddress.ip_network(value.strip(), strict=False)
        except ValueError as exc:
            raise ValueError(f"Invalid CIDR network: {value!r}") from exc
        internal = _network_is_internal(network)

    elif kind == "hostname":
        hostname = value.strip().lower().rstrip(".")
        if not hostname:
            raise ValueError("Hostname must not be empty")
        internal = hostname.endswith(ALLOWED_HOSTNAME_SUFFIXES)

    else:
        raise ValueError(f"Unknown target kind: {kind!r} (expected ip | hostname | cidr)")

    if internal:
        return "allowed"
    if _has_authorization(authorization_reference):
        # Public target covered by a documented authorization — allowed and audited.
        return "allowed"
    return "denied"
