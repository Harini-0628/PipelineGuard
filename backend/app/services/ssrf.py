"""Outbound URL validation to prevent SSRF through user-configured webhooks."""
from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlsplit

from app.config import get_settings


class UnsafeURL(ValueError):
    pass


def _check_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> None:
    if (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved or ip.is_unspecified
            or (isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None and not ip.ipv4_mapped.is_global)):
        raise UnsafeURL(f"address {ip} is not a public address")


def validate_outbound_url(url: str, *, resolve: bool = True) -> str:
    """Require https, no credentials, standard ports, and only public destination addresses.
    Limitation: DNS can change between validation and connection (rebinding). Delivery re-validates right before
    sending and never follows redirects, but it does NOT pin the resolved IP; for stricter guarantees send webhooks
    through an egress proxy that enforces the same deny-list."""
    parts = urlsplit(url)
    allow_private = get_settings().allow_private_webhook_targets
    if parts.scheme != "https" and not (allow_private and parts.scheme == "http"):
        raise UnsafeURL("webhook URLs must use https")
    if not parts.hostname:
        raise UnsafeURL("URL has no host")
    if parts.username or parts.password:
        raise UnsafeURL("credentials in URLs are not allowed")
    if parts.port not in (None, 443) and not allow_private:
        raise UnsafeURL("only the default https port is allowed")
    if allow_private:
        return url
    host = parts.hostname
    try:
        _check_ip(ipaddress.ip_address(host))
        return url
    except ValueError as e:
        if isinstance(e, UnsafeURL):
            raise
    if host.lower() in {"localhost"} or host.lower().endswith((".local", ".internal", ".localhost")):
        raise UnsafeURL("internal hostnames are not allowed")
    if resolve:
        try:
            infos = socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP)
        except socket.gaierror as e:
            raise UnsafeURL(f"host does not resolve: {e}") from e
        for info in infos:
            _check_ip(ipaddress.ip_address(info[4][0]))
    return url
