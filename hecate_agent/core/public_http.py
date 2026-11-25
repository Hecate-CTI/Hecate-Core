"""Bounded public HTTP downloads with DNS addresses pinned at connection time."""

from __future__ import annotations

import ipaddress
import socket
import time
from typing import Mapping
from urllib.parse import urljoin, urlsplit

import httpx

MAX_DOWNLOAD_BYTES = 2 * 1024 * 1024
MAX_REDIRECTS = 5
# Translation prefixes can encode a private IPv4 destination in a global IPv6 address.
TRANSLATION_PREFIXES = (ipaddress.ip_network("64:ff9b::/96"), ipaddress.ip_network("64:ff9b:1::/48"))

DISALLOWED_EXTENSIONS = {
    ".bin",
    ".exe",
    ".dll",
    ".sys",
    ".ps1",
    ".sh",
    ".bat",
    ".cmd",
    ".vbs",
    ".js",
    ".elf",
    ".so",
    ".zip",
    ".tar",
    ".gz",
    ".7z",
    ".rar",
    ".iso",
    ".img",
    ".dmg",
    ".pkg",
    ".deb",
    ".rpm",
    ".apk",
    ".dat",
    ".payload",
    ".scr",
    ".msi",
    ".hta",
    ".vbe",
    ".wsf",
    ".jar",
    ".class",
}

DISALLOWED_PATHS = {
    "/gate.php",
    "/c2",
    "/beacon",
}

SKIP_HOSTS = {"localhost", "127.0.0.1", "::1"}


def validate_public_url(url: str) -> None:
    """Validate that ``url`` is syntactically a safe public report URL, or raise ValueError."""
    if not url or not isinstance(url, str):
        raise ValueError("Public download URL cannot be empty")
    cleaned = url.strip()
    if len(cleaned) > 8192:
        raise ValueError("Public download URL exceeds maximum length (8192)")
    try:
        parsed = urlsplit(cleaned)
        target = httpx.URL(cleaned)
    except Exception as exc:
        raise ValueError("Invalid public download URL") from exc

    if (
        parsed.username is not None
        or parsed.password is not None
        or target.scheme not in {"http", "https"}
        or not target.host
        or target.port not in {None, 80 if target.scheme == "http" else 443}
        or "%" in target.host
    ):
        raise ValueError("Unsafe public download URL")

    host = target.host.lower()
    if host in SKIP_HOSTS or host.endswith((".local", ".internal", ".onion")):
        raise ValueError(f"Public download cannot target local or internal host: {host}")

    try:
        ipaddress.ip_address(host)
        raise ValueError("Public download cannot target raw IP addresses")
    except ValueError as err:
        if "Public download" in str(err):
            raise

    if "." not in host:
        raise ValueError(f"Public download requires a domain with at least one dot: {host}")

    path = (parsed.path or "").lower()
    for ext in DISALLOWED_EXTENSIONS:
        if path.endswith(ext):
            raise ValueError(f"Public download refuses payload extension {ext}")
    for bad_path in DISALLOWED_PATHS:
        if bad_path in path or path.endswith(bad_path):
            raise ValueError(f"Public download refuses payload path {bad_path}")


def is_safe_public_url(url: str) -> bool:
    """True if ``url`` appears syntactically safe for public CTI report fetching."""
    try:
        validate_public_url(url)
        return True
    except (ValueError, TypeError):
        return False


def public_addresses(url: str) -> tuple[httpx.URL, list[str]]:
    """Resolve once; reject credentials, non-web ports, payload targets, and every non-public answer."""
    validate_public_url(url)
    target = httpx.URL(url.strip())
    try:
        host = target.raw_host.decode("ascii")
        answers = socket.getaddrinfo(
            host,
            target.port or (443 if target.scheme == "https" else 80),
            type=socket.SOCK_STREAM,
            proto=socket.IPPROTO_TCP,
        )
        addresses = []
        for family, _kind, _proto, _canon, address in answers:
            if family not in {socket.AF_INET, socket.AF_INET6}:
                raise ValueError("Unsupported public address family")
            ip = ipaddress.ip_address(address[0])
            mapped = getattr(ip, "ipv4_mapped", None)
            if (
                not ip.is_global
                or ip.is_multicast
                or ip.is_reserved
                or ip.is_loopback
                or ip.is_private
                or ip.is_link_local
                or (mapped is not None and not mapped.is_global)
                or getattr(ip, "sixtofour", None) is not None
                or getattr(ip, "teredo", None) is not None
                or any(ip in network for network in TRANSLATION_PREFIXES)
            ):
                raise ValueError("Public download resolved to a non-public address")
            if str(ip) not in addresses:
                addresses.append(str(ip))
        if not addresses:
            raise ValueError("Public download has no usable addresses")
        # Prefer IPv4 on hosts without an IPv6 route; all answers were checked.
        addresses.sort(key=lambda value: ipaddress.ip_address(value).version)
        return target, addresses
    except (socket.gaierror, UnicodeError) as exc:
        raise ValueError("Invalid or unresolvable public download URL") from exc


def _get_pinned(
    target: httpx.URL,
    address: str,
    *,
    timeout: float,
    deadline: float,
    headers: Mapping[str, str],
    max_bytes: int,
) -> httpx.Response:
    """Use the checked numeric address for TCP, original hostname for Host/TLS."""
    pinned = target.copy_with(host=address)
    request_headers = httpx.Headers(headers)
    request_headers["Host"] = target.netloc.decode("ascii")
    request_headers["Accept-Encoding"] = "identity"
    with httpx.Client(verify=True, trust_env=False, follow_redirects=False) as client:
        with client.stream(
            "GET",
            pinned,
            headers=request_headers,
            timeout=timeout,
            extensions={"sni_hostname": target.raw_host.decode("ascii")},
        ) as response:
            if response.is_redirect:
                content = b""
            else:
                response.raise_for_status()
                if response.headers.get("content-encoding", "identity").lower() not in {"", "identity"}:
                    raise ValueError("Compressed public responses are not accepted")
                length = response.headers.get("content-length")
                if length is not None and (int(length) < 0 or int(length) > max_bytes):
                    raise ValueError("Public download exceeds its byte limit")
                content_buffer = bytearray()
                for chunk in response.iter_raw():
                    if time.monotonic() >= deadline:
                        raise httpx.TimeoutException("Public download exceeded its deadline")
                    if len(content_buffer) + len(chunk) > max_bytes:
                        raise ValueError("Public download exceeds its byte limit")
                    content_buffer.extend(chunk)
                content = bytes(content_buffer)
            return httpx.Response(
                response.status_code,
                headers=response.headers,
                content=content,
                request=httpx.Request("GET", target),
            )


def public_get(
    url: str,
    *,
    timeout: float = 20.0,
    headers: Mapping[str, str] | None = None,
    max_bytes: int = MAX_DOWNLOAD_BYTES,
) -> httpx.Response:
    """Fetch a public page, bounding bytes and validating/pinning every redirect."""
    if timeout <= 0 or max_bytes < 1:
        raise ValueError("Public download limits must be positive")
    deadline = time.monotonic() + timeout
    current = url
    request_headers = httpx.Headers(headers or {})
    for hop in range(MAX_REDIRECTS + 1):
        target, addresses = public_addresses(current)
        response = None
        for address in addresses:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise httpx.TimeoutException("Public download exceeded its deadline")
            try:
                response = _get_pinned(
                    target,
                    address,
                    timeout=remaining,
                    deadline=deadline,
                    headers=request_headers,
                    max_bytes=max_bytes,
                )
                break
            except httpx.ConnectError:
                if address == addresses[-1]:
                    raise
        assert response is not None
        if not response.is_redirect:
            return response
        if hop == MAX_REDIRECTS:
            raise ValueError("Public download exceeded its redirect limit")
        destination = urljoin(str(target), response.headers["location"])
        next_target = httpx.URL(destination)
        if target.scheme == "https" and next_target.scheme != "https":
            raise ValueError("Public download cannot downgrade HTTPS")
        if (target.scheme, target.host, target.port) != (next_target.scheme, next_target.host, next_target.port):
            for key in ("authorization", "cookie", "proxy-authorization"):
                request_headers.pop(key, None)
        current = destination
    raise ValueError("Public download failed")
