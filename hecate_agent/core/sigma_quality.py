"""Reject echo/README detections and documentation IOC artifacts before publish.

These checks catch rule shapes that passed structural validation but are not
hunt-worthy: auto-titled command/IOC dumps from source paste, PoC-README
procedure leads, and RFC documentation / example network indicators.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Mapping
from typing import Any, Optional

#: Auto-generated echo titles that paste source commands or PoC README procedures.
#: Generic "named in the source intelligence" IOC sweeps are allowed when they
#: carry real indicators; documentation IOCs are blocked separately below.
_ECHO_TITLE_RE = re.compile(
    r"(?is)^("
    r"Command the source shows being run\b"
    r"|File the source says the malware writes\b"
    r"|File created by command\b"
    r"|Request the PoC README documents\b"
    r"|Hunting lead:\s*"
    r")"
)

#: Filenames produced by the same echo generators (stem or basename).
_ECHO_STEM_RE = re.compile(
    r"(?i)("
    r"command_the_source_shows_being_run_"
    r"|file_the_source_says_the_malware_writes_"
    r"|request_the_poc_readme_documents_"
    r"|hunting_lead_"
    r")"
)

_DOC_OR_BENCHMARK_NETWORKS = (
    ipaddress.ip_network("192.0.2.0/24"),  # TEST-NET-1
    ipaddress.ip_network("198.51.100.0/24"),  # TEST-NET-2
    ipaddress.ip_network("203.0.113.0/24"),  # TEST-NET-3
    ipaddress.ip_network("198.18.0.0/15"),  # benchmarking
)

_PLACEHOLDER_IPS = frozenset(
    {
        "0.0.0.0",
        "1.2.3.4",
        "1.1.1.1",
        "8.8.8.8",
        "8.8.4.4",
        "9.9.9.9",
        "255.255.255.255",
        "127.0.0.1",
    }
)

_PLACEHOLDER_DOMAIN_SUFFIXES = (
    "example.com",
    "example.net",
    "example.org",
    "example.edu",
    "invalid",
    "localhost",
    "test",
    "local",
)

_IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b")
_HOSTISH_RE = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,63})\b", re.I)


def echo_rule_block_reason(*, title: str = "", filename: str = "") -> Optional[str]:
    """Reason to reject a README/command-echo rule, or None if the title is fine."""
    cleaned = str(title or "").strip()
    if cleaned and _ECHO_TITLE_RE.search(cleaned):
        return (
            "Auto-echo detection title is not hunt-worthy "
            "(command/IOC paste from source or PoC README); rewrite as behavioral detection"
        )
    stem = str(filename or "").rsplit("/", 1)[-1]
    if stem.endswith((".yml", ".yaml")):
        stem = stem.rsplit(".", 1)[0]
    if stem and _ECHO_STEM_RE.search(stem):
        return (
            "Auto-echo detection filename is not hunt-worthy "
            "(command_the_source / named_in_the_source / poc_readme); rewrite or drop"
        )
    return None


def is_documentation_network_indicator(value: str) -> bool:
    """True for RFC docnets, resolver/placeholder IPs, and example.* hosts."""
    text = str(value or "").strip().lower().rstrip(".")
    if not text:
        return False
    if text in _PLACEHOLDER_IPS:
        return True
    # Strip brackets / URL wrapping for host extraction.
    host = text
    for prefix in ("http://", "https://"):
        if host.startswith(prefix):
            host = host[len(prefix) :]
    host = host.split("/", 1)[0].split(":", 1)[0].strip("[]")
    try:
        ip = ipaddress.ip_address(host)
        if str(ip) in _PLACEHOLDER_IPS:
            return True
        return any(ip in net for net in _DOC_OR_BENCHMARK_NETWORKS)
    except ValueError:
        pass
    return any(host == suffix or host.endswith("." + suffix) for suffix in _PLACEHOLDER_DOMAIN_SUFFIXES)


def _walk_strings(node: Any) -> list[str]:
    found: list[str] = []
    if isinstance(node, str):
        found.append(node)
    elif isinstance(node, Mapping):
        for key, value in node.items():
            if str(key).lower() in {"condition", "timeframe"}:
                continue
            found.extend(_walk_strings(value))
    elif isinstance(node, (list, tuple, set)):
        for item in node:
            found.extend(_walk_strings(item))
    return found


def documentation_ioc_block_reason(detection: Any) -> Optional[str]:
    """Reject detections whose only concrete network IOCs are documentation placeholders."""
    if not isinstance(detection, Mapping):
        return None
    strings = _walk_strings(detection)
    if not strings:
        return None

    doc_hits: list[str] = []
    other_network = False
    for raw in strings:
        for ip_match in _IPV4_RE.findall(raw):
            if is_documentation_network_indicator(ip_match):
                doc_hits.append(ip_match)
            else:
                other_network = True
        for host_match in _HOSTISH_RE.findall(raw):
            if is_documentation_network_indicator(host_match):
                doc_hits.append(host_match)
            elif "." in host_match:
                other_network = True

    if doc_hits and not other_network:
        sample = ", ".join(sorted(set(doc_hits))[:4])
        return (
            f"Detection uses documentation/example network indicators only ({sample}); "
            "replace with observed campaign artifacts or drop the rule"
        )
    return None


def quality_block_reason(document: Any, *, filename: str = "") -> Optional[str]:
    """Combined quality rejection for a parsed Sigma document."""
    if not isinstance(document, Mapping):
        return None
    title = str(document.get("title") or "")
    echo = echo_rule_block_reason(title=title, filename=filename)
    if echo:
        return echo
    return documentation_ioc_block_reason(document.get("detection"))
