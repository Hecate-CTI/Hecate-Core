"""GeoIP location and ASN via IPinfo."""

from __future__ import annotations

import ipaddress
import logging
import time
from typing import Any, Dict, Set

from hecate_agent.enrichment.result import report


logger = logging.getLogger(__name__)


def _setting(name: str, default: str = "") -> str:
    from hecate_agent.orchestrator import enrichment

    return enrichment._setting(name, default)


def refang(value: str) -> str:
    from hecate_agent.orchestrator import enrichment

    return enrichment.refang(value)


def _get_apex_domain(domain: str) -> str:
    from hecate_agent.orchestrator import enrichment

    return enrichment._get_apex_domain(domain)


def _get_known_publishers() -> Set[str]:
    from hecate_agent.orchestrator import enrichment

    return getattr(enrichment, "_KNOWN_PUBLISHER_DOMAINS", set())


def query_geoip_ip(ip: str) -> str:
    """GeoIP location and ASN for an IP."""
    from hecate_agent.enrichment.providers.anonymity import (
        _IPINFO_CACHE,
        extract_ipinfo_context,
    )

    clean_ip = refang(ip).strip()
    if not clean_ip:
        return report("Invalid IP address.", "skipped")

    try:
        addr = ipaddress.ip_address(clean_ip)
        if (
            addr.is_private
            or addr.is_loopback
            or addr.is_link_local
            or addr.is_multicast
            or addr.is_reserved
            or addr.is_unspecified
        ):
            return report("Private/internal IP address.", "skipped")
    except ValueError:
        return report(f"Invalid IP address: {clean_ip}", "skipped")

    data: Dict[str, Any] = extract_ipinfo_context(clean_ip)
    if not data.get("configured", True):
        return report(str(data.get("error") or "GeoIP error."))
    if data.get("error"):
        return report(str(data["error"]))
    if data.get("bogon") or not data.get("found", True):
        return report(str(data.get("message") or "No GeoIP record found."), "missing")

    city = data.get("city") or ""
    region = data.get("region") or ""
    country = data.get("country") or ""
    loc = data.get("loc") or ""
    timezone = data.get("timezone") or ""
    org = data.get("org") or ""
    hostname = data.get("hostname") or ""
    anycast = bool(data.get("anycast"))

    parts = []
    loc_parts = [p for p in (city, region, country) if p]
    if loc_parts:
        parts.append(f"Loc: {', '.join(loc_parts)}")
    elif country:
        parts.append(f"Country: {country}")
    if loc:
        parts.append(f"Coords: {loc}")
    if timezone:
        parts.append(f"TZ: {timezone}")
    if org:
        parts.append(f"ASN/Org: {org}")
    if hostname and not str(hostname).endswith(".in-addr.arpa"):
        parts.append(f"Host: {hostname}")
    if anycast:
        parts.append("Anycast")

    if not parts:
        return report("No GeoIP attributes returned.", "missing")

    summary = " | ".join(parts)
    now = time.time()
    cached = _IPINFO_CACHE.get(clean_ip)
    anon_summary = cached[1] if cached else ""
    _IPINFO_CACHE[clean_ip] = (now, anon_summary, data)
    return report(summary)
