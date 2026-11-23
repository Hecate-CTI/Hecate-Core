"""RDAP domain and IP registration lookups."""

from __future__ import annotations

from hecate_agent.enrichment.result import report

import ipaddress
import logging
import re
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Set, cast

import httpx


logger = logging.getLogger(__name__)


def _setting(name: str, default: str = "") -> str:
    from hecate_agent.orchestrator import enrichment

    return enrichment._setting(name, default)


def _misp_verify_tls() -> bool:
    from hecate_agent.orchestrator import enrichment

    return enrichment._misp_verify_tls()


def refang(value: str) -> str:
    from hecate_agent.orchestrator import enrichment

    return enrichment.refang(value)


def _get_apex_domain(domain: str) -> str:
    from hecate_agent.orchestrator import enrichment

    return enrichment._get_apex_domain(domain)


def _get_known_publishers() -> Set[str]:
    from hecate_agent.orchestrator import enrichment

    return getattr(enrichment, "_KNOWN_PUBLISHER_DOMAINS", set())


def _format_rdap_date(date_str: str) -> str:
    """Format an RDAP date and age (marks recent/NRD)."""
    if not date_str:
        return "Unknown"
    try:
        clean = re.sub(r"Z$", "+00:00", str(date_str).strip())
        dt = datetime.fromisoformat(clean)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        now = datetime.now(timezone.utc)
        days = (now - dt).days
        iso_day = date_str[:10]
        if days < 0:
            return iso_day
        if days < 60:
            return f"{iso_day} ({days} days old - RECENT/NRD)"
        elif days < 365:
            months = max(1, days // 30)
            return f"{iso_day} ({months} months old)"
        else:
            years = max(1, days // 365)
            return f"{iso_day} ({years} years old)"
    except Exception:
        return date_str[:10] if len(date_str) >= 10 else date_str


def _vcard_prop(entity: Dict[str, Any], name: str) -> str:
    vcard = entity.get("vcardArray")
    if vcard and len(vcard) > 1 and isinstance(vcard[1], list):
        for prop in vcard[1]:
            if isinstance(prop, list) and len(prop) > 3 and prop[0] == name:
                return str(prop[3]).strip()
    return ""


def _vcard_fn(entity: Dict[str, Any]) -> str:
    return _vcard_prop(entity, "fn")


def _vcard_kind(entity: Dict[str, Any]) -> str:
    return _vcard_prop(entity, "kind").lower()


def _entity_display_name(entity: Dict[str, Any]) -> str:
    return _vcard_fn(entity) or str(entity.get("handle") or "").strip()


def _registrant_org_name(entities: Optional[Iterable[Dict[str, Any]]]) -> str:
    """Prefer org-kind registrant over mntner/person when several are listed."""
    candidates: List[tuple[int, str]] = []
    for ent in _walk_entities(entities):
        roles = {str(r).lower() for r in (ent.get("roles") or [])}
        if "registrant" not in roles:
            continue
        display = _entity_display_name(ent)
        if not display:
            continue
        kind = _vcard_kind(ent)
        handle = str(ent.get("handle") or "")
        if kind == "org":
            rank = 0
        elif handle.upper().endswith("-MNT") or display.upper().endswith("-MNT"):
            rank = 2
        elif kind in ("individual", "person", "group"):
            rank = 1
        else:
            rank = 1
        candidates.append((rank, display))
    if not candidates:
        return ""
    candidates.sort(key=lambda item: item[0])
    return candidates[0][1]


def _walk_entities(entities: Optional[Iterable[Dict[str, Any]]]) -> Iterable[Dict[str, Any]]:
    for ent in entities or []:
        yield ent
        nested = ent.get("entities")
        if nested:
            yield from _walk_entities(cast(Iterable[Dict[str, Any]], nested))


def _registration_event_date(data: Dict[str, Any]) -> str:
    for ev in data.get("events") or []:
        if ev.get("eventAction") in ("registration", "created"):
            return str(ev.get("eventDate") or "")
    return ""


def _format_cidrs(data: Dict[str, Any]) -> List[str]:
    cidrs: List[str] = []
    for entry in data.get("cidr0_cidrs") or []:
        length = entry.get("length")
        if entry.get("v4prefix") and length is not None:
            cidrs.append(f"{entry['v4prefix']}/{length}")
        elif entry.get("v6prefix") and length is not None:
            cidrs.append(f"{entry['v6prefix']}/{length}")
    return cidrs


def query_rdap_domain(domain: str) -> str:
    """RDAP registration age and registrar for a domain."""
    target_domain = _get_apex_domain(domain)
    url = f"https://rdap.org/domain/{target_domain}"
    headers = {"Accept": "application/rdap+json, application/json"}
    try:
        resp = httpx.get(url, headers=headers, follow_redirects=True, timeout=10.0)
        if resp.status_code == 200:
            data = cast(Dict[str, Any], resp.json())
            reg_date_raw = _registration_event_date(data)

            registrar = ""
            for ent in data.get("entities", []):
                roles = ent.get("roles", [])
                if "registrar" in roles:
                    registrar = _entity_display_name(ent)
                    if registrar:
                        break

            parts = []
            if reg_date_raw:
                age_formatted = _format_rdap_date(reg_date_raw)
                parts.append(f"Registered: {age_formatted}")
            if registrar:
                parts.append(f"Registrar: {registrar}")

            if parts:
                return report(" | ".join(parts))
            return report("Domain active (no creation date recorded in RDAP).", "found")
        elif resp.status_code == 404:
            return report("Domain not found on RDAP.", "missing")
        return report(f"RDAP error: HTTP {resp.status_code}")
    except Exception as e:
        return report(f"Error querying RDAP: {e}")


def query_rdap_ip(ip: str) -> str:
    """RDAP network registration for an IP."""
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

    url = f"https://rdap.org/ip/{clean_ip}"
    headers = {"Accept": "application/rdap+json, application/json"}
    try:
        resp = httpx.get(url, headers=headers, follow_redirects=True, timeout=10.0)
        if resp.status_code == 200:
            data = cast(Dict[str, Any], resp.json())
            parts: List[str] = []

            name = str(data.get("name") or "").strip()
            handle = str(data.get("handle") or "").strip()
            net_type = str(data.get("type") or "").strip()
            country = str(data.get("country") or "").strip()
            start = str(data.get("startAddress") or "").strip()
            end = str(data.get("endAddress") or "").strip()
            cidrs = _format_cidrs(data)

            if name:
                parts.append(f"Net: {name}")
            if handle and handle != name:
                parts.append(f"Handle: {handle}")
            if cidrs:
                parts.append(f"CIDR: {', '.join(cidrs[:3])}")
            elif start and end:
                parts.append(f"Range: {start} - {end}")
            if net_type:
                parts.append(f"Type: {net_type}")
            if country:
                parts.append(f"Country: {country}")

            registrant = _registrant_org_name(cast(Optional[Iterable[Dict[str, Any]]], data.get("entities")))
            if registrant:
                parts.append(f"Org: {registrant}")

            origin_asns = data.get("arin_originas0_originautnums") or data.get("originAutnums") or []
            if origin_asns:
                asn_list = ", ".join(f"AS{a}" for a in origin_asns[:5])
                parts.append(f"Origin ASN: {asn_list}")

            reg_date_raw = _registration_event_date(data)
            if reg_date_raw:
                parts.append(f"Registered: {_format_rdap_date(reg_date_raw)}")

            if parts:
                return report(" | ".join(parts))
            return report("IP network found on RDAP (no registration details).", "found")
        elif resp.status_code == 404:
            return report("IP not found on RDAP.", "missing")
        return report(f"RDAP error: HTTP {resp.status_code}")
    except Exception as e:
        return report(f"Error querying RDAP: {e}")
