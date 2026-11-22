"""Per-service display metrics derived from configuration and trail events."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from typing import Any, Dict, List, NamedTuple, Optional, Tuple

from hecate_agent.commands.monitor_samplers import TrailEvent
from hecate_agent.integration_registry import BY_LABEL


class IntegrationStatus(NamedTuple):
    label: str
    healthy: bool
    detail: str
    metric: str


@dataclass(frozen=True)
class ServiceMetricsContext:
    file_keys: set[str]
    cycle_events: List[TrailEvent]
    active_enrichment_events: List[TrailEvent]
    search_count: str
    narrow: bool
    events: List[TrailEvent]
    metrics: Optional[Dict[str, Any]]
    live: Optional[Dict[str, Any]]


def _backlog_observation(events: List[TrailEvent]) -> Optional[Tuple[int, str]]:
    for event in reversed(events):
        match = re.search(r"(\d+) high-signal waiting in its backlog", event.message)
        if match:
            return int(match.group(1)), event.timestamp[-8:]
    return None


def _llm_status(label: str, is_set: bool, context: ServiceMetricsContext) -> IntegrationStatus:
    if is_set:
        provider_name = os.environ.get("HECATE_LLM_PROVIDER")
        if not provider_name:
            if any(os.environ.get(k) or k in context.file_keys for k in ("ANTHROPIC_API_KEY",)):
                provider_name = "anthropic"
            elif any(os.environ.get(k) or k in context.file_keys for k in ("OPENAI_API_KEY",)):
                provider_name = "openai"
            elif any(os.environ.get(k) or k in context.file_keys for k in ("GEMINI_API_KEY", "GOOGLE_API_KEY")):
                provider_name = "gemini"
            elif any(os.environ.get(k) or k in context.file_keys for k in ("AWS_PROFILE",)):
                provider_name = "bedrock"
            else:
                provider_name = "ollama"
        else:
            provider_name = provider_name.lower().split()[0]
        detail = str(provider_name)
        calls = 0
        if context.live and context.live.get("llm_calls") is not None:
            calls = int(context.live.get("llm_calls") or 0)
        elif context.metrics:
            llm_stages = [
                s for s in (context.metrics.get("stages") or []) if isinstance(s, dict) and s.get("llm_calls") is not None
            ]
            calls = sum(int(s.get("llm_calls") or 0) for s in llm_stages)
        metric = f"{calls} calls"
        return IntegrationStatus(label, True, detail, metric)
    else:
        return IntegrationStatus(label, False, "unconfigured", "--")


def _tavily_status(label: str, is_set: bool, context: ServiceMetricsContext) -> IntegrationStatus:
    if is_set:
        detail = "web search"
        searches = None
        in_prog = False
        for e in reversed(context.cycle_events):
            m = re.search(r"(\d+)\s+web\s+search(?:es|\(es\))?", e.message)
            if m:
                searches = int(m.group(1))
                break
            if e.stage == "research" and "web search on" in e.message:
                in_prog = True
        if searches is None and not in_prog and context.active_enrichment_events != context.cycle_events:
            for e in reversed(context.active_enrichment_events):
                m = re.search(r"(\d+)\s+web\s+search(?:es|\(es\))?", e.message)
                if m:
                    searches = int(m.group(1))
                    break
        if searches is not None:
            metric = f"{searches} searches"
        elif in_prog:
            metric = "searching..."
        elif context.search_count.isdigit():
            metric = f"{context.search_count} searches"
        elif context.search_count in ("in progress...", "searching..."):
            metric = "searching..."
        else:
            metric = "0 searches"
        return IntegrationStatus(label, True, detail, metric)
    else:
        return IntegrationStatus(label, False, "unconfigured", "--")


def _otx_status(label: str, is_set: bool, context: ServiceMetricsContext) -> IntegrationStatus:
    if is_set:
        detail = "feed/ioc" if context.narrow else "pulses"
        otx_found = any(
            e.stage in ("intake", "route", "research") and ("otx:" in e.message.lower() or "otx pulse:" in e.message.lower())
            for e in context.cycle_events
        )
        if not otx_found and context.active_enrichment_events != context.cycle_events:
            otx_found = any(
                e.stage in ("intake", "route", "research")
                and ("otx:" in e.message.lower() or "otx pulse:" in e.message.lower())
                for e in context.active_enrichment_events
            )
        if otx_found:
            metric = "1 pulse"
        else:
            obs_count = 0
            for e in context.active_enrichment_events:
                if e.stage == "enrichment":
                    m_obs = re.search(r"(\d+)\s+observable\(s\)", e.message, re.IGNORECASE)
                    if m_obs:
                        obs_count = int(m_obs.group(1))
                        break
            if obs_count > 0:
                metric = f"{obs_count} queries"
            else:
                backlog = _backlog_observation(context.events or [])
                if backlog and backlog[0] > 0:
                    metric = f"{backlog[0]} queued"
                else:
                    metric = "0 queries"
        return IntegrationStatus(label, True, detail, metric)
    else:
        return IntegrationStatus(label, False, "unconfigured", "--")


def _misp_status(label: str, is_set: bool, context: ServiceMetricsContext) -> IntegrationStatus:
    if is_set:
        detail = "threat sharing" if context.narrow else "threat share"
        misp_found = any(e.stage == "intake" and "misp:" in e.message.lower() for e in context.cycle_events)
        if not misp_found and context.active_enrichment_events != context.cycle_events:
            misp_found = any(e.stage == "intake" and "misp:" in e.message.lower() for e in context.active_enrichment_events)
        metric = "1 event" if misp_found else "0 events"
        return IntegrationStatus(label, True, detail, metric)
    else:
        return IntegrationStatus(label, False, "unconfigured", "--")


def _vt_status(label: str, is_set: bool, context: ServiceMetricsContext) -> IntegrationStatus:
    if is_set:
        detail = "enrichment"
        ioc_count = 0
        for e in context.active_enrichment_events:
            m_obs = re.search(r"(\d+)\s+observable\(s\)", e.message, re.IGNORECASE)
            if m_obs:
                ioc_count = max(ioc_count, int(m_obs.group(1)))
            m = re.search(r"(\d+)\s+indicator\(s\)", e.message)
            if m:
                ioc_count = max(ioc_count, int(m.group(1)))
            m_typed = re.search(r"(\d+)/\d+\s+indicator\(s\)\s+typed", e.message)
            if m_typed:
                ioc_count = max(ioc_count, int(m_typed.group(1)))
            m_intake = re.search(r"indicators:\s*([^\);]+)", e.message)
            if m_intake and "none" not in m_intake.group(1).lower():
                nums = [int(n) for n in re.findall(r"\b(\d+)\b", m_intake.group(1))]
                if nums:
                    ioc_count = max(ioc_count, sum(nums))
        metric = f"{ioc_count} checked"
        return IntegrationStatus(label, True, detail, metric)
    else:
        return IntegrationStatus(label, False, "unconfigured", "--")


def _greynoise_status(label: str, is_set: bool, context: ServiceMetricsContext) -> IntegrationStatus:
    if is_set:
        detail = "noise" if context.narrow else "noise filter"
        ip_count = 0
        for e in context.active_enrichment_events:
            m = re.search(r"(\d+)\s+ip", e.message, re.IGNORECASE)
            if m:
                ip_count = max(ip_count, int(m.group(1)))
        metric = f"{ip_count} queries"
        return IntegrationStatus(label, True, detail, metric)
    else:
        return IntegrationStatus(label, False, "unconfigured", "--")


def _abuseipdb_status(label: str, is_set: bool, context: ServiceMetricsContext) -> IntegrationStatus:
    if is_set:
        detail = "ip abuse"
        ip_count = 0
        for e in context.active_enrichment_events:
            m = re.search(r"(\d+)\s+ip", e.message, re.IGNORECASE)
            if m:
                ip_count = max(ip_count, int(m.group(1)))
        metric = f"{ip_count} queries"
        return IntegrationStatus(label, True, detail, metric)
    else:
        return IntegrationStatus(label, False, "unconfigured", "--")


def _shodan_status(label: str, is_set: bool, context: ServiceMetricsContext) -> IntegrationStatus:
    if is_set:
        detail = "recon"
        ip_count = 0
        for e in context.active_enrichment_events:
            m = re.search(r"(\d+)\s+ip", e.message, re.IGNORECASE)
            if m:
                ip_count = max(ip_count, int(m.group(1)))
        metric = f"{ip_count} queries"
        return IntegrationStatus(label, True, detail, metric)
    else:
        return IntegrationStatus(label, False, "unconfigured", "--")


def _censys_status(label: str, is_set: bool, context: ServiceMetricsContext) -> IntegrationStatus:
    if is_set:
        detail = "surface" if context.narrow else "attack surface"
        ip_count = 0
        for e in context.active_enrichment_events:
            m = re.search(r"(\d+)\s+ip", e.message, re.IGNORECASE)
            if m:
                ip_count = max(ip_count, int(m.group(1)))
        metric = f"{ip_count} queries"
        return IntegrationStatus(label, True, detail, metric)
    else:
        return IntegrationStatus(label, False, "unconfigured", "--")


def _threatfox_status(label: str, is_set: bool, context: ServiceMetricsContext) -> IntegrationStatus:
    if is_set:
        detail = "abuse.ch"
        tf_count = 0
        for e in context.active_enrichment_events:
            if e.stage == "enrichment":
                m_obs = re.search(r"(\d+)\s+observable\(s\)", e.message, re.IGNORECASE)
                if m_obs:
                    tf_count = int(m_obs.group(1))
                    break
            m_obs = re.search(r"(\d+)\s+observable\(s\)", e.message, re.IGNORECASE)
            if m_obs:
                tf_count = max(tf_count, int(m_obs.group(1)))
            elif tf_count == 0:
                m_ind = re.search(r"(\d+)\s+indicator\(s\)", e.message, re.IGNORECASE)
                if m_ind:
                    tf_count = max(tf_count, int(m_ind.group(1)))
        metric = f"{tf_count} queries"
        return IntegrationStatus(label, True, detail, metric)
    else:
        return IntegrationStatus(label, False, "unconfigured", "--")


def _malbazaar_status(label: str, is_set: bool, context: ServiceMetricsContext) -> IntegrationStatus:
    if is_set:
        detail = "malware"
        hash_count = 0
        for e in context.active_enrichment_events:
            m = re.search(r"(\d+)\s+hash", e.message, re.IGNORECASE)
            if m:
                hash_count = max(hash_count, int(m.group(1)))
        metric = f"{hash_count} queries"
        return IntegrationStatus(label, True, detail, metric)
    else:
        return IntegrationStatus(label, False, "unconfigured", "--")


def _feodo_c2_status(label: str, is_set: bool, context: ServiceMetricsContext) -> IntegrationStatus:
    detail = "botnet c2" if context.narrow else "botnet"
    ip_count = 0
    for e in context.active_enrichment_events:
        m = re.search(r"(\d+)\s+ip", e.message, re.IGNORECASE)
        if m:
            ip_count = max(ip_count, int(m.group(1)))
    metric = f"{ip_count} queries"
    return IntegrationStatus(label, True, detail, metric)


def _sslbl_status(label: str, is_set: bool, context: ServiceMetricsContext) -> IntegrationStatus:
    detail = "ssl/ja3"
    hash_count = 0
    for e in context.active_enrichment_events:
        m = re.search(r"(\d+)\s+hash", e.message, re.IGNORECASE)
        if m:
            hash_count = max(hash_count, int(m.group(1)))
    metric = f"{hash_count} queries"
    return IntegrationStatus(label, True, detail, metric)


def _urlhaus_status(label: str, is_set: bool, context: ServiceMetricsContext) -> IntegrationStatus:
    if is_set:
        detail = "urls" if context.narrow else "malware urls"
        url_count = 0
        for e in context.active_enrichment_events:
            m = re.search(r"(\d+)\s+url", e.message, re.IGNORECASE)
            if m:
                url_count = max(url_count, int(m.group(1)))
        metric = f"{url_count} queries"
        return IntegrationStatus(label, True, detail, metric)
    else:
        return IntegrationStatus(label, False, "unconfigured", "--")


def _urlscan_status(label: str, is_set: bool, context: ServiceMetricsContext) -> IntegrationStatus:
    has_key = any(os.environ.get(name) for name in BY_LABEL[label].env_keys) or any(
        name in context.file_keys for name in BY_LABEL[label].env_keys
    )
    detail = "web lures" if has_key else "lures"
    url_count = 0
    for e in context.active_enrichment_events:
        m = re.search(r"(\d+)\s+url", e.message, re.IGNORECASE)
        if m:
            url_count = max(url_count, int(m.group(1)))
    metric = f"{url_count} scans"
    return IntegrationStatus(label, True, detail, metric)


def _hybrid_status(label: str, is_set: bool, context: ServiceMetricsContext) -> IntegrationStatus:
    if is_set:
        detail = "sandbox"
        hash_count = 0
        for e in context.active_enrichment_events:
            m = re.search(r"(\d+)\s+hash", e.message, re.IGNORECASE)
            if m:
                hash_count = max(hash_count, int(m.group(1)))
        metric = f"{hash_count} queries"
        return IntegrationStatus(label, True, detail, metric)
    else:
        return IntegrationStatus(label, False, "unconfigured", "--")


def _rdap_status(label: str, is_set: bool, context: ServiceMetricsContext) -> IntegrationStatus:
    detail = "whois/age"
    dom_count = 0
    for e in context.active_enrichment_events:
        m = re.search(r"(\d+)\s+domain", e.message, re.IGNORECASE)
        if m:
            dom_count = max(dom_count, int(m.group(1)))
    metric = f"{dom_count} queries"
    return IntegrationStatus(label, True, detail, metric)


def _crt_sh_status(label: str, is_set: bool, context: ServiceMetricsContext) -> IntegrationStatus:
    detail = "ct logs"
    dom_count = 0
    for e in context.active_enrichment_events:
        m = re.search(r"(\d+)\s+domain", e.message, re.IGNORECASE)
        if m:
            dom_count = max(dom_count, int(m.group(1)))
    metric = f"{dom_count} queries"
    return IntegrationStatus(label, True, detail, metric)


def _pdns_status(label: str, is_set: bool, context: ServiceMetricsContext) -> IntegrationStatus:
    detail = "passive dns"
    obs_count = 0
    for e in context.active_enrichment_events:
        m = re.search(r"(\d+)\s+observable\(s\)", e.message, re.IGNORECASE)
        if m:
            obs_count = max(obs_count, int(m.group(1)))
    metric = f"{obs_count} queries"
    return IntegrationStatus(label, True, detail, metric)


def _spur_status(label: str, is_set: bool, context: ServiceMetricsContext) -> IntegrationStatus:
    if is_set:
        detail = "proxy/vpn"
        ip_count = 0
        for e in context.active_enrichment_events:
            m = re.search(r"(\d+)\s+ip", e.message, re.IGNORECASE)
            if m:
                ip_count = max(ip_count, int(m.group(1)))
        metric = f"{ip_count} queries"
        return IntegrationStatus(label, True, detail, metric)
    else:
        return IntegrationStatus(label, False, "unconfigured", "--")


def _tor_proxy_status(label: str, is_set: bool, context: ServiceMetricsContext) -> IntegrationStatus:
    detail = "tor/vpn"
    ip_count = 0
    for e in context.active_enrichment_events:
        m = re.search(r"(\d+)\s+ip", e.message, re.IGNORECASE)
        if m:
            ip_count = max(ip_count, int(m.group(1)))
    metric = f"{ip_count} queries"
    return IntegrationStatus(label, True, detail, metric)


def _epss_status(label: str, is_set: bool, context: ServiceMetricsContext) -> IntegrationStatus:
    detail = "cve score" if context.narrow else "exploit prediction"
    cve_count = 0
    for e in context.active_enrichment_events:
        m = re.search(r"(\d+)\s+cve", e.message, re.IGNORECASE)
        if m:
            cve_count = max(cve_count, int(m.group(1)))
    metric = f"{cve_count} CVEs"
    return IntegrationStatus(label, True, detail, metric)


def _osv_dev_status(label: str, is_set: bool, context: ServiceMetricsContext) -> IntegrationStatus:
    detail = "supply chain" if context.narrow else "osv/pkg"
    cve_count = 0
    for e in context.active_enrichment_events:
        m = re.search(r"(\d+)\s+cve", e.message, re.IGNORECASE)
        if m:
            cve_count = max(cve_count, int(m.group(1)))
    metric = f"{cve_count} CVEs"
    return IntegrationStatus(label, True, detail, metric)


def _slack_status(label: str, is_set: bool, context: ServiceMetricsContext) -> IntegrationStatus:
    if is_set:
        detail = "alerts"
        draft_created = any("draft_created" in e.message for e in context.cycle_events)
        if not draft_created and context.active_enrichment_events != context.cycle_events:
            draft_created = any("draft_created" in e.message for e in context.active_enrichment_events)
        metric = "1 sent" if draft_created else "0 sent"
        return IntegrationStatus(label, True, detail, metric)
    else:
        return IntegrationStatus(label, False, "unconfigured", "--")


def _vulncheck_status(label: str, is_set: bool, context: ServiceMetricsContext) -> IntegrationStatus:
    if is_set:
        detail = "kev/cve" if context.narrow else "kev exploit"
        cve_count = 0
        for e in context.active_enrichment_events:
            m = re.search(r"(\d+)\s+cve", e.message, re.IGNORECASE)
            if m:
                cve_count = max(cve_count, int(m.group(1)))
        metric = f"{cve_count} KEVs" if cve_count > 0 else "active"
        return IntegrationStatus(label, True, detail, metric)
    else:
        return IntegrationStatus(label, False, "unconfigured", "--")


def _triage_status(label: str, is_set: bool, context: ServiceMetricsContext) -> IntegrationStatus:
    if is_set:
        detail = "sandbox"
        metric = "active"
        return IntegrationStatus(label, True, detail, metric)
    else:
        return IntegrationStatus(label, False, "unconfigured", "--")


def _shadowsrv_status(label: str, is_set: bool, context: ServiceMetricsContext) -> IntegrationStatus:
    if is_set:
        detail = "c2/botnet"
        metric = "active"
        return IntegrationStatus(label, True, detail, metric)
    else:
        return IntegrationStatus(label, False, "unconfigured", "--")


def _msrc_status(label: str, is_set: bool, context: ServiceMetricsContext) -> IntegrationStatus:
    detail = "cvrf/cve"
    cve_count = 0
    for e in context.active_enrichment_events:
        m = re.search(r"(\d+)\s+cve", e.message, re.IGNORECASE)
        if m:
            cve_count = max(cve_count, int(m.group(1)))
    metric = f"{cve_count} CVEs" if cve_count > 0 else "advisories"
    return IntegrationStatus(label, True, detail, metric)


def _cloudthrt_status(label: str, is_set: bool, context: ServiceMetricsContext) -> IntegrationStatus:
    detail = "iam/cloud"
    metric = "3 feeds"
    return IntegrationStatus(label, True, detail, metric)


def _dfir_rept_status(label: str, is_set: bool, context: ServiceMetricsContext) -> IntegrationStatus:
    detail = "reports"
    metric = "feed"
    return IntegrationStatus(label, True, detail, metric)


def _first_org_status(label: str, is_set: bool, context: ServiceMetricsContext) -> IntegrationStatus:
    detail = "epss spike"
    metric = "active"
    return IntegrationStatus(label, True, detail, metric)


def _any_run_status(label: str, is_set: bool, context: ServiceMetricsContext) -> IntegrationStatus:
    detail = "sandbox"
    metric = "active"
    return IntegrationStatus(label, True, detail, metric)


def _opencti_status(label: str, is_set: bool, context: ServiceMetricsContext) -> IntegrationStatus:
    detail = "stix/intel"
    metric = "active"
    return IntegrationStatus(label, True, detail, metric)


_SERVICE_METRICS = {
    "LLM": _llm_status,
    "Tavily": _tavily_status,
    "OTX": _otx_status,
    "MISP": _misp_status,
    "VT": _vt_status,
    "GreyNoise": _greynoise_status,
    "AbuseIPDB": _abuseipdb_status,
    "Shodan": _shodan_status,
    "Censys": _censys_status,
    "ThreatFox": _threatfox_status,
    "MalBazaar": _malbazaar_status,
    "Feodo C2": _feodo_c2_status,
    "Feodo": _feodo_c2_status,
    "SSLBL": _sslbl_status,
    "URLhaus": _urlhaus_status,
    "URLScan": _urlscan_status,
    "Hybrid": _hybrid_status,
    "RDAP": _rdap_status,
    "crt.sh": _crt_sh_status,
    "PDNS": _pdns_status,
    "Spur": _spur_status,
    "Tor/Proxy": _tor_proxy_status,
    "EPSS": _epss_status,
    "OSV.dev": _osv_dev_status,
    "OSV": _osv_dev_status,
    "Slack": _slack_status,
    "VulnCheck": _vulncheck_status,
    "Triage": _triage_status,
    "Shadowsrv": _shadowsrv_status,
    "MSRC": _msrc_status,
    "CloudThrt": _cloudthrt_status,
    "DFIR Rept": _dfir_rept_status,
    "FIRST.org": _first_org_status,
    "ANY.RUN": _any_run_status,
    "OpenCTI": _opencti_status,
}


def service_status(label: str, configured: bool, context: ServiceMetricsContext) -> IntegrationStatus:
    """Resolve one registry service without doing file or network I/O."""
    return _SERVICE_METRICS[label](label, configured, context)
