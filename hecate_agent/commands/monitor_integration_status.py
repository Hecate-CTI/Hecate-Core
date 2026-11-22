"""Collect integration status snapshots independently of Rich rendering."""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from hecate_agent.commands.monitor_samplers import TrailEvent
from hecate_agent.commands.monitor_service_metrics import IntegrationStatus, ServiceMetricsContext, service_status
from hecate_agent.integration_registry import BY_LABEL, INTEGRATIONS, SOURCE_INTEGRATIONS, STATUS_INTEGRATIONS, label_for_host

_INTEGRATION_IDS = {item.label: item.id for item in BY_LABEL.values()}
_SOURCE_INTEGRATIONS = {item.cti_name for item in INTEGRATIONS if item.follows_cti_provider}
_API_CALLS_TAIL_BYTES = 512 * 1024


@dataclass(frozen=True)
class IntegrationSnapshot:
    services: Tuple[IntegrationStatus, ...]
    active_integration: Optional[str]
    traffic: Dict[str, Dict[str, float]]


def _credential_status(workspace: Optional[Path] = None) -> Tuple[List[str], List[str]]:
    """Return lists of active (configured) and inactive service labels."""
    checks = tuple((item.label, item.env_keys) for item in STATUS_INTEGRATIONS if item.env_keys)
    env_files = [workspace / ".env"] if workspace else []
    if workspace:
        env_files.append(workspace.parent / "Hecate-Runner" / ".env")
    file_keys = set()
    for env_file in env_files:
        try:
            for line in env_file.read_text(encoding="utf-8").splitlines():
                key, sep, value = line.partition("=")
                if sep and value.strip().strip("\"'"):
                    file_keys.add(key.strip().removeprefix("export "))
        except OSError:
            continue
    on, off = [], []
    for label, names in checks:
        is_set = any(os.environ.get(name) for name in names) or any(name in file_keys for name in names)
        if is_set:
            on.append(label)
        else:
            off.append(label)
    return on, off


def _credential_summary(workspace: Optional[Path] = None) -> str:
    """Show configured status only; never read or render credential values."""
    on, off = _credential_status(workspace)
    return " · ".join([f"{item} ON" for item in on] + [f"{item} OFF" for item in off])


def _confirmed_integration(workspace: Optional[Path], name: str, enabled: bool) -> Tuple[bool, str]:
    """Only a recent successful check plus current enablement can produce green."""
    if workspace is None:
        return False, "unconfirmed" if enabled else "disabled"
    try:
        record = json.loads((workspace / ".hecate" / "integrations" / f"{name}.json").read_text())
        checked = datetime.fromisoformat(record["checked_at"])
        age = (datetime.now(timezone.utc) - checked).total_seconds()
        if not 0 <= age <= 7200:
            return False, "check stale" if enabled else "disabled"
        if not enabled and record.get("healthy") is True:
            return False, "reachable; disabled"
        if not enabled:
            return False, "disabled"
        healthy = enabled and record.get("healthy") is True and record.get("enabled") is True
        return healthy, "confirmed" if healthy else str(record.get("detail") or "failed")[:80]
    except (OSError, ValueError, TypeError, KeyError, AttributeError):
        return False, "unconfirmed" if enabled else "disabled"


def _color_group_rank(ok: bool, detail: str) -> int:
    """Group by color: 1=Green (healthy), 2=Pink (output-only), 3=Magenta (reachable; disabled), 4=Red (failed/error), 5=Grey (disabled)."""
    if ok and detail != "output only":
        return 1
    if ok and detail == "output only":
        return 2
    if detail == "reachable; disabled":
        return 3
    if detail == "disabled":
        return 5
    return 4


def _detect_active_integration(
    current: Optional[TrailEvent] = None,
    events: Optional[List[TrailEvent]] = None,
    live: Optional[Dict[str, Any]] = None,
) -> Optional[str]:
    """Identify which integration service is actively in use right now."""
    if live and (live.get("in_flight") or live.get("status") in ("CALLING", "STREAMING")):
        return "LLM"

    if not current:
        return None

    msg = current.message.lower()
    stage = current.stage.lower()

    if stage in ("hypothesis", "techniques", "scope", "write", "sigma", "review"):
        return "LLM"
    if stage == "research":
        if "search" in msg or "tavily" in msg:
            return "Tavily"
        return "LLM"
    if stage in ("intake", "source"):
        for token, label in (
            ("misp", "MISP"),
            ("otx", "OTX"),
            ("rss", "RSS"),
            ("github poc", "GitHub PoC"),
            ("vxug", "VXUG"),
            ("cisa", "CISA AA"),
            ("vulncheck", "VulnCheck"),
            ("triage", "Triage"),
            ("shadowserver", "Shadowsrv"),
            ("certstream", "CertStrm"),
        ):
            if token in msg:
                return label
        return None
    if stage == "enrichment":
        for token, label in (
            ("virustotal", "VT"),
            ("vt", "VT"),
            ("greynoise", "GreyNoise"),
            ("abuseipdb", "AbuseIPDB"),
            ("shodan", "Shodan"),
            ("censys", "Censys"),
            ("threatfox", "ThreatFox"),
            ("malwarebazaar", "MalBazaar"),
            ("malbazaar", "MalBazaar"),
            ("urlhaus", "URLhaus"),
            ("urlscan", "URLScan"),
            ("hybrid", "Hybrid"),
            ("rdap", "RDAP"),
            ("crt.sh", "crt.sh"),
            ("pdns", "PDNS"),
            ("spur", "Spur"),
        ):
            if token in msg:
                return label
    return None


def _api_label(host: str, env_values: Dict[str, str]) -> Optional[str]:
    """The panel label for a request host. Instance hosts come from the registry's env URLs."""
    return label_for_host(host, env_values)


def _read_jsonl_tail(path: Path) -> List[dict]:
    try:
        with path.open("rb") as fh:
            size = fh.seek(0, os.SEEK_END)
            fh.seek(max(0, size - _API_CALLS_TAIL_BYTES))
            raw = fh.read().decode("utf-8", errors="replace")
    except OSError:
        return []
    rows = []
    for line in raw.splitlines():
        try:
            row = json.loads(line)
        except (ValueError, TypeError):
            continue
        if isinstance(row, dict):
            rows.append(row)
    return rows


def _api_traffic(workspace: Optional[Path], since: float, env_values: Dict[str, str]) -> Dict[str, Dict[str, float]]:
    """Per-label request counts since ``since``.

    Prefers ``logs/events.jsonl`` http events (the cycle event channel) and
    falls back to ``logs/api_calls.jsonl`` from before that channel existed.
    """
    if workspace is None:
        return {}
    logs = workspace / "logs"
    recorded = [row for row in _read_jsonl_tail(logs / "events.jsonl") if row.get("type") == "http"]
    calls = recorded or _read_jsonl_tail(logs / "api_calls.jsonl")
    traffic: Dict[str, Dict[str, float]] = {}
    for call in calls:
        try:
            ts, host, status = float(call["ts"]), str(call["host"]), int(call["status"])
        except (ValueError, TypeError, KeyError):
            continue
        if ts < since:
            continue
        label = _api_label(host, env_values)
        if label is None:
            continue
        row = traffic.setdefault(label, {"requests": 0, "ok": 0, "errors": 0, "limited": 0, "last_ts": 0.0})
        row["requests"] += 1
        if status == 429:
            row["limited"] += 1
        elif 200 <= status < 400:
            row["ok"] += 1
        else:
            row["errors"] += 1
        row["last_ts"] = max(row["last_ts"], ts)
    return traffic


def _cycle_start(events: List[TrailEvent]) -> Optional[float]:
    """Epoch seconds the latest cycle began, from its first trail line (local time)."""
    if not events:
        return None
    cycle = events[-1].cycle_id
    first = next((e for e in events if e.cycle_id == cycle), None)
    if first is None:
        return None
    try:
        return datetime.strptime(first.timestamp, "%Y-%m-%d %H:%M:%S").timestamp() - first.elapsed
    except ValueError:
        return None


def collect_integration_snapshot(
    workspace: Optional[Path] = None,
    search_count: str = "pending",
    narrow: bool = True,
    events: Optional[List[TrailEvent]] = None,
    metrics: Optional[Dict[str, Any]] = None,
    live: Optional[Dict[str, Any]] = None,
    current: Optional[TrailEvent] = None,
    include_traffic: bool = True,
) -> IntegrationSnapshot:
    """Read configuration and recorded checks; return display data without credentials."""
    env_files = [workspace / ".env"] if workspace else []
    if workspace:
        env_files.append(workspace.parent / "Hecate-Runner" / ".env")
    file_keys = set()
    file_values: Dict[str, str] = {}
    for env_file in env_files:
        try:
            for line in env_file.read_text(encoding="utf-8").splitlines():
                key, sep, value = line.partition("=")
                if sep and value.strip().strip("\"'"):
                    env_key = key.strip().removeprefix("export ")
                    file_keys.add(env_key)
                    file_values[env_key] = value.strip().strip("\"'")
        except OSError:
            continue
    cycle_events: List[TrailEvent] = []
    if current and events:
        cycle_events = [e for e in events if e.cycle_id == current.cycle_id]
    elif events:
        last_cid = events[-1].cycle_id if events else None
        if last_cid:
            cycle_events = [e for e in events if e.cycle_id == last_cid]

    # For enrichment services, preserve metrics from the latest active cycle that performed
    # enrichment across idle polling cycles (similar to _latest_metrics for LLM calls).
    active_enrichment_events: List[TrailEvent] = cycle_events
    if not any(e.stage == "enrichment" for e in cycle_events) and events:
        for e in reversed(events):
            if e.stage == "enrichment":
                last_enrich_cid = e.cycle_id
                active_enrichment_events = [ev for ev in events if ev.cycle_id == last_enrich_cid]
                break

    services_data = []
    context = ServiceMetricsContext(
        file_keys, cycle_events, active_enrichment_events, search_count, narrow, events or [], metrics, live
    )
    services_data = [
        service_status(
            item.label,
            any(os.environ.get(name) for name in item.env_keys)
            or any(name in file_keys for name in item.env_keys)
            or item.always_configured,
            context,
        )
        for item in STATUS_INTEGRATIONS
    ]

    env_values = {**file_values, **os.environ}
    provider = env_values.get("HECATE_RUNNER_CTI_PROVIDER", "file")
    active_sources = (
        set(env_values.get("HECATE_RUNNER_CTI_MULTI_PROVIDERS", "rss,otx,misp").replace(" ", "").split(","))
        if provider == "multi"
        else {provider}
    )
    for item in SOURCE_INTEGRATIONS:
        services_data.append(IntegrationStatus(item.label, True, "source", "--"))
    confirmed_data = []
    for label, configured, detail, metric in services_data:
        item = BY_LABEL[label]
        name = item.id
        source_name = item.cti_name
        enabled = source_name in active_sources if item.follows_cti_provider else configured
        if name == "misp" and str(env_values.get("HECATE_RUNNER_MISP_PUBLISHING_ENABLED", "false")).lower() in {
            "true",
            "1",
            "yes",
            "on",
        }:
            name, enabled = "misp_output", True
            detail = "output only" if source_name not in active_sources else "input/output"
        if name == "slack" and str(env_values.get("HECATE_RUNNER_SLACK_INTERACTIVE_ENABLED", "false")).lower() not in {
            "true",
            "1",
            "yes",
            "on",
        }:
            detail = "output only"
        ok, reason = _confirmed_integration(workspace, name, enabled)
        confirmed_data.append(IntegrationStatus(label, ok, detail if ok else reason, metric))
    active_integration = _detect_active_integration(current, events, live)
    confirmed_data.sort(key=lambda item: (_color_group_rank(item[1], item[2]), item[0].lower()))
    services_data = confirmed_data

    traffic = _api_traffic(workspace, _cycle_start(events or []) or time.time() - 3600, env_values) if include_traffic else {}
    return IntegrationSnapshot(tuple(services_data), active_integration, traffic)
