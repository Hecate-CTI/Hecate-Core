"""Validation panels for the live monitor."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from rich import box
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from hecate_agent.commands.monitor_metrics import SiemDriftMetrics, _collect_siem_drift_metrics
from hecate_agent.commands.monitor_samplers import TrailEvent


def _bas_status_panel(workspace: Path, events: List[TrailEvent], metrics: Any) -> Panel:
    table = Table(box=box.SIMPLE, expand=True, show_header=False, padding=(0, 1))
    table.add_column("KEY", width=20, style="dim")
    table.add_column("VALUE", style="bright_white")

    table.add_row("CONTROLLER ENGINE", Text("Caldera Controller (Non-Root)", style="bright_green"))
    table.add_row("TARGET SENSOR", Text("Ubuntu Local Process Sensor + Sigma", style="bright_cyan"))
    table.add_row(
        "ATTACK AUTOMATION", Text(getattr(metrics, "bas_mode_label", "AUTO · approved Linux lab"), style="bright_white")
    )
    table.add_row(
        "VALIDATION SCOPE", Text(getattr(metrics, "bas_scope_label", "Local process sensor + Sigma"), style="bright_white")
    )

    runs = getattr(metrics, "bas_runs", 0)
    live_runs = getattr(metrics, "bas_live_runs", 0)
    mock_runs = getattr(metrics, "bas_mock_runs", 0)
    table.add_row("SIMULATION RUNS", f"{runs} runs ({live_runs} live, {mock_runs} mock)")

    events_count = getattr(metrics, "bas_matched_events", 0)
    table.add_row("SENSOR TELEMETRY", f"{events_count} events captured & correlated")

    siem_latency = getattr(metrics, "bas_last_detection_latency_sec", 0.0)
    siem_backend = getattr(metrics, "bas_last_siem_backend", "") or "SPLUNK"
    if siem_latency > 0.0:
        latency_str = f"{siem_latency:.3f}s ({siem_latency * 1000:.0f} ms)"
        avg_latency = getattr(metrics, "bas_avg_detection_latency_sec", 0.0)
        if avg_latency > 0.0 and avg_latency != siem_latency:
            latency_str += f" · avg {avg_latency:.3f}s"
        table.add_row("LIVE SIEM ALERT", Text(f"{siem_backend.upper()} ALERT FIRED · VERIFIED", style="bold bright_green"))
        table.add_row("DETECTION LATENCY", Text(f"{latency_str} (True Positive)", style="bold bright_cyan"))
    else:
        table.add_row("LIVE SIEM ALERT", Text("STANDBY · awaiting adversary detonation", style="dim"))
        table.add_row("DETECTION LATENCY", Text("--", style="dim"))

    return Panel(
        table,
        title="[bold bright_cyan]BAS CONTROLLER & SENSOR STATUS[/]",
        border_style="bright_magenta",
        box=box.ROUNDED,
    )


def _bas_events_panel(events: List[TrailEvent]) -> Panel:
    table = Table(box=box.SIMPLE, expand=True, show_header=True, header_style="bold bright_cyan", padding=(0, 1))
    table.add_column("TIME", width=9, style="dim")
    table.add_column("STAGE", width=12)
    table.add_column("VALIDATION ACTIVITY", ratio=1, overflow="ellipsis", no_wrap=True)

    bas_events = [
        e
        for e in events
        if any(
            k in e.message.lower() or k in e.stage.lower()
            for k in ("bas", "sensor", "caldera", "stratus", "validation", "telemetry", "replay")
        )
    ]
    for e in bas_events[-8:]:
        table.add_row(e.timestamp[-8:], e.stage, e.message)

    if not bas_events:
        table.add_row("--:--:--", "standby", "No recent breach simulation events in log stream")

    return Panel(
        table,
        title="[bold bright_cyan]RECENT SENSOR & BREACH SIMULATION LOGS[/]",
        border_style="bright_magenta",
        box=box.ROUNDED,
    )


def _siem_sync_panel(
    workspace: Optional[Path] = None,
    metrics: Optional[SiemDriftMetrics] = None,
) -> Panel:
    """SIEM Detection-as-Code sync health, audit sweeps, and platform targets."""
    measured = metrics or _collect_siem_drift_metrics(workspace)
    table = Table(box=None, show_header=False, expand=True, padding=(0, 1))
    table.add_column("label", style="dim", width=14, min_width=14, no_wrap=True)
    table.add_column("value", ratio=1, overflow="ellipsis", no_wrap=True)

    if measured.drifted_count > 0:
        st_text = Text(f"DRIFT DETECTED ({measured.drifted_count})", style="bold bright_red")
    elif measured.pending_decommission_count > 0:
        st_text = Text(f"DECOMMISSION PENDING ({measured.pending_decommission_count})", style="bold bright_yellow")
    elif measured.missing_count > 0 or measured.error_count > 0:
        st_text = Text("ATTENTION REQUIRED", style="bold bright_yellow")
    elif measured.total_queries > 0:
        st_text = Text("IN SYNC (100%)", style="bold bright_green")
    else:
        st_text = Text("STANDBY", style="dim")
    table.add_row("STATUS", st_text)

    active_queries = max(1, measured.total_queries - measured.decommissioned_count)
    sync_val = (
        f"{measured.in_sync_count} / {active_queries} active queries in sync ({measured.sync_pct:.1f}%)"
        + (f" · {measured.decommissioned_count} decommissioned" if measured.decommissioned_count > 0 else "")
        if measured.total_queries > 0
        else "0 queries tracked"
    )
    table.add_row("SYNC RATIO", Text(sync_val, style="bright_white" if measured.total_queries else "dim"))

    drift_style = "bold bright_red" if measured.drifted_count > 0 else "dim"
    drift_elements: List[Tuple[str, str]] = [
        (f"{measured.drifted_count} drifted", drift_style),
        (" · ", "dim"),
        (f"{measured.missing_count} missing", "bold bright_yellow" if measured.missing_count else "dim"),
    ]
    if measured.decommissioned_count > 0:
        drift_elements.extend(
            [
                (" · ", "dim"),
                (f"{measured.decommissioned_count} decommissioned", "bright_cyan"),
            ]
        )
    if measured.pending_decommission_count > 0:
        drift_elements.extend(
            [
                (" · ", "dim"),
                (f"{measured.pending_decommission_count} pending decom", "bold bright_yellow"),
            ]
        )
    drift_elements.extend(
        [
            (" · ", "dim"),
            (f"{measured.error_count} errors", "bold bright_red" if measured.error_count else "dim"),
        ]
    )
    table.add_row("DRIFT METRICS", Text.assemble(*drift_elements))

    table.add_row(
        "AUDIT SWEEPS",
        Text(
            f"{measured.sweeps_conducted} sweeps executed · {measured.reconciled_count} reconciled",
            style="bright_white" if measured.sweeps_conducted else "dim",
        ),
    )

    table.add_row(
        "VERSIONS",
        Text(
            f"{measured.tracked_versions} query version snapshots tracked",
            style="bright_cyan" if measured.tracked_versions else "dim",
        ),
    )

    last_sweep = measured.last_audited[:19].replace("T", " ") + " UTC" if measured.last_audited else "never"
    table.add_row("LAST AUDIT", Text(last_sweep, style="dim"))

    if measured.last_detection_latency_sec > 0.0 or measured.bas_verified_alerts_count > 0:
        hunt_txt = (
            f" ({measured.last_verified_hunt} · {measured.last_verified_technique})" if measured.last_verified_hunt else ""
        )
        lat_txt = f"{measured.last_detection_latency_sec:.3f}s latency{hunt_txt}"
        table.add_row(
            "CLOSED-LOOP BAS",
            Text(f"{measured.bas_verified_alerts_count} live alerts verified · {lat_txt}", style="bold bright_green"),
        )
    else:
        table.add_row("CLOSED-LOOP BAS", Text("Standby · 0 live validations recorded", style="dim"))

    if measured.active_targets:
        targets_str = " · ".join(
            f"{t.upper()} ({measured.target_breakdown.get(t, {}).get('in_sync', 0)}/{measured.target_breakdown.get(t, {}).get('total', 0)} in sync)"
            for t in measured.active_targets
        )
        table.add_row("TARGETS", Text(targets_str, style="bright_cyan"))
    else:
        table.add_row("TARGETS", Text("Splunk REST API (Saved Searches) · Elastic Fleet / Rules API", style="dim"))

    table.add_row("AUTHORITATIVE", Text("queries/H-*/ (Git HEAD repository authoritative source)", style="dim"))

    return Panel(
        table,
        title="[bold bright_cyan]SIEM DETECTION-AS-CODE[/]",
        border_style="bright_magenta",
        box=box.ROUNDED,
    )


def _siem_drift_diff_panel(
    events: Optional[List[Dict[str, Any]]] = None,
) -> Panel:
    """Inspect AST and syntax differences between local git and live SIEM queries."""
    ev_list = events or []
    diff_event: Optional[Dict[str, Any]] = None
    for ev in ev_list:
        if ev.get("drift_diff"):
            diff_event = ev
            break
        if ev.get("event_type") == "drift_detected":
            diff_event = ev
            break

    if not diff_event or not diff_event.get("drift_diff"):
        text = Text()
        text.append("\n  ✔  All deployed SIEM queries match git-authoritative AST\n\n", style="bold bright_green")
        text.append("  • No active query drift detected across monitoring targets.\n", style="bright_white")
        text.append("  • Live SIEM Saved Searches verify 1:1 against transpiled SPL/KQL.\n", style="dim")
        text.append("  • Any remote console edits will trigger automated drift detection.\n", style="dim")
        if ev_list:
            latest = ev_list[0]
            text.append(
                f"\n  Last audit event: {latest.get('event_type', '')} on {latest.get('hunt_id', '')} ({latest.get('target', '')})",
                style="bright_cyan",
            )
        return Panel(
            text,
            title="[bold bright_cyan]DRIFT INSPECTION & DIFF[/]",
            border_style="bright_magenta",
            box=box.ROUNDED,
        )

    diff_text = Text()
    diff_text.append(
        f"HUNT: {diff_event.get('hunt_id', '')}  TARGET: {diff_event.get('target', '')}  EVENT: {diff_event.get('event_type', '')}\n",
        style="bold bright_cyan",
    )
    diff_text.append(f"FILE: {diff_event.get('file_name', '')}\n", style="dim")
    diff_text.append(
        f"TIMESTAMP: {diff_event.get('timestamp', '')[:19].replace('T', ' ')}  ACTOR: {diff_event.get('actor', '')}\n\n",
        style="dim",
    )

    raw_diff = str(diff_event.get("drift_diff", ""))
    lines = raw_diff.splitlines()
    for line in lines[:10]:
        if line.startswith("-"):
            diff_text.append(line + "\n", style="bright_red")
        elif line.startswith("+"):
            diff_text.append(line + "\n", style="bright_green")
        elif line.startswith("@") or line.startswith("---") or line.startswith("+++"):
            diff_text.append(line + "\n", style="bold bright_cyan")
        else:
            diff_text.append(line + "\n", style="dim")
    if len(lines) > 10:
        diff_text.append(f"... ({len(lines) - 10} additional diff lines)\n", style="dim")

    return Panel(
        diff_text,
        title="[bold bright_cyan]DRIFT INSPECTION & DIFF[/]",
        border_style="bright_magenta",
        box=box.ROUNDED,
    )


def _siem_drift_events_table(
    events: Optional[List[Dict[str, Any]]] = None,
) -> Panel:
    """Historical audit sweep and reconciliation event log table."""
    table = Table(box=box.SIMPLE, expand=True, show_header=True, header_style="bold bright_cyan", padding=(0, 1))
    table.add_column("TIME", width=8, style="dim")
    table.add_column("EVENT", width=15)
    table.add_column("HUNT", width=8, style="bright_cyan")
    table.add_column("TARGET", width=11, style="dim")
    table.add_column("ACTOR", width=8, style="dim")
    table.add_column("DETAIL", ratio=1, overflow="ellipsis", no_wrap=True)

    ev_list = events or []
    if not ev_list:
        table.add_row("--:--:--", "[dim]standby[/]", "--", "--", "--", "[dim]No drift or reconciliation events logged yet.[/]")
    else:
        for ev in ev_list[:12]:
            ts = str(ev.get("timestamp") or "")
            time_part = ts[11:19] if len(ts) >= 19 else ts
            event_type = str(ev.get("event_type") or "unknown")
            if event_type == "reconciled":
                event_style = "[bold bright_green]reconciled[/]"
            elif event_type == "decommissioned":
                event_style = "[bold bright_cyan]decommissioned[/]"
            elif event_type == "pending_decommission":
                event_style = "[bold bright_yellow]pending_decom[/]"
            elif event_type == "drift_detected":
                event_style = "[bold bright_red]drift_detected[/]"
            elif event_type == "missing_remote":
                event_style = "[bold bright_yellow]missing_remote[/]"
            else:
                event_style = f"[bright_white]{event_type}[/]"

            table.add_row(
                time_part,
                event_style,
                str(ev.get("hunt_id") or "--"),
                str(ev.get("target") or "--"),
                str(ev.get("actor") or "system"),
                str(ev.get("detail") or ""),
            )

    return Panel(
        table,
        title="[bold bright_cyan]SIEM AUDIT & DRIFT EVENT LOG[/]",
        border_style="bright_magenta",
        box=box.ROUNDED,
    )


def _siem_query_versions_table(
    versions: Optional[List[Dict[str, Any]]] = None,
) -> Panel:
    """Immutable deployed query versions recorded in SQLite history."""
    table = Table(box=box.SIMPLE, expand=True, show_header=True, header_style="bold bright_cyan", padding=(0, 1))
    table.add_column("HUNT", width=8, style="bright_cyan")
    table.add_column("VER", width=5, style="bold bright_white")
    table.add_column("TARGET", width=11, style="dim")
    table.add_column("QUERY HASH", width=12, style="dim")
    table.add_column("DEPLOYED", width=16, style="dim")
    table.add_column("BY", width=8, style="dim")
    table.add_column("STATUS", width=8)

    v_list = versions or []
    if not v_list:
        table.add_row("--", "--", "--", "--", "--", "--", "[dim]none[/]")
    else:
        for ver in v_list[:12]:
            q_hash = str(ver.get("query_hash") or "")
            hash_display = f"{q_hash[:8]}…" if len(q_hash) > 8 else q_hash
            dep_at = str(ver.get("deployed_at") or "")
            dep_display = dep_at[:16].replace("T", " ") if len(dep_at) >= 16 else dep_at
            status = str(ver.get("status") or "active")
            if status == "active":
                st_display = "[bright_green]active[/]"
            elif status in ("decommissioned", "retired"):
                st_display = "[bright_cyan]decommissioned[/]"
            elif status == "deprecated":
                st_display = "[bright_yellow]deprecated[/]"
            else:
                st_display = f"[dim]{status}[/]"

            table.add_row(
                str(ver.get("hunt_id") or "--"),
                f"v{ver.get('version', 1)}",
                str(ver.get("target") or "--"),
                hash_display,
                dep_display,
                str(ver.get("deployed_by") or "system"),
                st_display,
            )

    return Panel(
        table,
        title="[bold bright_cyan]QUERY VERSION CATALOG[/]",
        border_style="bright_magenta",
        box=box.ROUNDED,
    )
