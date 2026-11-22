"""Integration panels and credential status for monitor UI."""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from rich import box
from rich.console import Console, ConsoleOptions, RenderResult
from rich.measure import Measurement
from rich.panel import Panel
from rich.rule import Rule
from rich.segment import Segment
from rich.table import Table
from rich.text import Text

from hecate_agent.commands.monitor_integration_status import (
    _INTEGRATION_IDS as _INTEGRATION_IDS,
)
from hecate_agent.commands.monitor_integration_status import (
    _SOURCE_INTEGRATIONS as _SOURCE_INTEGRATIONS,
)
from hecate_agent.commands.monitor_integration_status import (
    IntegrationSnapshot,
    collect_integration_snapshot,
)
from hecate_agent.commands.monitor_integration_status import (
    _api_label as _api_label,
)
from hecate_agent.commands.monitor_integration_status import (
    _api_traffic as _api_traffic,
)
from hecate_agent.commands.monitor_integration_status import (
    _color_group_rank as _color_group_rank,
)
from hecate_agent.commands.monitor_integration_status import (
    _confirmed_integration as _confirmed_integration,
)
from hecate_agent.commands.monitor_integration_status import (
    _credential_status as _credential_status,
)
from hecate_agent.commands.monitor_integration_status import (
    _credential_summary as _credential_summary,
)
from hecate_agent.commands.monitor_integration_status import (
    _cycle_start as _cycle_start,
)
from hecate_agent.commands.monitor_integration_status import (
    _detect_active_integration as _detect_active_integration,
)
from hecate_agent.commands.monitor_integration_status import (
    _read_jsonl_tail as _read_jsonl_tail,
)
from hecate_agent.commands.monitor_samplers import TrailEvent
from hecate_agent.integration_registry import (
    enrichment_label,
)


def _integration_style(healthy: bool, detail: str) -> str:
    if healthy:
        return "bold #ff69b4" if detail == "output only" else "bold bright_green"
    if detail == "reachable; disabled":
        return "bold bright_magenta"
    if detail == "disabled":
        return "bold grey62"
    return "bold bright_red"


def _compact_count(value: float) -> str:
    if value >= 1_000_000:
        return f"{value / 1_000_000:.1f}M"
    if value >= 1_000:
        return f"{value / 1_000:.1f}k"
    return str(int(value))


_RECENT_REQUEST_S = 8.0


def _enrichment_result(label: str, events: List[TrailEvent]) -> Optional[str]:
    """The Runner's per-service outcome line for ``label`` from the latest enrichment."""
    for event in reversed(events):
        data = event.data or {}
        if data.get("kind") == "enrichment" and enrichment_label(str(data.get("service") or "")) == label:
            summary = data.get("summary")
            if summary:
                return str(summary)
        if event.stage != "enrichment" or ": " not in event.message:
            continue
        service, outcome = event.message.split(": ", 1)
        if enrichment_label(service) == label:
            return outcome
    return None


def _traffic_line(row: Dict[str, float], now: float) -> Text:
    parts = [f"{int(row['requests'])} req", f"{int(row['ok'])} ok"]
    if row["errors"]:
        parts.append(f"{int(row['errors'])} err")
    if row["limited"]:
        parts.append(f"{int(row['limited'])} rate-limited")
    ago = max(0.0, now - row["last_ts"])
    parts.append(f"last {ago:.0f}s ago" if ago < 120 else f"last {ago / 60:.0f}m ago")
    style = "bright_red" if row["errors"] or row["limited"] else "bright_green"
    return Text(" · ".join(parts), style=style, overflow="ellipsis", no_wrap=True)


def _active_integration_lines(
    active: Optional[str],
    services: Sequence[Tuple[str, bool, str, str]],
    current: Optional[TrailEvent],
    events: Optional[List[TrailEvent]],
    live: Optional[Dict[str, Any]],
    traffic: Optional[Dict[str, Dict[str, float]]] = None,
    now: Optional[float] = None,
) -> List[Text]:
    """Metrics for the integration in use, or the last one used, under the panel's grid.

    The monitor's layouts give this panel a fixed height and crop from the
    bottom, so these lines fill spare rows and are the first thing dropped
    when there are none.
    """
    events = events or []
    traffic = traffic or {}
    now = time.time() if now is None else now
    label, event, stage_events = active, current, []
    if label is None and traffic:
        recent, row = max(traffic.items(), key=lambda item: item[1]["last_ts"])
        if now - row["last_ts"] <= _RECENT_REQUEST_S:
            label = active = recent
    if label is None:
        for candidate in reversed(events):
            label = _detect_active_integration(candidate, events, None)
            if label:
                event = candidate
                break
    if label is None:
        return [Text("No integration in use this cycle", style="dim")]
    if event is not None:
        stage_events = [e for e in events if e.cycle_id == event.cycle_id and e.stage == event.stage]

    service = next((s for s in services if s[0] == label), None)
    detail, metric = (service[2], service[3]) if service else ("", "--")
    head = Text.assemble(
        ("NOW " if active else "LAST ", "bold black on bright_cyan" if active else "bold grey62"),
        (f" {label}", "bold bright_cyan" if active else "bold bright_white"),
        (f" · {detail}" if detail else "", "bright_white"),
        (f" · {metric}" if metric != "--" else "", "bright_cyan"),
    )
    head.no_wrap, head.overflow = True, "ellipsis"
    lines = [head]
    if label in traffic:
        lines.append(_traffic_line(traffic[label], now))
    outcome = _enrichment_result(label, events)
    if outcome:
        lines.append(Text(f"lookups: {outcome}", style="bright_cyan", overflow="ellipsis", no_wrap=True))

    facts: List[str] = []
    if event is not None:
        facts.append(f"stage {event.stage}")
        if stage_events:
            spent = max(0.0, event.elapsed - stage_events[0].elapsed)
            facts.append(f"{spent:.0f}s in stage")
            facts.append(f"{len(stage_events)} step(s)")
        if not active:
            facts.append(f"at {event.timestamp[-8:]}")
    if facts:
        lines.append(Text(" · ".join(facts), style="bright_white", overflow="ellipsis", no_wrap=True))
    if label == "LLM" and live:
        calls = int(live.get("llm_calls") or 0)
        usage = [f"{int(live.get('in_flight') or 0)} in flight", f"{calls} done"]
        if live.get("failed"):
            usage.append(f"{int(live['failed'])} failed")
        tokens_in, tokens_out = int(live.get("input_tokens") or 0), int(live.get("output_tokens") or 0)
        if tokens_in or tokens_out:
            usage.append(f"{_compact_count(tokens_in)} in / {_compact_count(tokens_out)} out tok")
        if calls and live.get("duration_ms"):
            usage.append(f"avg {int(live['duration_ms']) / calls / 1000:.1f}s/call")
        if live.get("cost_usd"):
            usage.append(f"${float(live['cost_usd']):.2f}")
        raw_tier = live.get("by_tier")
        by_tier: Dict[str, Any] = raw_tier if isinstance(raw_tier, dict) else {}
        tier_bits = []
        for name in ("simple", "complex"):
            raw_bucket = by_tier.get(name)
            bucket: Dict[str, Any] = raw_bucket if isinstance(raw_bucket, dict) else {}
            tier_calls = int(bucket.get("llm_calls") or 0)
            if tier_calls:
                tier_bits.append(f"{name} {tier_calls}")
        if tier_bits:
            usage.append(" / ".join(tier_bits))
        if live.get("escalated_calls"):
            usage.append(f"esc {int(live['escalated_calls'])}")
        models = live.get("models") or []
        if models:
            usage.append(", ".join(str(m) for m in sorted(models))[:40])
        lines.append(Text(" · ".join(usage), style="bright_cyan", overflow="ellipsis", no_wrap=True))
    if event is not None and event.message:
        lines.append(Text(event.message, style="dim", overflow="ellipsis", no_wrap=True))
    return lines


def _integrations_panel(
    workspace: Optional[Path] = None,
    search_count: str = "pending",
    narrow: bool = True,
    compact: bool = False,
    events: Optional[List[TrailEvent]] = None,
    metrics: Optional[Dict[str, Any]] = None,
    live: Optional[Dict[str, Any]] = None,
    current: Optional[TrailEvent] = None,
    grid: bool = False,
    grid_compact_names: bool = False,
) -> Panel:
    """A dedicated panel displaying external API and service integration statuses and activity metrics."""
    snapshot = collect_integration_snapshot(
        workspace, search_count=search_count, narrow=narrow, events=events,
        metrics=metrics, live=live, current=current, include_traffic=not compact,
    )
    return render_integration_snapshot(
        snapshot, narrow=narrow, compact=compact, events=events, live=live,
        current=current, grid=grid, grid_compact_names=grid_compact_names,
    )


def render_integration_snapshot(
    snapshot: IntegrationSnapshot,
    *,
    narrow: bool = True,
    compact: bool = False,
    events: Optional[List[TrailEvent]] = None,
    live: Optional[Dict[str, Any]] = None,
    current: Optional[TrailEvent] = None,
    grid: bool = False,
    grid_compact_names: bool = False,
) -> Panel:
    """Render a collected snapshot without reading configuration or workspace files."""
    services_data = list(snapshot.services)
    active_integration = snapshot.active_integration
    table = Table(box=None, show_header=False, expand=True, padding=(0, 1))
    if grid:
        # The wide dashboard places this panel beside other detail panels.
        # Use a compact grid so every configured integration remains visible.
        for column in ("one", "two", "three", "four"):
            table.add_column(column, ratio=1, overflow="ellipsis", no_wrap=True)
        aliases = {
            "GreyNoise": "GreyN",
            "AbuseIPDB": "Abuse",
            "ThreatFox": "ThrtFx",
            "MalBazaar": "MalBzr",
            "Feodo C2": "Feodo",
            "Tor/Proxy": "TorPrx",
            "VulnCheck": "VulnCh",
            "DFIR Rept": "DFIR",
            "FIRST.org": "FIRST",
            "URLhaus": "URLhs",
            "URLScan": "URLScn",
            "OSV.dev": "OSVdev",
        }
        display_items = [
            (
                aliases.get(label, label) if grid_compact_names else label,
                is_set,
                detail,
                label == active_integration,
            )
            for label, is_set, detail, _ in services_data
        ]
        for start in range(0, len(display_items), 4):
            row = [
                Text(
                    f" {label} " if is_active else label,
                    style="bold black on bright_cyan"
                    if is_active
                    else _integration_style(ok, detail),
                )
                for label, ok, detail, is_active in display_items[start : start + 4]
            ]
            row.extend(Text("") for _ in range(4 - len(row)))
            table.add_row(*row)
    elif narrow:
        table.add_column("label", style="dim", width=11, no_wrap=True)
        table.add_column("status", ratio=1, overflow="ellipsis", no_wrap=True)
        table.add_column("metric", justify="right", width=11, no_wrap=True)
        for label, is_set, detail, metric in services_data:
            is_active = (label == active_integration)
            if is_active:
                lbl_style = "bold black on bright_cyan"
                st = Text.assemble(("ACTIVE", "bold black on bright_cyan"), (" · ", "dim"), (detail, "bright_white"))
                m_style = "bold bright_cyan"
            elif is_set:
                lbl_style = "dim"
                st = Text.assemble(("ON", _integration_style(True, detail)), (" · ", "dim"), (detail, "bright_white"))
                m_style = "bright_cyan" if metric != "--" else "dim"
            else:
                lbl_style = "dim"
                st = Text.assemble(("OFF", _integration_style(False, detail)), (" · ", "dim"), (detail, "dim"))
                m_style = "dim"
            table.add_row(Text(label, style=lbl_style), st, Text(metric, style=m_style))
    else:

        def format_item(lbl: str, is_on: bool, det: str, met: str) -> Text:
            is_active = (lbl == active_integration)
            if is_active:
                lbl_style = "bold black on bright_cyan"
                st = "ACTIVE"
                col = "bold black on bright_cyan"
                m_col = "bold bright_cyan"
            else:
                lbl_style = "dim"
                st = "ON" if is_on else "OFF"
                col = _integration_style(is_on, det)
                m_col = "bright_cyan" if is_on and met != "--" else "dim"
            return Text.assemble(
                (f"{lbl:<9}", lbl_style),
                (" ", "default"),
                (st, col),
                (" · ", "dim"),
                (f"{det[:7]:<7}", "bright_white" if is_on else "dim"),
                (" ", "default"),
                (f"{met:>9}", m_col),
            )

        table = Table(box=None, show_header=False, expand=True, padding=(0, 0))
        table.add_column("col1", ratio=1, no_wrap=True)
        table.add_column("col2", ratio=1, no_wrap=True)
        pairs = [
            (services_data[i], services_data[i + 1] if i + 1 < len(services_data) else None)
            for i in range(0, len(services_data), 2)
        ]
        for d1, d2 in pairs:
            if d2:
                table.add_row(format_item(*d1), format_item(*d2))
            else:
                table.add_row(format_item(*d1), Text(""))

    body: Any = table
    if not compact:
        body = _SpareRows(
            table,
            _active_integration_lines(active_integration, services_data, current, events, live, snapshot.traffic),
        )
    return Panel(body, title="[bold bright_cyan]INTEGRATIONS[/]", border_style="bright_magenta", box=box.ROUNDED)


class _SpareRows:
    """``main``, then as many of ``extra`` as fit below it in a height-bounded region.

    With no height bound (printed, not in a layout) only ``main`` renders, so the
    panel is never taller than its integrations.
    """

    def __init__(self, main: Any, extra: List[Text]) -> None:
        self.main, self.extra = main, extra

    def __rich_console__(self, console: Console, options: ConsoleOptions) -> RenderResult:
        lines = console.render_lines(self.main, options.update(height=None), pad=False)
        yield from _as_lines(lines)
        spare = (options.height or 0) - len(lines)
        if spare < 2 or not self.extra:
            return
        yield from _as_lines(console.render_lines(Rule(style="grey35"), options.update(height=None)))
        for line in self.extra[: spare - 1]:
            yield line

    def __rich_measure__(self, console: Console, options: ConsoleOptions) -> Measurement:
        return Measurement.get(console, options, self.main)


def _as_lines(lines: List[List[Segment]]) -> RenderResult:
    for line in lines:
        yield from line
        yield Segment.line()
