"""Collection/rendering boundaries and terminal-size coverage for the monitor."""

import io
import json
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

import pytest
from rich.console import Console
from rich.layout import Layout

from hecate_agent.commands import monitor_views
from hecate_agent.commands.monitor_integration_status import collect_integration_snapshot
from hecate_agent.commands.monitor_integrations import render_integration_snapshot
from hecate_agent.commands.monitor_samplers import HostSample, RunnerStatus, TrailEvent
from hecate_agent.integration_registry import STATUS_INTEGRATIONS


def test_snapshot_preserves_recent_enrichment_without_exposing_credentials(tmp_path, monkeypatch):
    secret = "fixture-private-api-key"
    monkeypatch.setenv("VT_API_KEY", secret)
    checks = tmp_path / ".hecate" / "integrations"
    checks.mkdir(parents=True)
    (checks / "vt.json").write_text(
        json.dumps(
            {
                "healthy": True,
                "enabled": True,
                "checked_at": datetime.now(timezone.utc).isoformat(),
            }
        )
    )
    events = [
        TrailEvent("2026-11-22 12:00:00", "old", 1, "enrichment", "7 observable(s)"),
        TrailEvent("2026-11-22 12:01:00", "new", 1, "done", "empty_queue"),
    ]
    snapshot = collect_integration_snapshot(tmp_path, events=events)
    vt = next(row for row in snapshot.services if row.label == "VT")
    assert vt.healthy and vt.metric == "7 checked"
    assert secret not in repr(snapshot)


@pytest.mark.parametrize(
    "grid,narrow,compact", [(True, True, False), (False, True, False), (False, False, False), (False, False, True)]
)
def test_collected_snapshot_renders_without_workspace_reads(tmp_path, grid, narrow, compact):
    snapshot = collect_integration_snapshot(tmp_path)
    output = io.StringIO()
    console = Console(file=output, width=160, height=90, color_system=None)
    with (
        patch.object(Path, "read_text", side_effect=AssertionError("renderer read a file")),
        patch.object(Path, "open", side_effect=AssertionError("renderer opened a file")),
    ):
        console.print(Layout(render_integration_snapshot(snapshot, grid=grid, narrow=narrow, compact=compact)))
    assert "INTEGRATIONS" in output.getvalue()
    assert "VT" in output.getvalue()


@pytest.mark.parametrize("configured", [True, False])
@pytest.mark.parametrize("narrow", [True, False])
def test_every_registry_status_has_metrics(tmp_path, monkeypatch, configured, narrow):
    for item in STATUS_INTEGRATIONS:
        for name in item.env_keys:
            if configured:
                monkeypatch.setenv(name, "fixture-configured")
            else:
                monkeypatch.delenv(name, raising=False)
    snapshot = collect_integration_snapshot(tmp_path, narrow=narrow)
    assert {item.label for item in STATUS_INTEGRATIONS} <= {row.label for row in snapshot.services}
    assert all(isinstance(row.detail, str) and isinstance(row.metric, str) for row in snapshot.services)


@pytest.mark.parametrize("width,height", [(60, 24), (100, 39), (120, 40), (160, 60), (240, 80)])
@pytest.mark.parametrize("tab", [1, 2, 3, 4, 5])
def test_dashboard_tabs_render_across_terminal_sizes(tmp_path, monkeypatch, width, height, tab):
    output = io.StringIO()
    console = Console(file=output, width=width, height=height, color_system=None)
    monkeypatch.setattr(monitor_views, "console", console)
    now = datetime(2026, 11, 22, 12, 0)
    events = [TrailEvent("2026-11-22 12:00:00", "abcd", 0, "done", "empty_queue")]
    layout = monitor_views._render_dashboard(tmp_path, events, {}, HostSample(None, None, None, []), now, RunnerStatus(), active_tab=tab)
    console.print(layout)
    rendered = output.getvalue()
    assert "HECATE" in rendered
    assert len(rendered.splitlines()) == height
    assert all(len(line) <= width for line in rendered.splitlines())
