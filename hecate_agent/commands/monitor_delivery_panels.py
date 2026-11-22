"""Delivery panels for the live monitor."""

from __future__ import annotations

import logging
import sqlite3
from pathlib import Path
from typing import Any, Dict, List, Optional

from rich import box
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from hecate_agent.commands.monitor_samplers import RunnerStatus, TrailEvent
from hecate_agent.core.sqlite_utils import connect_sqlite_ro


from hecate_agent.commands.monitor_format import _bar

logger = logging.getLogger(__name__)


def _collect_outbound_metrics(workspace: Optional[Path] = None, runner: Optional[RunnerStatus] = None) -> Dict[str, Any]:
    res: Dict[str, Any] = {
        "github_published": 0,
        "github_pending": 0,
        "github_failed": 0,
        "github_latest_hunt": None,
        "github_latest_pr": None,
        "misp_confirmed": 0,
        "misp_pending": 0,
        "misp_failed": 0,
        "misp_latest_hunt": None,
        "misp_target": None,
    }
    if runner:
        res["github_published"] = runner.github_confirmed_promotions or 0
        res["github_pending"] = runner.github_pending_prs or 0
        res["misp_confirmed"] = runner.misp_confirmed_exports or 0
        res["misp_pending"] = runner.misp_pending_exports or 0

    if workspace:
        db_path = workspace / ".hecate" / "publisher" / "promotion-outbox.sqlite3"
        if not db_path.exists():
            db_path = workspace / ".hecate" / "github" / "outbox.sqlite3"
        if db_path.exists():
            try:
                conn = connect_sqlite_ro(db_path, timeout=1.0)
                conn.row_factory = sqlite3.Row
                try:
                    rows = conn.execute("SELECT status, hunt_id, pr_number FROM promotions").fetchall()
                    pub = sum(1 for r in rows if str(r["status"]).lower() in ("published", "merged"))
                    pend = sum(1 for r in rows if str(r["status"]).lower() in ("queued", "publishing", "pending"))
                    fail = sum(1 for r in rows if str(r["status"]).lower() in ("retry", "failed"))
                    res["github_published"] = max(res["github_published"], pub)
                    res["github_pending"] = max(res["github_pending"], pend)
                    res["github_failed"] = fail
                    if rows:
                        res["github_latest_hunt"] = rows[-1]["hunt_id"]
                        if rows[-1]["pr_number"]:
                            res["github_latest_pr"] = f"PR #{rows[-1]['pr_number']}"
                finally:
                    conn.close()
            except sqlite3.Error as exc:
                logger.debug("Failed querying GitHub outbox in monitor: %s", exc)

        misp_db = workspace / ".hecate" / "misp" / "outbox.sqlite3"
        if misp_db.exists():
            try:
                conn = connect_sqlite_ro(misp_db, timeout=1.0)
                conn.row_factory = sqlite3.Row
                try:
                    rows = conn.execute("SELECT status, hunt_id, event_id, target FROM exports").fetchall()
                    conf = sum(1 for r in rows if str(r["status"]).lower() == "confirmed")
                    pend = sum(1 for r in rows if str(r["status"]).lower() in ("queued", "publishing", "pending"))
                    fail = sum(1 for r in rows if str(r["status"]).lower() in ("retry", "failed"))
                    res["misp_confirmed"] = max(res["misp_confirmed"], conf)
                    res["misp_pending"] = max(res["misp_pending"], pend)
                    res["misp_failed"] = fail
                    if rows:
                        res["misp_latest_hunt"] = rows[-1]["hunt_id"]
                        res["misp_target"] = rows[-1]["target"]
                finally:
                    conn.close()
            except sqlite3.Error as exc:
                logger.debug("Failed querying MISP outbox in monitor: %s", exc)

    return res


def _outbound_panel(
    workspace: Optional[Path] = None,
    runner: Optional[RunnerStatus] = None,
    narrow: bool = False,
    compact: bool = False,
) -> Panel:
    """A dedicated panel displaying summary metrics for outbound publication across GitHub and MISP."""
    ob = _collect_outbound_metrics(workspace, runner)

    table = Table(box=None, show_header=False, expand=True, padding=(0, 1))
    table.add_column("label", style="dim", width=11, min_width=10, no_wrap=True)
    table.add_column("value", ratio=1, overflow="ellipsis", no_wrap=True)

    gh_pub = ob["github_published"]
    gh_pend = ob["github_pending"]
    gh_style = "bright_green" if gh_pub > 0 else "dim"
    gh_parts = [(f"{gh_pub} published", gh_style)]
    if gh_pend > 0:
        gh_parts.extend([(" · ", "dim"), (f"{gh_pend} PR pending", "bold bright_yellow")])
    elif ob["github_latest_hunt"]:
        gh_parts.extend([(" · ", "dim"), (f"last: {ob['github_latest_hunt']}", "bright_cyan")])
    else:
        gh_parts.extend([(" · ", "dim"), ("0 pending", "dim")])
    table.add_row("GITHUB", Text.assemble(*gh_parts))

    misp_conf = ob["misp_confirmed"]
    misp_pend = ob["misp_pending"]
    misp_style = "bright_green" if misp_conf > 0 else "dim"
    misp_parts = [(f"{misp_conf} confirmed", misp_style)]
    if misp_pend > 0:
        misp_parts.extend([(" · ", "dim"), (f"{misp_pend} pending", "bold bright_yellow")])
    elif ob["misp_latest_hunt"]:
        misp_parts.extend([(" · ", "dim"), (f"last: {ob['misp_latest_hunt']}", "bright_cyan")])
    else:
        misp_parts.extend([(" · ", "dim"), ("0 pending", "dim")])
    table.add_row("MISP", Text.assemble(*misp_parts))

    total_pend = gh_pend + misp_pend
    if total_pend > 0:
        sync_txt = f"{total_pend} outbound queued"
        sync_style = "bold bright_yellow"
    elif gh_pub > 0 or misp_conf > 0:
        sync_txt = "all destinations synced"
        sync_style = "bold bright_green"
    else:
        sync_txt = "standby · ready"
        sync_style = "dim"
    table.add_row("STATUS", Text(sync_txt, style=sync_style))

    return Panel(
        table,
        title="[bold bright_cyan]OUTBOUND[/]",
        border_style="bright_magenta",
        box=box.ROUNDED,
    )


def _cti_feeds_panel(workspace: Path, events: List[TrailEvent]) -> Panel:
    table = Table(box=box.SIMPLE, expand=True, show_header=True, header_style="bold bright_cyan", padding=(0, 1))
    table.add_column("FEED SOURCE", width=16, style="bright_cyan")
    table.add_column("CATEGORY", width=18, style="dim")
    table.add_column("LAST INTAKE", width=12, style="dim")
    table.add_column("ACTIVITY TODAY", ratio=1, overflow="ellipsis", no_wrap=True)
    table.add_column("STATUS", width=10)

    feeds = [
        ("cisa_kev", "CISA KEV", "Exploited Vulns"),
        ("otx", "Abuse.ch OTX", "Threat Pulses"),
        ("threatfox", "ThreatFox", "Threat Indicators"),
        ("malwarebazaar", "MalwareBazaar", "Malware Hashes"),
        ("shadowserver", "Shadowserver", "C2 Infrastructure"),
        ("misp", "MISP Inbound", "Community Events"),
        ("cisa_advisories", "CISA Advisories", "Alerts & ICS"),
        ("github_poc", "GitHub PoC", "Exploit Advisories"),
        ("rss", "Threat RSS", "Security Blogs"),
        ("certstream", "CertStream", "Live TLS Stream"),
    ]

    for key, name, category in feeds:
        last_time = "--"
        activity = "Standby"
        status = "STANDBY"
        status_style = "dim"

        for e in reversed(events):
            if key in e.message.lower() or (e.stage == "intake" and key in e.message.lower()):
                last_time = e.timestamp[-8:]
                status = "ACTIVE"
                status_style = "bold bright_green"
                activity = e.message[:55]
                break

        table.add_row(name, category, last_time, activity, Text(status, style=status_style))

    return Panel(
        table,
        title="[bold bright_cyan]INBOUND CTI FEEDS & POLLER STATUS[/]",
        border_style="bright_magenta",
        box=box.ROUNDED,
    )


def _ingestion_funnel_panel(events: List[TrailEvent], runner: RunnerStatus) -> Panel:
    table = Table(box=box.SIMPLE, expand=True, show_header=True, header_style="bold bright_cyan", padding=(0, 1))
    table.add_column("PIPELINE FUNNEL STAGE", width=24, style="bright_cyan")
    table.add_column("COUNT", width=8, justify="right", style="bold bright_white")
    table.add_column("PROGRESS / CONVERSION", ratio=1)

    intake_count = sum(1 for e in events if e.stage == "intake" or "intake:" in e.message)
    triage_count = sum(1 for e in events if e.stage == "triage" and "pass" in e.message)
    hypothesis_count = sum(1 for e in events if e.stage == "hypothesis" or "hypothesis:" in e.message)
    draft_count = runner.drafts_today or sum(1 for e in events if "draft_created" in e.message or "draft_written" in e.message)
    promoted_count = runner.github_confirmed_promotions

    base = max(intake_count, 1)
    stages = [
        ("1. Raw CTI Ingested", intake_count, 100.0 if intake_count else 0.0),
        ("2. Triage Validated", triage_count, (triage_count / base * 100.0)),
        ("3. Hypotheses Formed", hypothesis_count, (hypothesis_count / base * 100.0)),
        ("4. Drafts Created", draft_count, (draft_count / base * 100.0)),
        ("5. Hunts Published", promoted_count, (promoted_count / base * 100.0)),
    ]

    for label, cnt, pct in stages:
        bar = _bar(pct, width=16).plain
        table.add_row(label, str(cnt), f"[{bar}] {pct:.1f}%")

    if runner.parked_reasons:
        p_str = ", ".join(f"{cnt} {k}" for k, cnt in sorted(runner.parked_reasons.items())[:3])
        table.add_row("PARKED ITEMS QUEUE", str(runner.parked_items or 0), f"Reasons: {p_str}")

    return Panel(
        table,
        title="[bold bright_cyan]CTI INGESTION FUNNEL & CONVERSION (TODAY)[/]",
        border_style="bright_magenta",
        box=box.ROUNDED,
    )


def _github_outbox_panel(workspace: Path) -> Panel:
    table = Table(box=box.SIMPLE, expand=True, show_header=True, header_style="bold bright_cyan", padding=(0, 1))
    table.add_column("ID", width=4, style="dim")
    table.add_column("HUNT", width=8, style="bright_cyan")
    table.add_column("STATUS", width=11)
    table.add_column("PR / BRANCH", ratio=1, overflow="ellipsis", no_wrap=True)
    table.add_column("UPDATED", width=9, style="dim")

    db_path = workspace / ".hecate" / "publisher" / "promotion-outbox.sqlite3"
    if not db_path.exists():
        db_path = workspace / ".hecate" / "github" / "outbox.sqlite3"

    rows = []
    if db_path.exists():
        try:
            conn = connect_sqlite_ro(db_path, timeout=2.0)
            conn.row_factory = sqlite3.Row
            try:
                rows = conn.execute("SELECT * FROM promotions ORDER BY id DESC LIMIT 8").fetchall()
            finally:
                conn.close()
        except sqlite3.Error as exc:
            logger.debug("Failed querying GitHub promotions outbox in monitor: %s", exc)

    for r in rows:
        st = str(r["status"]).lower()
        if st in ("published", "merged"):
            st_style = "bold bright_green"
        elif st in ("queued", "publishing"):
            st_style = "bold bright_yellow"
        elif st == "retry":
            st_style = "bold red"
        else:
            st_style = "bright_white"

        pr = f"PR #{r['pr_number']}" if r["pr_number"] else str(r["branch"] or "--")
        upd = str(r["updated_at"] or "")[-14:-6] if r["updated_at"] else "--"
        table.add_row(str(r["id"]), str(r["hunt_id"]), Text(st.upper(), style=st_style), pr, upd)

    if not rows:
        table.add_row("--", "--", "EMPTY", "No promotions in GitHub outbox", "--")

    return Panel(
        table,
        title="[bold bright_cyan]GITHUB PROMOTION OUTBOX[/]",
        border_style="bright_magenta",
        box=box.ROUNDED,
    )


def _misp_outbox_panel(workspace: Path) -> Panel:
    table = Table(box=box.SIMPLE, expand=True, show_header=True, header_style="bold bright_cyan", padding=(0, 1))
    table.add_column("HUNT", width=8, style="bright_cyan")
    table.add_column("EVENT ID", width=10, style="dim")
    table.add_column("STATUS", width=11)
    table.add_column("TARGET", ratio=1, overflow="ellipsis", no_wrap=True)
    table.add_column("CONFIRMED", width=12, style="dim")

    db_path = workspace / ".hecate" / "misp" / "outbox.sqlite3"
    rows = []
    if db_path.exists():
        try:
            conn = connect_sqlite_ro(db_path, timeout=2.0)
            conn.row_factory = sqlite3.Row
            try:
                rows = conn.execute("SELECT * FROM exports ORDER BY next_attempt DESC LIMIT 8").fetchall()
            finally:
                conn.close()
        except sqlite3.Error as exc:
            logger.debug("Failed querying MISP exports outbox in monitor: %s", exc)

    for r in rows:
        st = str(r["status"]).lower()
        st_style = (
            "bold bright_green"
            if st == "confirmed"
            else "bold bright_yellow"
            if st in ("queued", "publishing")
            else "bold red"
        )
        conf = str(r["confirmed_at"] or "")[:10] if r["confirmed_at"] else "--"
        table.add_row(
            str(r["hunt_id"]),
            str(r["event_id"] or "--"),
            Text(st.upper(), style=st_style),
            str(r["target"]),
            conf,
        )

    if not rows:
        table.add_row("--", "--", "EMPTY", "No exports in MISP outbox", "--")

    return Panel(
        table,
        title="[bold bright_cyan]MISP EXPORT OUTBOX[/]",
        border_style="bright_magenta",
        box=box.ROUNDED,
    )
