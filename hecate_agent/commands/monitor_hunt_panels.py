"""Hunt panels for the live monitor."""

from __future__ import annotations

from pathlib import Path
from typing import List, Optional

import yaml
from rich import box
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from hecate_agent.commands.monitor_metrics import (
    HuntsMetrics,
    PurpleTeamMetrics,
    SiemDriftMetrics,
    _collect_hunts_metrics,
    _collect_purple_team_metrics,
    _collect_siem_drift_metrics,
)
from hecate_agent.commands.monitor_samplers import RunnerStatus, TrailEvent


def _hunts_panel(
    workspace: Optional[Path] = None,
    narrow: bool = True,
    compact: bool = False,
    metrics: Optional[HuntsMetrics] = None,
) -> Panel:
    """A combined panel displaying summary metrics for hunts, threat observables, and factual grounding fidelity."""
    h_metrics = metrics or _collect_hunts_metrics(workspace)

    table = Table(box=None, show_header=False, expand=True, padding=(0, 1))
    table.add_column("label", style="dim", width=11, min_width=10, no_wrap=True)
    table.add_column("value", ratio=1, overflow="ellipsis", no_wrap=True)

    if (
        h_metrics.total_hunts == 0
        and h_metrics.network_total == 0
        and h_metrics.host_total == 0
        and h_metrics.threats_count == 0
    ):
        table.add_row("HUNTS", Text("0 generated · standby", style="dim"))
        table.add_row("THREATS", Text("0 tracked", style="dim"))
        table.add_row("NETWORK", Text("0 IOCs · standby", style="dim"))
        table.add_row("ENDPOINT", Text("0 IOCs · standby", style="dim"))
        if not compact:
            table.add_row("FIDELITY", Text("100% target · 0 unsupp", style="dim"))
    else:
        if h_metrics.total_hunts > 0:
            hunts_text = f"{h_metrics.total_hunts} total"
            hunts_sub = (
                f"{h_metrics.drafts_count} drafts"
                if not h_metrics.completed_count
                else f"{h_metrics.drafts_count} drf · {h_metrics.completed_count} done"
            )
            hunts_parts = [(hunts_text, "bright_white"), (" · ", "dim"), (hunts_sub, "bright_cyan")]
            table.add_row("HUNTS", Text.assemble(*hunts_parts))
        else:
            table.add_row("HUNTS", Text("0 generated · standby", style="dim"))

        threats_val = f"{h_metrics.threats_count} threats" if not narrow else f"{h_metrics.threats_count}"
        threats_sub = f"{h_metrics.actors_count} act, {h_metrics.campaigns_count} camp, {h_metrics.malware_count} mal"
        table.add_row(
            "THREATS",
            Text.assemble((threats_val, "bright_white"), (" · ", "dim"), (threats_sub, "bright_cyan")),
        )

        net_str = f"{h_metrics.network_total:,} IOCs"
        net_sub = f"{h_metrics.network_ips} IP, {h_metrics.network_domains} dom"
        if h_metrics.network_urls and not narrow:
            net_sub += f", {h_metrics.network_urls} url"
        table.add_row(
            "NETWORK",
            Text.assemble((net_str, "bright_white"), (" · ", "dim"), (net_sub, "bright_cyan")),
        )

        host_str = f"{h_metrics.host_total:,} IOCs"
        host_sub = f"{h_metrics.host_hashes} hash, {h_metrics.host_paths} path"
        table.add_row(
            "ENDPOINT",
            Text.assemble((host_str, "bright_white"), (" · ", "dim"), (host_sub, "bright_cyan")),
        )

        if not compact and (h_metrics.fingerprints_count > 0 or h_metrics.cloud_ops_count > 0):
            infra_str = f"{h_metrics.fingerprints_count} JA4/JARM" if h_metrics.fingerprints_count else "JA4 standby"
            cloud_sub = f"{h_metrics.cloud_ops_count} cloud/k8s" if h_metrics.cloud_ops_count else "cloud ready"
            table.add_row(
                "INFRA/CLOUD",
                Text.assemble((infra_str, "bright_white"), (" · ", "dim"), (cloud_sub, "bright_cyan")),
            )

        if not compact:
            unsupp_style = "bold bright_red" if h_metrics.grounding_unsupported > 0 else "dim"
            table.add_row(
                "FIDELITY",
                Text.assemble(
                    (f"{h_metrics.grounding_asserted} asrt", "bright_green"),
                    (" · ", "dim"),
                    (f"{h_metrics.grounding_derived} drv", "bright_cyan"),
                    (" · ", "dim"),
                    (f"{h_metrics.grounding_unsupported} unsupp", unsupp_style),
                ),
            )

    return Panel(
        table,
        title="[bold bright_cyan]HUNTS[/]",
        border_style="bright_magenta",
        box=box.ROUNDED,
    )


def _hunts_summary_panel(
    workspace: Optional[Path] = None,
    narrow: bool = True,
    compact: bool = False,
    metrics: Optional[HuntsMetrics] = None,
) -> Panel:
    return _hunts_panel(workspace=workspace, narrow=narrow, compact=compact, metrics=metrics)


def _mitre_metrics_panel(
    workspace: Optional[Path] = None,
    narrow: bool = False,
    compact: bool = False,
    metrics: Optional[HuntsMetrics] = None,
    detailed: bool = False,
    col_width: Optional[int] = None,
) -> Panel:
    """A dedicated panel displaying MITRE ATT&CK Enterprise, Cloud, and Container coverage metrics."""
    h_metrics = metrics or _collect_hunts_metrics(workspace)

    table = Table(box=None, show_header=False, expand=True, padding=(0, 1))
    table.add_column("label", style="dim", width=11, min_width=10, no_wrap=True)
    table.add_column("value", ratio=1, overflow="ellipsis", no_wrap=True)

    ent = h_metrics.enterprise_ttps or {}
    cloud = h_metrics.cloud_ttps or {}
    containers = h_metrics.containers_ttps or {}

    ent_total = h_metrics.enterprise_total or sum(ent.values())
    cloud_total = h_metrics.cloud_total or sum(cloud.values())
    container_total = h_metrics.containers_total or sum(containers.values())

    cloud_tactics = sum(v > 0 for v in cloud.values())
    container_tactics = sum(v > 0 for v in containers.values())

    recon = ent.get("reconnaissance", 0)
    resdev = ent.get("resource-development", 0)
    initacc = ent.get("initial-access", 0)
    exec_cnt = ent.get("execution", 0)
    persist = ent.get("persistence", 0)
    privesc = ent.get("privilege-escalation", 0)
    stealth = ent.get("stealth", 0)
    defimp = ent.get("defense-impairment", 0)
    credacc = ent.get("credential-access", 0)
    disc = ent.get("discovery", 0)
    latmove = ent.get("lateral-movement", 0)
    collect = ent.get("collection", 0)
    c2 = ent.get("command-and-control", 0)
    exfil = ent.get("exfiltration", 0)
    impact = ent.get("impact", 0)

    active_tactics = sum(1 for v in ent.values() if v > 0)

    if detailed:
        table = Table(box=None, show_header=False, expand=True, padding=(0, 0))
        table.add_column("tactic", ratio=1, min_width=20, no_wrap=True, overflow="ellipsis")
        metric_w = col_width if col_width is not None else 6
        for name in ("TTPs", "IOCs", "Hunts", "Rules"):
            table.add_column(name, width=metric_w, justify="right", no_wrap=True)
        table.add_row(
            Text(f"ENTERPRISE ({active_tactics} / 15 tactics) ({ent_total} Unique TTPs)", style="bold bright_cyan"),
            *(Text(label, style="bold bright_cyan") for label in ("TTPs", "IOCs", "Hunts", "Rules")),
        )
        for tactic, label in (
            ("reconnaissance", "Reconnaissance"),
            ("resource-development", "Resource Development"),
            ("initial-access", "Initial Access"),
            ("execution", "Execution"),
            ("persistence", "Persistence"),
            ("privilege-escalation", "Privilege Escalation"),
            ("stealth", "Stealth"),
            ("defense-impairment", "Defense Impairment"),
            ("credential-access", "Credential Access"),
            ("discovery", "Discovery"),
            ("lateral-movement", "Lateral Movement"),
            ("collection", "Collection"),
            ("command-and-control", "Command and Control"),
            ("exfiltration", "Exfiltration"),
            ("impact", "Impact"),
        ):
            count = ent.get(tactic, 0)
            iocs = h_metrics.tactic_iocs.get("enterprise", {}).get(tactic, 0)
            hunts = h_metrics.tactic_hunts.get("enterprise", {}).get(tactic, 0)
            rules = h_metrics.tactic_rules.get("enterprise", {}).get(tactic, 0)
            table.add_row(
                Text(label, style="dim"),
                Text(str(count), style="bright_white" if count else "dim"),
                Text(str(iocs), style="bright_cyan" if iocs else "dim"),
                Text(str(hunts), style="bright_cyan" if hunts else "dim"),
                Text(str(rules), style="bright_green" if rules else "dim"),
            )
        table.add_row(
            Text(f"CLOUD ({cloud_tactics} / 12 tactics) ({cloud_total} Unique TTPs)", style="bright_cyan"),
            Text(str(cloud_total), style="bright_cyan"),
            Text(str(h_metrics.matrix_iocs.get("cloud", 0)), style="bright_cyan"),
            Text(str(h_metrics.matrix_hunts.get("cloud", 0)), style="bright_cyan"),
            Text(str(h_metrics.matrix_rules.get("cloud", 0)), style="bright_cyan"),
        )
        table.add_row(
            Text(f"CONTAINERS ({container_tactics} / 10 tactics) ({container_total} Unique TTPs)", style="bright_cyan"),
            Text(str(container_total), style="bright_cyan"),
            Text(str(h_metrics.matrix_iocs.get("containers", 0)), style="bright_cyan"),
            Text(str(h_metrics.matrix_hunts.get("containers", 0)), style="bright_cyan"),
            Text(str(h_metrics.matrix_rules.get("containers", 0)), style="bright_cyan"),
        )
    elif compact:
        if ent_total == 0 and h_metrics.ttps_count == 0:
            table.add_row("ENTERPRISE", Text("(0 / 15 tactics) (0 Unique TTPs)", style="dim"))
            table.add_row(" Ingress", Text("Recon 0 · ResDev 0 · InitAcc 0", style="dim"))
            table.add_row(" Execution", Text("Exec 0 · Persist 0 · PrivEsc 0", style="dim"))
            table.add_row(" Defense", Text("Stealth 0 · DefImp 0 · CredAcc 0", style="dim"))
            table.add_row(" Actions", Text("Disc 0 · C2 0 · Impact 0", style="dim"))
            table.add_row("CLOUD & K8S", Text("(0/12) (0 TTPs) · (0/10) (0 TTPs)", style="dim"))
        else:
            table.add_row(
                "ENTERPRISE",
                Text(f"({active_tactics} / 15 tactics) ({ent_total} Unique TTPs)", style="bright_white"),
            )
            table.add_row(
                " Ingress",
                Text.assemble(
                    ("Recon ", "dim"),
                    (str(recon), "bright_white"),
                    (" · ", "dim"),
                    ("ResDev ", "dim"),
                    (str(resdev), "bright_white"),
                    (" · ", "dim"),
                    ("InitAcc ", "dim"),
                    (str(initacc), "bright_white"),
                ),
            )
            table.add_row(
                " Execution",
                Text.assemble(
                    ("Exec ", "dim"),
                    (str(exec_cnt), "bright_white"),
                    (" · ", "dim"),
                    ("Persist ", "dim"),
                    (str(persist), "bright_white"),
                    (" · ", "dim"),
                    ("PrivEsc ", "dim"),
                    (str(privesc), "bright_white"),
                ),
            )
            table.add_row(
                " Defense",
                Text.assemble(
                    ("Stealth ", "dim"),
                    (str(stealth), "bright_white"),
                    (" · ", "dim"),
                    ("DefImp ", "dim"),
                    (str(defimp), "bright_white"),
                    (" · ", "dim"),
                    ("CredAcc ", "dim"),
                    (str(credacc), "bright_white"),
                ),
            )
            table.add_row(
                " Actions",
                Text.assemble(
                    ("Disc ", "dim"),
                    (str(disc), "bright_white"),
                    (" · ", "dim"),
                    ("C2 ", "dim"),
                    (str(c2), "bright_white"),
                    (" · ", "dim"),
                    ("Impact ", "dim"),
                    (str(impact), "bright_white"),
                ),
            )
            cloud_str = f"Cloud ({cloud_tactics}/12) ({cloud_total} Unique TTPs)"
            k8s_str = f"K8s ({container_tactics}/10) ({container_total} Unique TTPs)"
            table.add_row(
                "CLOUD & K8S",
                Text.assemble(
                    (cloud_str, "bright_cyan" if cloud_total else "dim"),
                    (" · ", "dim"),
                    (k8s_str, "bright_cyan" if container_total else "dim"),
                ),
            )
    else:
        if ent_total == 0 and h_metrics.ttps_count == 0:
            table.add_row("ENTERPRISE", Text("(0 / 15 tactics) (0 Unique TTPs)", style="dim"))
            table.add_row(" Pre-Attack", Text("Recon 0 · ResDev 0", style="dim"))
            table.add_row(" Initial", Text("InitAcc 0 · Exec 0", style="dim"))
            table.add_row(" Persist", Text("Persist 0 · PrivEsc 0", style="dim"))
            table.add_row(" Defense", Text("Stealth 0 · DefImp 0", style="dim"))
            table.add_row(" Discovery", Text("Disc 0 · CredAcc 0", style="dim"))
            table.add_row(" Movement", Text("LatMove 0 · Collect 0", style="dim"))
            table.add_row(" Actions", Text("C2 0 · Exfil 0 · Impact 0", style="dim"))
            table.add_row("CLOUD", Text("(0 / 12 tactics) (0 Unique TTPs)", style="dim"))
            table.add_row("CONTAINERS", Text("(0 / 10 tactics) (0 Unique TTPs)", style="dim"))
        else:
            table.add_row(
                "ENTERPRISE",
                Text(f"({active_tactics} / 15 tactics) ({ent_total} Unique TTPs)", style="bright_white"),
            )
            table.add_row(
                " Pre-Attack",
                Text.assemble(
                    ("Recon ", "dim"),
                    (str(recon), "bright_white"),
                    (" · ", "dim"),
                    ("ResDev ", "dim"),
                    (str(resdev), "bright_white"),
                ),
            )
            table.add_row(
                " Initial",
                Text.assemble(
                    ("InitAcc ", "dim"),
                    (str(initacc), "bright_white"),
                    (" · ", "dim"),
                    ("Exec ", "dim"),
                    (str(exec_cnt), "bright_white"),
                ),
            )
            table.add_row(
                " Persist",
                Text.assemble(
                    ("Persist ", "dim"),
                    (str(persist), "bright_white"),
                    (" · ", "dim"),
                    ("PrivEsc ", "dim"),
                    (str(privesc), "bright_white"),
                ),
            )
            table.add_row(
                " Defense",
                Text.assemble(
                    ("Stealth ", "dim"),
                    (str(stealth), "bright_white"),
                    (" · ", "dim"),
                    ("DefImp ", "dim"),
                    (str(defimp), "bright_white"),
                ),
            )
            table.add_row(
                " Discovery",
                Text.assemble(
                    ("Disc ", "dim"),
                    (str(disc), "bright_white"),
                    (" · ", "dim"),
                    ("CredAcc ", "dim"),
                    (str(credacc), "bright_white"),
                ),
            )
            table.add_row(
                " Movement",
                Text.assemble(
                    ("LatMove ", "dim"),
                    (str(latmove), "bright_white"),
                    (" · ", "dim"),
                    ("Collect ", "dim"),
                    (str(collect), "bright_white"),
                ),
            )
            table.add_row(
                " Actions",
                Text.assemble(
                    ("C2 ", "dim"),
                    (str(c2), "bright_white"),
                    (" · ", "dim"),
                    ("Exfil ", "dim"),
                    (str(exfil), "bright_white"),
                    (" · ", "dim"),
                    ("Impact ", "dim"),
                    (str(impact), "bright_white"),
                ),
            )

            table.add_row(
                "CLOUD",
                Text(
                    f"({cloud_tactics} / 12 tactics) ({cloud_total} Unique TTPs)",
                    style="bright_cyan" if cloud_total else "dim",
                ),
            )

            table.add_row(
                "CONTAINERS",
                Text(
                    f"({container_tactics} / 10 tactics) ({container_total} Unique TTPs)",
                    style="bright_cyan" if container_total else "dim",
                ),
            )

    return Panel(
        table,
        title="[bold bright_cyan]MITRE[/]",
        subtitle=None,
        border_style="bright_magenta",
        box=box.ROUNDED,
    )


def _detections_panel(
    workspace: Optional[Path] = None,
    metrics: Optional[HuntsMetrics] = None,
    runner: Optional[RunnerStatus] = None,
    events: Optional[List[TrailEvent]] = None,
    purple_metrics: Optional[PurpleTeamMetrics] = None,
    siem_metrics: Optional[SiemDriftMetrics] = None,
    narrow: bool = False,
    compact: bool = False,
) -> Panel:
    """A combined panel displaying Sigma detection rules, SIEM query targets, rule tests, self-tuning, and BAS simulation."""
    h_metrics = metrics or _collect_hunts_metrics(workspace)
    p_metrics = purple_metrics or _collect_purple_team_metrics(workspace, events)
    siem_m = siem_metrics or _collect_siem_drift_metrics(workspace)
    q_prov = runner.query_provider if runner and runner.query_provider else "mock"
    pending = runner.pending_queries if runner else None

    table = Table(box=None, show_header=False, expand=True, padding=(0, 1))
    table.add_column("label", style="dim", width=11, min_width=10, no_wrap=True)
    table.add_column("value", ratio=1, overflow="ellipsis", no_wrap=True)

    rules_cnt = h_metrics.sigma_rules_count
    rules_str = f"{rules_cnt:,} rules" if rules_cnt else "0 rules drafted"
    table.add_row("RULES", Text(rules_str, style="bright_white"))

    pending_str = f"{pending} pending" if pending else "0 pending"
    pending_style = "bold bright_yellow" if pending else "bright_white"
    table.add_row(
        "SIEM QUERY",
        Text.assemble(
            (f"{q_prov.upper()} backend", "bright_white"),
            (" · ", "dim"),
            (pending_str, pending_style),
        ),
    )

    if siem_m.total_queries > 0:
        if siem_m.drifted_count > 0:
            sync_style = "bold bright_red"
            sync_sub = f"{siem_m.drifted_count} drifted"
        elif siem_m.missing_count > 0 or siem_m.error_count > 0:
            sync_style = "bold bright_yellow"
            sync_sub = f"{siem_m.missing_count} missing"
        else:
            sync_style = "bright_green"
            sync_sub = "100% in sync"
        table.add_row(
            "SIEM SYNC",
            Text.assemble(
                (f"{siem_m.in_sync_count}/{siem_m.total_queries} queries", "bright_white"),
                (" · ", "dim"),
                (sync_sub, sync_style),
            ),
        )

    active_val = p_metrics.validated_rules > 0 or p_metrics.bas_runs > 0
    test_sub = f"{p_metrics.hunts_validated} hunts"
    table.add_row(
        "RULE TESTS",
        Text.assemble(
            (f"{p_metrics.validated_rules} rules tested", "bright_white" if active_val else "dim"),
            (" · ", "dim"),
            (test_sub, "bright_cyan" if active_val else "dim"),
        ),
    )

    if not compact and p_metrics.validated_rules > 0:
        table.add_row(
            "PRECISION",
            Text.assemble(
                (f"{p_metrics.precision_rate:.0%} rule precision", "bright_green"),
                (" · ", "dim"),
                (f"{p_metrics.false_positive_count} FP", "bright_white"),
            ),
        )

    table.add_row(
        "SELF-TUNING",
        Text.assemble(
            (f"{p_metrics.tuned_rules} tuned", "bright_cyan" if active_val else "dim"),
            (" · ", "dim"),
            (f"{p_metrics.false_positive_count} FP", "bright_white" if active_val else "dim"),
        ),
    )

    bas_runs = p_metrics.bas_runs
    bas_sub = f"{p_metrics.bas_verified} verified · {p_metrics.bas_detection_misses} missed"
    table.add_row(
        "BREACH SIM",
        Text.assemble(
            (f"{bas_runs} runs", "bright_white" if bas_runs else "dim"),
            (" · ", "dim"),
            (bas_sub if bas_runs else "standby", "bright_cyan" if bas_runs else "dim"),
        ),
    )

    if not compact and (p_metrics.bas_telemetry_missing or p_metrics.bas_failures):
        gap_style = "bright_red"
        table.add_row(
            "BAS GAPS",
            Text(f"{p_metrics.bas_telemetry_missing} sensor gaps · {p_metrics.bas_failures} failed", style=gap_style),
        )

    return Panel(
        table,
        title="[bold bright_cyan]DETECTIONS[/]",
        border_style="bright_magenta",
        box=box.ROUNDED,
    )


def _purple_team_panel(
    workspace: Optional[Path] = None,
    events: Optional[List[TrailEvent]] = None,
    narrow: bool = True,
    compact: bool = False,
    metrics: Optional[PurpleTeamMetrics] = None,
) -> Panel:
    """Show rule replay and breach-and-attack simulation in one validation panel."""
    measured = metrics or _collect_purple_team_metrics(workspace, events)
    table = Table(box=None, show_header=False, expand=True, padding=(0, 1))
    table.add_column("label", style="dim", width=11, min_width=11, no_wrap=True)
    table.add_column("value", ratio=1, overflow="ellipsis", no_wrap=True)
    active = measured.validated_rules > 0 or measured.bas_runs > 0
    table.add_row("STATUS", Text("ACTIVE" if active else "STANDBY", style="bold bright_green" if active else "dim"))
    rules = f"{measured.validated_rules} rules" if compact else f"{measured.validated_rules} rules tested"
    table.add_row("RULE TESTS", Text(f"{rules} · {measured.hunts_validated} hunts", style="bright_white" if active else "dim"))
    tuned = f"{measured.tuned_rules} tuned" if compact else f"{measured.tuned_rules} logic re-tuned"
    table.add_row(
        "SELF-TUNING", Text(f"{tuned} · {measured.false_positive_count} FP", style="bright_cyan" if active else "dim")
    )
    if not compact:
        precision = f"{measured.precision_rate:.0%} precision" if measured.validated_rules else "awaiting rule results"
        table.add_row("PRECISION", Text(precision, style="bright_green" if measured.validated_rules else "dim"))
    if measured.bas_mode_label:
        table.add_row("BAS MODE", Text(measured.bas_mode_label, style="bright_cyan"))
    if measured.bas_scope_label:
        table.add_row("BAS SCOPE", Text(measured.bas_scope_label, style="dim"))
        table.add_row(
            "BAS CHECKS",
            Text(
                f"{measured.bas_runs - measured.bas_control_runs} hunt checks · {measured.bas_control_runs} sensor controls",
                style="dim",
            ),
        )
    table.add_row(
        "BREACH SIM",
        Text(
            f"{measured.bas_runs} runs · {measured.bas_live_runs} live, {measured.bas_mock_runs} mock",
            style="bright_white" if measured.bas_runs else "dim",
        ),
    )
    table.add_row(
        "ATTACKS",
        Text(
            f"{measured.bas_techniques} techniques · {measured.bas_detections} "
            + ("rule matches" if measured.bas_scope_label else "detections"),
            style="bright_cyan" if measured.bas_runs else "dim",
        ),
    )
    table.add_row(
        "BAS RESULTS",
        Text(
            f"{measured.bas_verified} verified · {measured.bas_detection_misses} missed",
            style="bright_white" if measured.bas_runs else "dim",
        ),
    )
    if measured.bas_simulation_matches or measured.bas_query_matches or measured.bas_smoke_matches:
        table.add_row(
            "OTHER MATCHES",
            Text(
                f"{measured.bas_simulation_matches} synthetic · {measured.bas_query_matches} query · {measured.bas_smoke_matches} smoke",
                style="bright_yellow",
            ),
        )
    if measured.bas_last_detection_latency_sec > 0.0 or measured.bas_siem_verified > 0:
        table.add_row(
            "SIEM ALERTS",
            Text(
                f"{measured.bas_siem_verified} live fired · {measured.bas_last_detection_latency_sec:.3f}s latency",
                style="bright_green",
            ),
        )
    if not compact:
        gap_style = "bright_red" if measured.bas_telemetry_missing or measured.bas_failures else "dim"
        table.add_row(
            "BAS GAPS", Text(f"{measured.bas_telemetry_missing} sensor gaps · {measured.bas_failures} failed", style=gap_style)
        )
        table.add_row(
            "BAS SENSORS",
            Text(
                f"{measured.bas_telemetry_runs}/{measured.bas_runs} observed · {measured.bas_matched_events} events",
                style="bright_white" if measured.bas_runs else "dim",
            ),
        )
        if measured.bas_skipped:
            table.add_row("BAS SKIPPED", Text(f"{measured.bas_skipped} · {measured.bas_last_skip_reason}", style="dim"))
    if not compact and not narrow:
        table.add_row("REPLAY DATA", Text(f"{measured.total_telemetry_events:,} telemetry events", style="dim"))
        if measured.last_duration_sec:
            table.add_row(
                "LAST REPLAY",
                Text(f"{measured.last_validated_count} in {measured.last_duration_sec:.1f}s", style="bright_cyan"),
            )
        providers = " · ".join(f"{name.upper()} {count}" for name, count in sorted(measured.bas_providers.items()))
        table.add_row("BAS ENGINES", Text(providers or "no simulations yet", style="dim"))
        if measured.bas_last_status:
            last = measured.bas_last_status.replace("_", " ")
            if measured.bas_last_duration_sec:
                last += f" · {measured.bas_last_duration_sec:.1f}s"
            table.add_row("LAST BAS", Text(last, style="bright_cyan"))
    return Panel(table, title="[bold bright_cyan]VALIDATION[/]", border_style="magenta", box=box.ROUNDED)


def _detection_rules_panel(
    workspace: Optional[Path] = None,
    metrics: Optional[HuntsMetrics] = None,
    runner: Optional[RunnerStatus] = None,
    narrow: bool = False,
    siem_metrics: Optional[SiemDriftMetrics] = None,
) -> Panel:
    return _detections_panel(workspace=workspace, metrics=metrics, runner=runner, narrow=narrow, siem_metrics=siem_metrics)


def _threat_observables_panel(
    workspace: Optional[Path] = None,
    metrics: Optional[HuntsMetrics] = None,
    narrow: bool = False,
) -> Panel:
    return _hunts_panel(workspace=workspace, metrics=metrics, narrow=narrow)


def _hunts_table(workspace: Path, metrics: HuntsMetrics) -> Panel:
    table = Table(box=box.SIMPLE, expand=True, show_header=True, header_style="bold bright_cyan", padding=(0, 1))
    table.add_column("HUNT ID", width=10, style="bright_cyan")
    table.add_column("STATUS", width=12)
    table.add_column("TITLE", ratio=1, overflow="ellipsis", no_wrap=True)
    table.add_column("TACTICS", width=18, style="dim")
    table.add_column("TECHNIQUES", width=16, style="dim")

    hunts_dir = workspace / "hunts"
    if not hunts_dir.exists():
        for candidate in [
            workspace.parent / "Hecate-Workspace" / "hunts",
            workspace.parent / "Hecate-Public" / "hunts",
        ]:
            if candidate.exists():
                hunts_dir = candidate
                break

    hunt_files = []
    if hunts_dir.exists():
        try:
            hunt_files = sorted(hunts_dir.rglob("H-*.md"), key=lambda p: p.stat().st_mtime, reverse=True)
        except OSError:
            hunt_files = []

    status_styles = {
        "promoted": "bold bright_green",
        "published": "bold bright_green",
        "completed": "bright_green",
        "active": "bright_cyan",
        "in_progress": "bright_cyan",
        "in_review": "bold bright_yellow",
        "planning": "dim bright_yellow",
        "draft": "dim yellow",
    }

    count = 0
    for hf in hunt_files[:15]:
        try:
            content = hf.read_text(encoding="utf-8", errors="ignore")
            title = hf.stem
            status = "planning"
            tactics = []
            techniques = []
            if content.startswith("---"):
                parts = content.split("---", 2)
                if len(parts) >= 3:
                    fm = yaml.safe_load(parts[1])
                    if isinstance(fm, dict):
                        title = str(fm.get("title") or title)
                        if title.startswith("DRAFT - "):
                            title = title[8:].strip()
                        status = str(fm.get("status") or "planning").lower()
                        tactics = [str(t).title() for t in (fm.get("tactics") or [])]
                        techniques = [str(t).upper() for t in (fm.get("techniques") or [])]
            style = status_styles.get(status, "bright_white")
            table.add_row(
                hf.stem,
                Text(status.upper(), style=style),
                title,
                ", ".join(tactics[:2]) if tactics else "--",
                ", ".join(techniques[:2]) if techniques else "--",
            )
            count += 1
        except Exception:
            continue

    if count == 0:
        table.add_row("--", "--", "No hunt drafts found in workspace", "--", "--")

    return Panel(
        table,
        title=f"[bold bright_cyan]ACTIVE & RECENT HUNTS ({metrics.total_hunts} total)[/]",
        border_style="bright_magenta",
        box=box.ROUNDED,
    )
