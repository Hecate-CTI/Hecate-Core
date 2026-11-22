# Core architecture

Core (`hecate_agent`) is a Python library and Click CLI. Runner imports its API
in-process and uses the CLI where required. They must therefore resolve compatible
packages in the same runtime environment.

| Layer | Implementation |
| --- | --- |
| CLI and workflows | `hecate_agent/commands/`, `hecate_agent/cli.py` |
| Public in-process API | `hecate_agent/api.py` |
| Models, prompts and agents | `hecate_agent/agents/`, `hecate_agent/data/prompts/` |
| Grounding, parsing, Sigma and native queries | `hecate_agent/core/` |
| External intelligence enrichment | `hecate_agent/enrichment/` |
| Workspace knowledge and references | Workspace readers plus generic `hecate_agent/data/` defaults |
| Monitoring | `commands/monitor*.py`, reading workspace records |

The monitor keeps collection separate from presentation. `monitor_integration_status.py`
reads configuration and recorded checks into a display snapshot; `monitor_service_metrics.py`
derives per-service metrics. `monitor_integrations.py` renders those snapshots without
workspace reads. Hunt, delivery and validation panels live in `monitor_*_panels.py`;
`monitor_views.py` composes the dashboard and preserves existing panel imports.

`HECATE_WORKSPACE` selects enterprise knowledge and output storage. Workspace
configuration, hunt/research/query documents and operational databases belong to
that selected directory, not automatically to the source repository. Similarity
and catalog caches are disposable local state; source documents remain authoritative.

Generation validates structure, supported techniques, source claims and backend
syntax. These checks narrow errors but do not guarantee factual correctness,
verified field mappings, live ingestion or a fired alert. Review outputs and keep
simulation evidence separate from operational telemetry.

Runner owns feed polling, generation scheduling, active-hunt execution, approval
queues, BAS providers, Slack operations and external publication. Public supplies
shareable content. See the canonical [system architecture](https://github.com/Hecate-Org/Hecate-Runner/blob/main/docs/ARCHITECTURE.md)
and [workspace setup](ONBOARDING.md).
