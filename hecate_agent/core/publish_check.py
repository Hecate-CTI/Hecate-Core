"""One publish decision for a finished hunt and its Sigma rules.

Generation, semantics, and the public promotion gate each check a slice of a
draft. This runs the checks that can be decided from the hunt as it will be
published, and returns one verdict: pass, review, or block.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from typing import Any

_FENCE_RE = re.compile(r"```ya?ml\s*\n(.*?)```", re.DOTALL | re.IGNORECASE)
_SECRET_RE = re.compile(
    r"(?i)(AKIA[0-9A-Z]{16}|xox[baprs]-[0-9A-Za-z-]{10,}|-----BEGIN (?:RSA |OPENSSH )?PRIVATE KEY-----)"
)
# LOCK drafts that still look finished while CHECK/KEEP are stubs.
_LOCK_MARKERS = (
    "## CHECK:",
    "## KEEP:",
    "### Data Source Information",
)
_INCOMPLETE_PATTERNS: tuple[tuple[str, re.Pattern[str], str], ...] = (
    (
        "incomplete_check",
        re.compile(r"UNVALIDATED", re.IGNORECASE),
        "CHECK is UNVALIDATED — no real lab/SIEM execution evidence",
    ),
    (
        "incomplete_keep",
        re.compile(r"UNEXECUTED", re.IGNORECASE),
        "KEEP is UNEXECUTED — findings not closed after a real run",
    ),
    (
        "incomplete_placeholder",
        re.compile(r"\[Human to populate\]", re.IGNORECASE),
        "Hunt still contains '[Human to populate]' placeholders",
    ),
    (
        "incomplete_placeholder",
        re.compile(r"\[Review CTI and populate\]", re.IGNORECASE),
        "Hunt still contains unfinished CTI placeholders",
    ),
    (
        "incomplete_placeholder",
        re.compile(r"\[To be completed after human review", re.IGNORECASE),
        "KEEP executive summary is still a draft stub",
    ),
    (
        "incomplete_placeholder",
        re.compile(r"Draft only", re.IGNORECASE),
        "Findings table is still marked 'Draft only'",
    ),
    (
        "incomplete_check",
        re.compile(r"not yet executed", re.IGNORECASE),
        "Events Analyzed still says the hunt is not yet executed",
    ),
    (
        "incomplete_placeholder",
        re.compile(r"\[none mapped\s*-\s*human to populate\]", re.IGNORECASE),
        "No MITRE techniques mapped",
    ),
    (
        "incomplete_placeholder",
        re.compile(r"\[Human to draft based on Observe", re.IGNORECASE),
        "Hunting queries were never generated",
    ),
)


@dataclass(frozen=True)
class Finding:
    check: str
    severity: str  # "block" stops approval; "review" is shown and does not
    message: str
    target: str = ""

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


@dataclass
class PublishReport:
    findings: list[Finding] = field(default_factory=list)

    @property
    def verdict(self) -> str:
        if any(item.severity == "block" for item in self.findings):
            return "block"
        if self.findings:
            return "review"
        return "pass"

    def blocking(self) -> list[Finding]:
        return [item for item in self.findings if item.severity == "block"]


def fenced_sigma(hunt_text: str) -> list[tuple[str, str]]:
    """Sigma documents embedded in the hunt body, named by their title."""
    import yaml

    found: list[tuple[str, str]] = []
    for match in _FENCE_RE.finditer(hunt_text or ""):
        raw = match.group(1).strip()
        try:
            doc = yaml.safe_load(raw)
        except yaml.YAMLError:
            found.append(("embedded rule", raw))
            continue
        if _is_sigma(doc):
            found.append((str(doc.get("title") or "embedded rule"), raw))
    return found


def evaluate_hunt(
    hunt_text: str, rules: list[tuple[str, str]] | None = None
) -> PublishReport:
    """Check the hunt text and its Sigma rules.

    ``rules`` is ``(name, yaml)``. When it is omitted, fenced Sigma in the hunt
    body is checked instead. Query files, when the caller has them, should be
    passed here so a rule is not judged twice.

    When the text looks like a LOCK hunt (CHECK/KEEP present), unfinished
    execution stubs and human-populate placeholders are **block** findings —
    drafts must not look publishable until CHECK and KEEP are closed for real.
    """
    findings: list[Finding] = []
    secret = _SECRET_RE.search(hunt_text or "")
    if secret:
        findings.append(
            Finding("credential", "block", "High-confidence credential material in the hunt text")
        )
    findings.extend(_check_lock_completeness(hunt_text or ""))
    chosen = rules if rules is not None else fenced_sigma(hunt_text)
    for name, raw in chosen:
        findings.extend(_check_rule(name, raw))
    return PublishReport(findings)


def _looks_like_lock_hunt(hunt_text: str) -> bool:
    return any(marker in hunt_text for marker in _LOCK_MARKERS)


def _check_lock_completeness(hunt_text: str) -> list[Finding]:
    if not _looks_like_lock_hunt(hunt_text):
        return []
    findings: list[Finding] = []
    seen: set[str] = set()
    for check, pattern, message in _INCOMPLETE_PATTERNS:
        if not pattern.search(hunt_text):
            continue
        key = f"{check}:{message}"
        if key in seen:
            continue
        seen.add(key)
        findings.append(Finding(check, "block", message, target="hunt"))
    return findings


def _is_sigma(doc: Any) -> bool:
    return (
        isinstance(doc, dict)
        and isinstance(doc.get("detection"), dict)
        and isinstance(doc.get("logsource"), dict)
    )


def _check_rule(name: str, raw: str) -> list[Finding]:
    import yaml

    from hecate_agent.agents.llm.sigma.validators import (
        _breadth_problem,
        _field_type_problem,
        _impossible_modifier_problem,
        _library_as_process_problem,
        _modifier_in_value_problem,
        _or_branch_breadth_problem,
        _pysigma_problem,
    )
    from hecate_agent.agents.llm.sigma_generator import _unobservable_auth_claim_problem
    from hecate_agent.core.sigma_semantics import semantic_problem

    target = name or "rule"
    try:
        doc = yaml.safe_load(raw)
    except yaml.YAMLError as exc:
        return [Finding("sigma_parse", "block", f"YAML did not parse: {exc}", target)]
    if not _is_sigma(doc):
        return []
    detection = doc["detection"]
    category = str((doc.get("logsource") or {}).get("category") or "")
    description = " ".join(str(doc.get(key) or "") for key in ("title", "description"))
    findings: list[Finding] = []

    def add(check: str, severity: str, message: str | None) -> None:
        if message:
            findings.append(Finding(check, severity, message[:400], target))

    add("semantics", "block", semantic_problem(detection, category, description))
    add("auth_claim", "block", _unobservable_auth_claim_problem(detection, description))
    add("field_type", "block", _field_type_problem(detection))
    add("modifier", "block", _modifier_in_value_problem(detection))
    add("modifier", "block", _impossible_modifier_problem(detection))
    add("library_as_process", "block", _library_as_process_problem(detection, category))
    add("breadth", "review", _breadth_problem(detection))
    add("breadth", "review", _or_branch_breadth_problem(detection))
    add("pysigma", "block", _pysigma_problem(raw))
    from hecate_agent.core.sigma_review_policy import review_rejection_reason

    reason = review_rejection_reason(doc)
    if reason:
        add("rule_review_rejected", "block", f"Rule was rejected during review: {reason}")
    if _SECRET_RE.search(raw):
        add("credential", "block", "High-confidence credential material in the rule")
    return findings
