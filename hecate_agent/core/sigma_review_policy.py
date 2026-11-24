"""Shared rejection policy for generated Sigma rules and their consumers."""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Optional


def review_block_reason(document: Any) -> Optional[str]:
    """A rejection blocks use even when its explanation has no verified quote.

    Quote verification describes the evidence for a review, not permission to
    ignore its verdict. Rejected and revision-required proposals remain diagnostics,
    not accepted rules.
    """
    if not isinstance(document, Mapping):
        return None
    review = document.get("hecate_review")
    if not isinstance(review, Mapping) or str(review.get("verdict", "")).strip().lower() not in {"reject", "revise"}:
        return None
    issues = review.get("issues") or []
    if isinstance(issues, str):
        issues = [issues]
    reason = review.get("unverified_contradiction") or review.get("contradiction")
    if not reason and isinstance(issues, (list, tuple)):
        reason = "; ".join(str(issue) for issue in issues if str(issue).strip())
    reason = str(reason or "Not approved during automated rule review")[:2000]
    return "Revision required: " + reason if str(review.get("verdict")).strip().lower() == "revise" else reason
