"""Regression cases from the held November hunt regenerations; entirely offline."""

import json

import pytest

from hecate_agent.api import extract_indicators
from hecate_agent.core import source_evidence as se
from hecate_agent.core.provenance import routable_indicators
from hecate_agent.core.platform_evidence import platform_evidence
from hecate_agent.core.technique_evidence import map_behaviours, technique_support

REVISION = "a" * 40  # Synthetic Git SHA1; no live patch or sample lookup.
PATCH = f"https://github.com/signalwire/freeswitch/commit/{REVISION}"


@pytest.mark.parametrize("reference", [PATCH, f"[{REVISION}]({PATCH})", PATCH.upper(),
    f"https://gitlab.com/example/project/-/commit/{REVISION}",
    f"https://bitbucket.org/example/project/commits/{REVISION}"])
def test_patch_reference_does_not_become_a_hash_indicator(reference: str) -> None:
    assert extract_indicators(f"Fixed in 1.11.3. Vendor patch: {reference}")["hashes"] == []


def test_patch_reference_cannot_be_promoted_by_a_model_or_feed_hash_label() -> None:
    evidence = se.extract_source_evidence(
        "https://example.com/advisory",
        page_text=f"Vendor patch: {PATCH}",
        complete=lambda _: json.dumps({"artifacts": [{
            "kind": "sha1", "value": REVISION, "role": "executable", "status": "active",
            "evidence": f"Vendor patch: {PATCH}",
        }]}),
    )
    records = se.build_indicator_records({"FileHash-SHA1": [REVISION]}, evidence, complete=lambda _: "{}")
    assert records[0].role == "non_file"
    assert routable_indicators(records) == {}


def test_same_digest_separately_reported_as_a_file_is_preserved() -> None:
    text = f"Vendor patch: {PATCH}\nMalware executable SHA1: {REVISION}"
    assert extract_indicators(text)["hashes"] == [REVISION]
    assert not se.non_file_passage(text, REVISION)


def test_github_malware_filename_is_not_a_patch_revision() -> None:
    text = f"Sample: https://github.com/example/samples/blob/main/{REVISION}"
    assert extract_indicators(text)["hashes"] == [REVISION]


def test_scraped_site_controls_are_removed_without_losing_article_behavior() -> None:
    page = "\n".join([
        "* [Create account](https://portal.aws.amazon.com/billing/signup)",
        "* Discover AWS", "* Products", "* Pricing",
        "# OpenJDK decoding advisory",
        "The attacker sends a create account request and downloads a payload to the victim.",
    ])
    clean = se.strip_page_furniture(page)
    assert "Create account" not in clean
    assert "Discover AWS" not in clean
    assert "attacker sends a create account request" in clean
    assert technique_support("T1136", ["Create Account"], clean) is not None
    nav_only = se.strip_page_furniture(page.split("# OpenJDK")[0])
    assert technique_support("T1136", ["Create Account"], nav_only) is None


@pytest.mark.parametrize(("text", "technique", "name"), [
    ("Please note that customers may download only software that was procured from Cisco directly "
     "or through a Cisco authorized reseller or partner and for which the license is still valid.",
     "T1105", "Ingress Tool Transfer"),
    ("Use a browser extension such as NoScript to block malicious scripts.", "T1176.001", "Browser Extensions"),
    ("Background Task Management (BTM) manages persistent tasks such as LaunchAgents, login items, or cron jobs.",
     "T1053.003", "Cron"),
    ("Background Task Management (BTM) manages persistent tasks such as LaunchAgents, login items, or cron jobs.",
     "T1547.015", "Login Items"),
    ("BTM is a legitimate Apple subsystem that is used to track anything that installs itself to run "
     "automatically in the background (like launch agents, login items, or cron jobs).", "T1053.003", "Cron"),
    ("It is possible to reduce the likelihood of receiving ClickFix attack popups by installing malicious "
     "script mitigation browser add-ons, such as the NoScript browser extension (available for Chrome and Firefox).",
     "T1176.001", "Browser Extension"),
])
def test_support_mitigation_and_generic_mechanisms_are_not_observed(text: str, technique: str, name: str) -> None:
    supported = technique_support(technique, [name], text)
    assert supported is None or supported.status != "observed"
    assert not any(e.technique_id == technique and e.status == "observed" for e in map_behaviours([("source", text)]))


def test_context_does_not_suppress_a_separate_observed_download_or_persistence() -> None:
    text = (
        "Please note that customers may download only software for which the license is still valid.\n"
        "The attacker downloads a payload to the victim and installs a cron job for persistence.\n"
        "Use a browser extension such as NoScript to block malicious scripts."
    )
    observed = {e.technique_id for e in map_behaviours([("source", text)]) if e.status == "observed"}
    assert "T1105" in observed
    assert technique_support("T1053.003", ["Cron"], text).status == "observed"


def test_cve_json_schema_and_enrichment_do_not_become_platform_evidence() -> None:
    record = {"dataType": "CVE_RECORD", "containers": {
        "cna": {"descriptions": [{"lang": "en", "value": "mod_http2 assign_headers race allows RCE."}],
                "affected": [{"product": "Apache HTTP Server", "versions": [{"version": "2.4.70"}]}],
                "references": [{"url": PATCH}]},
        "adp": [{"generator": "docker kubernetes AWS CloudTrail metadata"}],
    }}
    text = se.report_body_text(json.dumps(record))
    assert "mod_http2 assign_headers" in text and "2.4.70" in text and PATCH in text
    assert '"containers"' not in text and "CloudTrail" not in text
    assert platform_evidence([text]).supported == []
    seen = []
    evidence = se.extract_source_evidence("https://example.com/cve", page_text=json.dumps(record),
        complete=lambda messages: seen.append(messages[-1]["content"]) or '{"artifacts": []}')
    assert evidence.text == text
    assert seen and all('"containers"' not in prompt for prompt in seen)


def test_reference_urls_cannot_establish_platform_scope() -> None:
    assert platform_evidence(["References: https://aws.amazon.com/cloud/ec2/linux/"]).supported == []
    assert "IaaS" in platform_evidence(["The attacker used AWS CloudTrail and EC2 to discover cloud hosts."]).supported


@pytest.mark.parametrize("text", ['{"containers": null}', '{"dataType":"CVE_RECORD","containers":null}',
    '{"dataType":"CVE_RECORD","containers":{"cna":{"descriptions":null}}}', 'ordinary report'])
def test_non_cve_or_malformed_documents_are_left_intact(text: str) -> None:
    assert se.report_body_text(text) == text
