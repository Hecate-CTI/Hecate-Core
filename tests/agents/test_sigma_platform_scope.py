"""Keep generated rules within the hunt's explicit operating-system scope."""

import pytest
import yaml
from sigma.collection import SigmaCollection

from hecate_agent.agents.llm.sigma_generator import SigmaGenerationInput, SigmaGeneratorAgent
from hecate_agent.core.sigma_evaluator import SigmaEvaluator


@pytest.mark.parametrize("platform", ["macOS", "Windows", "Linux"])
@pytest.mark.parametrize("hint", ["linux", "unix", "windows", "macos"])
def test_single_os_scope_takes_precedence_over_rule_hint(platform, hint):
    block = SigmaGeneratorAgent._logsource_block("process_creation", [platform], rule_platform=hint)
    assert block["product"] == platform.lower()


def _launchctl_rule(platforms, hint=None):
    raw = {
        "title": "Load source-named macOS LaunchAgent",
        "logsource_category": "process_creation",
        "description": "Launchctl loads the source-named LaunchAgent.",
        "detection": {
            "selection": {
                "Image|endswith": "/launchctl",
                "CommandLine|contains": "com.apple.softwareupdated.plist",
            },
            "condition": "selection",
        },
    }
    if hint:
        raw["logsource_product"] = hint
    agent = SigmaGeneratorAgent.__new__(SigmaGeneratorAgent)
    rule, problem = agent._build_rule(
        raw,
        SigmaGenerationInput(
            hypothesis="Adversaries load a malicious LaunchAgent on macOS.",
            platforms=platforms,
            techniques=["T1543.001"],
            threat_intel="launchctl bootstrap gui/501 /Users/m1/Library/LaunchAgents/com.apple.softwareupdated.plist",
        ),
    )
    assert problem is None
    assert rule is not None
    SigmaCollection.from_yaml(rule.rule_yaml)
    return yaml.safe_load(rule.rule_yaml)


@pytest.mark.parametrize("hint", [None, "linux"])
def test_macos_posix_rule_matches_macos_events_and_rejects_benign_control(hint):
    document = _launchctl_rule(["macOS"], hint)
    evaluator = SigmaEvaluator(document, strict_logsource=True)
    assert document["logsource"]["product"] == "macos"
    assert evaluator.matches(
        {
            "category": "process_creation",
            "product": "macos",
            "Image": "/bin/launchctl",
            "CommandLine": "launchctl bootstrap gui/501 /Users/m1/Library/LaunchAgents/com.apple.softwareupdated.plist",
        }
    )
    assert not evaluator.matches(
        {
            "category": "process_creation",
            "product": "macos",
            "Image": "/bin/launchctl",
            "CommandLine": "launchctl list",
        }
    )


def test_posix_path_does_not_choose_linux_over_macos_in_mixed_scope():
    assert "product" not in _launchctl_rule(["Linux", "macOS"])["logsource"]


def test_source_quoted_macos_command_keeps_macos_scope():
    from hecate_agent.core.command_rules import command_candidates

    text = "Adversaries executed launchctl bootstrap gui/501 /Users/m1/Library/LaunchAgents/com.apple.softwareupdated.plist"
    candidates = command_candidates(text, platforms=["macOS"])
    assert candidates
    agent = SigmaGeneratorAgent.__new__(SigmaGeneratorAgent)
    rules = agent._command_rules(
        SigmaGenerationInput(hypothesis="Malicious LaunchAgent", platforms=["macOS"], observed_commands=candidates)
    )
    assert rules
    for rule, problem in rules:
        assert problem is None
        assert rule is not None
        assert yaml.safe_load(rule.rule_yaml)["logsource"]["product"] == "macos"


def test_rule_hint_cannot_choose_an_os_outside_a_mixed_scope():
    assert "product" not in SigmaGeneratorAgent._logsource_block(
        "process_creation", ["Windows", "macOS"], rule_platform="linux"
    )


def test_rule_hint_can_choose_an_os_within_a_mixed_scope():
    assert (
        SigmaGeneratorAgent._logsource_block("process_creation", ["Windows", "macOS"], rule_platform="macos")["product"]
        == "macos"
    )


@pytest.mark.parametrize("category", ["webserver", "proxy", "cloud_audit", "identity_audit"])
def test_endpoint_scope_does_not_pin_non_endpoint_sources(category):
    assert SigmaGeneratorAgent._logsource_block(category, ["macOS"], rule_platform="linux") == {"category": category}


def test_linux_inference_without_explicit_os_and_container_product_are_preserved():
    assert SigmaGeneratorAgent._logsource_block("process_creation", [], "unix")["product"] == "linux"
    assert SigmaGeneratorAgent._logsource_block("container_runtime", ["Linux"])["product"] == "docker"
