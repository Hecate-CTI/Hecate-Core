"""Echo-title and documentation-IOC quality gates."""

from hecate_agent.core.sigma_quality import (
    documentation_ioc_block_reason,
    echo_rule_block_reason,
    is_documentation_network_indicator,
    quality_block_reason,
)
from hecate_agent.core.sigma_review_policy import review_block_reason


def test_echo_command_title_is_blocked() -> None:
    reason = echo_rule_block_reason(
        title="Command the source shows being run: system_profiler SPHardwareDataType"
    )
    assert reason is not None
    assert "hunt-worthy" in reason


def test_echo_filename_is_blocked() -> None:
    reason = echo_rule_block_reason(
        filename="process_creation__command_the_source_shows_being_run_ioreg.yml"
    )
    assert reason is not None


def test_behavioral_title_is_allowed() -> None:
    assert (
        echo_rule_block_reason(title="macOS ClickFix Stealer LaunchAgent Persistence via launchctl")
        is None
    )


def test_named_in_source_ioc_title_is_allowed_when_indicators_are_real() -> None:
    """Generic IOC sweep titles are OK; placeholder values are a separate check."""
    assert (
        echo_rule_block_reason(title="DNS lookup of a domain named in the source intelligence")
        is None
    )


def test_docnet_ip_is_documentation_indicator() -> None:
    assert is_documentation_network_indicator("203.0.113.10")
    assert is_documentation_network_indicator("1.2.3.4")
    assert is_documentation_network_indicator("evil.example.com")
    assert not is_documentation_network_indicator("193.29.224.151")
    assert not is_documentation_network_indicator("profitnow.io")


def test_detection_with_only_docnet_iocs_blocks() -> None:
    reason = documentation_ioc_block_reason(
        {"selection": {"DestinationIp": ["203.0.113.10", "1.2.3.4"]}, "condition": "selection"}
    )
    assert reason is not None
    assert "documentation/example" in reason


def test_detection_with_real_and_doc_iocs_passes_doc_check() -> None:
    assert (
        documentation_ioc_block_reason(
            {
                "selection": {"DestinationIp": ["203.0.113.10", "193.29.224.151"]},
                "condition": "selection",
            }
        )
        is None
    )


def test_review_block_reason_includes_quality_gate() -> None:
    doc = {
        "title": "Hunting lead: POST /api/v1/privileged/session as the PoC README documents",
        "detection": {"selection": {"cs-method": "POST"}, "condition": "selection"},
        "logsource": {"category": "webserver"},
    }
    reason = review_block_reason(doc)
    assert reason is not None
    assert "hunt-worthy" in reason


def test_quality_block_reason_on_filename() -> None:
    doc = {
        "title": "Otherwise fine title",
        "detection": {"selection": {"Image|endswith": "/curl"}, "condition": "selection"},
        "logsource": {"category": "process_creation"},
    }
    reason = quality_block_reason(
        doc, filename="process_creation__command_the_source_shows_being_run_curl.yml"
    )
    assert reason is not None
