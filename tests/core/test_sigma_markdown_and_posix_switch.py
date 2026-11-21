"""Tests for POSIX path linter rules and markdown link prevention in Sigma rules."""

from hecate_agent.agents.llm.sigma.validators import _field_type_problem
from hecate_agent.core.sigma_semantics import markdown_or_url_in_command_line, semantic_problem


def test_posix_short_binaries_in_image_not_flagged_as_switches():
    # Endswith /sh or /nc or /bash should not be considered Windows switches
    for shell in ("/sh", "/bin/sh", "/usr/bin/sh", "/bash", "/bin/bash", "/nc", "/env", "/python3", "/java"):
        detection = {
            "selection": {
                "Image|endswith": shell,
                "CommandLine|contains": "-c",
            },
            "condition": "selection",
        }
        problem = _field_type_problem(detection)
        assert problem is None, f"Expected {shell} to be accepted, but got problem: {problem}"


def test_actual_windows_switches_in_image_are_rejected():
    # Bare switch in Image without executable path
    for bad_image in ("/s", "/q", "/f", "/c"):
        detection = {
            "selection": {
                "Image": bad_image,
                "CommandLine|contains": "foo",
            },
            "condition": "selection",
        }
        problem = _field_type_problem(detection)
        assert problem is not None, f"Expected {bad_image} to be rejected"
        assert "carries command-line switches" in problem


def test_executable_with_embedded_arguments_in_image_rejected():
    detection = {
        "selection": {
            "Image": "/bin/nc -lvnp 4444",
        },
        "condition": "selection",
    }
    problem = _field_type_problem(detection)
    assert problem is not None
    assert "carries command-line switches" in problem


def test_markdown_hyperlinks_in_command_line_rejected():
    detection = {
        "selection": {
            "Image|endswith": "/security",
            "CommandLine|contains": "advisory](https://openjdk.org/groups/vulnerability/advisories/2026-11-17",
        },
        "condition": "selection",
    }
    problem = markdown_or_url_in_command_line(detection)
    assert problem is not None
    assert "markdown hyperlink syntax" in problem

    # Verify semantic_problem catches it
    assert semantic_problem(detection, "process_creation") is not None


def test_url_in_image_field_rejected():
    detection = {
        "selection": {
            "Image|contains": "https://example.com/exploit.sh",
        },
        "condition": "selection",
    }
    problem = markdown_or_url_in_command_line(detection)
    assert problem is not None
    assert "Image field contains URL" in problem
