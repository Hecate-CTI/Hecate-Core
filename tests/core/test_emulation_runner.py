"""Unit tests for EmulationRunner and Sandboxed Detonation."""

import shutil
import subprocess
from pathlib import Path

import pytest

from hecate_agent.core.emulation_runner import (
    DEFAULT_PINNED_DOCKER_IMAGE,
    BwrapBackend,
    DockerBackend,
    EmulationRunner,
    MockBackend,
    SimulationBackend,
    SubprocessBackend,
    _truncate_output,
)
from hecate_agent.api import run_dynamic_atomic_emulation


def _strace_can_trace() -> bool:
    strace = shutil.which("strace")
    if strace is None:
        return False
    try:
        result = subprocess.run(
            [strace, "-qq", "-o", "/dev/null", "-e", "trace=execve", "true"],
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return result.returncode == 0


def test_mock_backend_emulation() -> None:
    mock_events = [
        {"category": "process_creation", "CommandLine": "vshell_loader.exe -stage2", "Image": "vshell_loader.exe"},
        {"category": "network_connection", "DestinationIp": "38.207.178.192", "DestinationPort": 443},
    ]
    mock_backend = MockBackend(mock_events=mock_events, exit_code=0, stdout="test detonation completed")
    runner = EmulationRunner(backend=mock_backend)

    result = runner.run_command("vshell_loader.exe -stage2")
    assert result.success is True
    assert result.exit_code == 0
    assert result.backend == "mock"
    assert len(result.events) == 2

    # Closed-loop evaluation against a Sigma rule
    rule_yaml = """
title: VShell IOC Connection
logsource:
    category: network_connection
detection:
    selection:
        DestinationIp: '38.207.178.192'
    condition: selection
"""
    report = result.evaluate(rule_yaml)
    assert report.true_positives == 1
    assert report.fired_on_intrusion is True
    assert report.is_clean is True


@pytest.mark.skipif(
    shutil.which("bwrap") is None or not _strace_can_trace(),
    reason="bwrap and working ptrace support are required for sandbox telemetry",
)
def test_bwrap_sandbox_execution_and_isolation() -> None:
    runner = EmulationRunner(backend="bwrap")
    test_marker = "/tmp/hecate_art_test_marker.txt"

    # Ensure host marker doesn't exist before test
    assert not Path(test_marker).exists()

    cmd = f"echo 'purple_team_payload' > {test_marker} && cat {test_marker}"
    result = runner.run_command(cmd)

    assert result.success is True
    assert result.exit_code == 0
    assert result.backend == "bwrap"
    assert "purple_team_payload" in result.stdout

    # Verify filesystem isolation: file written inside sandbox MUST NOT exist on host!
    assert not Path(test_marker).exists(), "Sandbox isolation violated: file leaked to host filesystem"

    # /home is an empty tmpfs — the real host username must not appear.
    host_user = Path.home().name
    home_list = runner.run_command("ls -A /home 2>/dev/null; echo HOME_OK")
    assert home_list.success is True
    assert "HOME_OK" in home_list.stdout
    assert host_user not in home_list.stdout

    # Network must be disabled inside the sandbox.
    net = runner.run_command(
        "python3 -c 'import socket; socket.create_connection((\"1.1.1.1\", 80), 1)' >/dev/null 2>&1 || echo net_blocked"
    )
    assert "net_blocked" in net.stdout

    # Verify telemetry harvesting
    proc_events = [e for e in result.events if e.get("category") == "process_creation"]
    file_events = [e for e in result.events if e.get("category") == "file_event"]

    assert len(proc_events) > 0, "No process_creation events captured"
    assert len(file_events) > 0, "No file_event events captured"
    assert any(test_marker in e.get("TargetFilename", "") for e in file_events)


def test_subprocess_backend_disabled_by_default() -> None:
    backend = SubprocessBackend()
    assert backend.is_available() is False
    with pytest.raises(RuntimeError, match="Unsandboxed"):
        backend.run("echo should_not_run")


def test_subprocess_backend_opt_in(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HECATE_ALLOW_UNSANDBOXED_EMULATION", "1")
    runner = EmulationRunner(backend=SubprocessBackend(allow_unsandboxed=True))
    result = runner.run_command("echo 'subprocess_fallback'")
    assert result.success is True
    assert "subprocess_fallback" in result.stdout


def test_auto_backend_never_selects_subprocess(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(BwrapBackend, "is_available", lambda self: False)
    from hecate_agent.core import emulation_runner as er

    monkeypatch.setattr(er.DockerBackend, "is_available", lambda self: False)
    runner = EmulationRunner(backend=None)
    assert isinstance(runner.backend, SimulationBackend)


def test_requested_subprocess_without_opt_in_uses_simulation(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("HECATE_ALLOW_UNSANDBOXED_EMULATION", raising=False)
    runner = EmulationRunner(backend="subprocess")
    assert isinstance(runner.backend, SimulationBackend)


def test_emulation_runner_run_atomic_test() -> None:
    mock_events = [
        {"category": "process_creation", "CommandLine": "whoami /all", "Image": "/usr/bin/whoami"},
    ]
    runner = EmulationRunner(backend=MockBackend(mock_events=mock_events))

    art_test = {
        "name": "System Discovery via Whoami",
        "command": "whoami /all",
        "telemetry": "Sysmon Event ID 1",
    }
    result = runner.run_atomic_test(art_test)
    assert result.success is True
    assert result.command == "whoami /all"
    assert len(result.events) == 1


def test_emulation_runner_run_technique() -> None:
    mock_events = [
        {"category": "process_creation", "CommandLine": "procdump.exe -ma lsass.exe lsass.dmp"},
    ]
    runner = EmulationRunner(backend=MockBackend(mock_events=mock_events))

    # T1003.001 is curated in ATOMIC_TESTS_MAP
    result = runner.run_technique("T1003.001", test_index=0)
    assert result.success is True
    assert "procdump" in result.command


@pytest.mark.skipif(
    shutil.which("bwrap") is None or not _strace_can_trace(),
    reason="bwrap and working ptrace support are required for telemetry harvesting",
)
def test_closed_loop_detonation_and_detection_self_evaluation() -> None:
    """Full closed-loop evaluation: command execution -> harvested telemetry -> Sigma rule evaluation."""
    runner = EmulationRunner(backend="bwrap")

    cmd = "sh -c 'echo detonation_test > /tmp/art_signal.tmp && cat /tmp/art_signal.tmp'"
    result = runner.run_command(cmd)
    assert result.success is True

    # Rule matching the file event created in sandbox
    matching_rule = """
title: Detection of Temporary Signal File Creation
logsource:
    category: file_event
detection:
    selection:
        TargetFilename|endswith: 'art_signal.tmp'
    condition: selection
"""
    report = result.evaluate(matching_rule)
    assert report.true_positives >= 1
    assert report.fired_on_intrusion is True


def test_truncate_output() -> None:
    assert _truncate_output("") == ""
    assert _truncate_output(None) == ""

    short_text = "Standard stdout line\n"
    assert _truncate_output(short_text, max_bytes=100) == short_text

    long_text = "A" * 200
    truncated = _truncate_output(long_text, max_bytes=50)
    assert len(truncated.encode("utf-8")) > 50  # Contains truncation notice
    assert truncated.startswith("A" * 50)
    assert "[truncated: output exceeded 50 bytes limit]" in truncated


def test_docker_backend_limits_and_command_construction(monkeypatch: pytest.MonkeyPatch) -> None:
    backend = DockerBackend()
    assert backend.image == DEFAULT_PINNED_DOCKER_IMAGE
    assert backend.memory_limit == "256m"
    assert backend.cpu_limit == "1.0"
    assert backend.pids_limit == 64

    monkeypatch.setattr(backend, "is_available", lambda: True)
    backend.docker_bin = "/usr/bin/docker"

    captured_cmds: list[list[str]] = []

    def mock_run(cmd: list[str], *args: object, **kwargs: object) -> subprocess.CompletedProcess[str]:
        captured_cmds.append(cmd)
        return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="test_ok\n", stderr="")

    monkeypatch.setattr(subprocess, "run", mock_run)

    exit_code, stdout, stderr, _ = backend.run("whoami")
    assert exit_code == 0
    assert stdout == "test_ok\n"
    assert len(captured_cmds) == 1

    cmd = captured_cmds[0]
    assert cmd[0] == "/usr/bin/docker"
    assert cmd[1] == "run"
    assert "--name" in cmd
    name_idx = cmd.index("--name")
    container_name = cmd[name_idx + 1]
    assert container_name.startswith("hecate-detonate-")
    assert "--rm" in cmd
    assert "-i" in cmd
    assert "--network" in cmd and cmd[cmd.index("--network") + 1] == "none"
    assert "--read-only" in cmd
    assert "--tmpfs" in cmd and cmd[cmd.index("--tmpfs") + 1] == "/tmp:rw,exec,nosuid,nodev,size=64m"
    assert "--security-opt" in cmd and cmd[cmd.index("--security-opt") + 1] == "no-new-privileges"
    assert "--cap-drop" in cmd and cmd[cmd.index("--cap-drop") + 1] == "ALL"
    assert "--user" in cmd and cmd[cmd.index("--user") + 1] == "65534:65534"
    assert "--memory=256m" in cmd
    assert "--memory-swap=256m" in cmd
    assert "--cpus=1.0" in cmd
    assert "--pids-limit=64" in cmd
    assert DEFAULT_PINNED_DOCKER_IMAGE in cmd
    assert cmd[-3:] == ["sh", "-c", "whoami"]


def test_docker_backend_validation_rejects_unsafe_inputs() -> None:
    # Reject shell metacharacters, spaces, flag injections in image
    for unsafe_img in [
        "alpine:latest; rm -rf /",
        "alpine:latest && touch /tmp/pwn",
        "$(whoami)",
        "`id`",
        "--privileged",
        "-v /:/host",
    ]:
        with pytest.raises(ValueError, match="Invalid Docker image reference"):
            DockerBackend(image=unsafe_img)

    # Valid images
    b1 = DockerBackend(image="alpine:3.18")
    assert b1.image == "alpine:3.18"
    b2 = DockerBackend(image="my-registry.local:5000/sec/tool@sha256:" + "a" * 64)
    assert "my-registry.local" in b2.image

    # Invalid memory limit
    with pytest.raises(ValueError, match="Invalid memory limit"):
        DockerBackend(memory_limit="256mb")
    with pytest.raises(ValueError, match="Invalid memory limit"):
        DockerBackend(memory_limit="256m; rm -rf")

    # Invalid CPU limit
    with pytest.raises(ValueError, match="Invalid CPU limit"):
        DockerBackend(cpu_limit="-1.0")
    with pytest.raises(ValueError, match="Invalid CPU limit"):
        DockerBackend(cpu_limit="two")

    # Invalid pids limit
    with pytest.raises(ValueError, match="Invalid pids limit"):
        DockerBackend(pids_limit=0)
    with pytest.raises(ValueError, match="Invalid pids limit"):
        DockerBackend(pids_limit=-5)
    with pytest.raises(ValueError, match="Invalid pids limit"):
        DockerBackend(pids_limit="64")  # type: ignore[arg-type]


def test_docker_backend_timeout_and_error_daemon_cleanup(monkeypatch: pytest.MonkeyPatch) -> None:
    backend = DockerBackend()
    backend.docker_bin = "/usr/bin/docker"
    monkeypatch.setattr(backend, "is_available", lambda: True)

    calls: list[list[str]] = []

    def mock_timeout_run(cmd: list[str], *args: object, **kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append(cmd)
        if len(calls) == 1:
            raise subprocess.TimeoutExpired(cmd=cmd, timeout=5)
        return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")

    monkeypatch.setattr(subprocess, "run", mock_timeout_run)

    exit_code, stdout, stderr, _ = backend.run("sleep 10", timeout=5)
    assert exit_code == -1
    assert "timed out" in stderr
    assert len(calls) == 2
    # Verify cleanup call removed the named container
    cleanup_cmd = calls[1]
    assert cleanup_cmd[:3] == ["/usr/bin/docker", "rm", "-f"]
    assert cleanup_cmd[3].startswith("hecate-detonate-")

    # Verify generic exception also cleans up
    calls.clear()

    def mock_exc_run(cmd: list[str], *args: object, **kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append(cmd)
        if len(calls) == 1:
            raise RuntimeError("docker daemon socket hangup")
        return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")

    monkeypatch.setattr(subprocess, "run", mock_exc_run)

    exit_code, stdout, stderr, _ = backend.run("id")
    assert exit_code == -1
    assert "docker daemon socket hangup" in stderr
    assert len(calls) == 2
    assert calls[1][:3] == ["/usr/bin/docker", "rm", "-f"]


def test_emulation_runner_real_backend_selection(monkeypatch: pytest.MonkeyPatch) -> None:
    # 1. When bwrap is available, real mode selects bwrap
    monkeypatch.setattr(BwrapBackend, "is_available", lambda self: True)
    monkeypatch.setattr(DockerBackend, "is_available", lambda self: True)
    runner = EmulationRunner(backend="real")
    assert isinstance(runner.backend, BwrapBackend)

    # 2. When bwrap is unavailable but docker is available, real mode selects docker
    monkeypatch.setattr(BwrapBackend, "is_available", lambda self: False)
    runner = EmulationRunner(backend="real")
    assert isinstance(runner.backend, DockerBackend)

    # 3. When neither bwrap nor docker is available, real mode fails closed
    monkeypatch.setattr(DockerBackend, "is_available", lambda self: False)
    with pytest.raises(RuntimeError, match="Real adversary emulation requested, but no verified isolated"):
        EmulationRunner(backend="real")


def test_emulation_runner_require_isolated(monkeypatch: pytest.MonkeyPatch) -> None:
    # Require isolated with simulation raises RuntimeError
    with pytest.raises(RuntimeError, match="Verified isolated sandbox backend"):
        EmulationRunner(backend="simulation", require_isolated=True)

    # Require isolated with mock raises RuntimeError
    with pytest.raises(RuntimeError, match="Verified isolated sandbox backend"):
        EmulationRunner(backend="mock", require_isolated=True)

    # Require isolated with subprocess raises RuntimeError even if opt-in env is set
    monkeypatch.setenv("HECATE_ALLOW_UNSANDBOXED_EMULATION", "1")
    with pytest.raises(RuntimeError, match="Verified isolated sandbox backend"):
        EmulationRunner(backend="subprocess", require_isolated=True)

    # Require isolated with no sandbox available raises RuntimeError
    monkeypatch.setattr(BwrapBackend, "is_available", lambda self: False)
    monkeypatch.setattr(DockerBackend, "is_available", lambda self: False)
    with pytest.raises(RuntimeError, match="No verified isolated sandbox backend"):
        EmulationRunner(backend=None, require_isolated=True)

    # If bwrap is available, require_isolated succeeds
    monkeypatch.setattr(BwrapBackend, "is_available", lambda self: True)
    runner = EmulationRunner(backend="bwrap", require_isolated=True)
    assert isinstance(runner.backend, BwrapBackend)


def test_run_dynamic_atomic_emulation_require_isolated() -> None:
    with pytest.raises(RuntimeError, match="Verified isolated sandbox backend"):
        run_dynamic_atomic_emulation("T1059.001", backend="simulation", require_isolated=True)
