from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

CLI_TIMEOUT_SECONDS = 15


def _boundari_executable() -> Path:
    name = "boundari.exe" if os.name == "nt" else "boundari"
    return Path(sys.executable).parent / name


def _run_boundari(*args: str, cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [str(_boundari_executable()), *args],
        cwd=cwd,
        capture_output=True,
        text=True,
        check=False,
        timeout=CLI_TIMEOUT_SECONDS,
    )


def test_cli_end_to_end_via_console_script(tmp_path) -> None:
    policy = tmp_path / "boundari.yaml"
    trace = tmp_path / "trace.jsonl"
    runner_dir = tmp_path / "runner"

    runner_dir.mkdir()

    init_result = _run_boundari("init", str(policy), cwd=runner_dir)

    assert _boundari_executable().exists()
    assert init_result.returncode == 0, init_result.stdout + init_result.stderr
    assert policy.exists()

    policy.write_text(
        f"""agent: test
tools:
  docs.search:
    allow: true
  shell.run:
    allow: false
policy_tests:
  forbidden_tools:
    - shell.run
  golden_traces:
    - {trace.name}
""",
        encoding="utf-8",
    )
    trace.write_text(
        "\n".join(
            [
                '{"tool": "docs.search", "args": {"query": "refund policy"}, '
                '"expected_allowed": true, "reason": "allowed"}',
                '{"tool": "shell.run", "args": {"command": "whoami"}, '
                '"expected_allowed": false, "reason": "tool_not_allowed"}',
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    validate_result = _run_boundari("validate", str(policy), cwd=runner_dir)
    test_result = _run_boundari("test", str(policy), cwd=runner_dir)
    replay_result = _run_boundari(
        "replay", str(trace), "--policy", str(policy), cwd=runner_dir
    )
    explain_result = _run_boundari("explain", str(trace), cwd=runner_dir)

    assert validate_result.returncode == 0, validate_result.stdout + validate_result.stderr
    assert test_result.returncode == 0, test_result.stdout + test_result.stderr
    assert replay_result.returncode == 0, replay_result.stdout + replay_result.stderr
    assert explain_result.returncode == 0, explain_result.stdout + explain_result.stderr
    assert "Policy is valid" in validate_result.stdout
    assert "Policy tests passed" in test_result.stdout
    assert "Replay passed" in replay_result.stdout
    assert "tool_not_allowed" in explain_result.stdout