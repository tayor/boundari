from __future__ import annotations

from boundari.testing import run_policy_tests, validate_policy_file


def test_validate_fails_when_required_output_schema_missing(tmp_path) -> None:
    path = tmp_path / "boundari.yaml"
    path.write_text(
        """agent: test
tools:
  docs.search:
    allow: true
outputs:
  require_schema: true
""",
        encoding="utf-8",
    )

    result = validate_policy_file(path)

    assert result.passed is False
    assert "Allowed tool is missing an output schema: docs.search" in result.errors


def test_policy_tests_catch_forbidden_tool_and_trace_violation(tmp_path) -> None:
    trace = tmp_path / "trace.jsonl"
    trace.write_text(
        '{"tool": "shell.run", "args": {"command": "whoami"}, "expected_allowed": true}\n',
        encoding="utf-8",
    )
    path = tmp_path / "boundari.yaml"
    path.write_text(
        f"""agent: test
tools:
  shell.run:
    allow: false
policy_tests:
  forbidden_tools:
    - shell.run
  golden_traces:
    - "{trace}"
""",
        encoding="utf-8",
    )

    result = run_policy_tests(path)

    assert result.passed is False
    assert "expected allowed=True" in result.errors[0]


def test_policy_tests_resolve_golden_traces_relative_to_policy_file(
    tmp_path, monkeypatch
) -> None:
    policy_dir = tmp_path / "policy"
    runner_dir = tmp_path / "runner"
    policy_dir.mkdir()
    runner_dir.mkdir()

    trace = policy_dir / "trace.jsonl"
    trace.write_text(
        '{"tool": "docs.search", "args": {"query": "refund"}, "expected_allowed": true}\n',
        encoding="utf-8",
    )
    path = policy_dir / "boundari.yaml"
    path.write_text(
        f"""agent: test
tools:
  docs.search:
    allow: true
policy_tests:
  golden_traces:
    - "{trace.name}"
""",
        encoding="utf-8",
    )

    monkeypatch.chdir(runner_dir)
    result = run_policy_tests(path)

    assert result.passed is True
    assert result.checked_traces == 1
