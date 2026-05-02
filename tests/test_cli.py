from __future__ import annotations

from typer.testing import CliRunner

from boundari.cli import app

runner = CliRunner()


def test_cli_init_validate_and_test(tmp_path) -> None:
    policy = tmp_path / "boundari.yaml"

    init_result = runner.invoke(app, ["init", str(policy)])
    validate_result = runner.invoke(app, ["validate", str(policy)])
    test_result = runner.invoke(app, ["test", str(policy)])

    assert init_result.exit_code == 0
    assert validate_result.exit_code == 0
    assert test_result.exit_code == 0


def test_cli_replay_and_explain(tmp_path) -> None:
    policy = tmp_path / "boundari.yaml"
    policy.write_text(
        """agent: test
tools:
  docs.search:
    allow: true
  shell.run:
    allow: false
""",
        encoding="utf-8",
    )
    trace = tmp_path / "trace.jsonl"
    trace.write_text(
        "\n".join(
            [
                '{"tool": "docs.search", "args": {"query": "refund"}, '
                '"expected_allowed": true, "reason": "allowed"}',
                '{"tool": "shell.run", "args": {"command": "whoami"}, '
                '"expected_allowed": false, "reason": "tool_not_allowed"}',
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    replay_result = runner.invoke(app, ["replay", str(trace), "--policy", str(policy)])
    explain_result = runner.invoke(app, ["explain", str(trace)])

    assert replay_result.exit_code == 0
    assert explain_result.exit_code == 0
    assert "tool_not_allowed" in explain_result.output
