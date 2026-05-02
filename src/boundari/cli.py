"""Command-line interface for Boundari."""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from boundari.testing import replay_trace, run_policy_tests, validate_policy_file
from boundari.yaml import load_boundary, sample_policy

app = typer.Typer(help="Policy-as-code runtime boundaries for Python AI agents.")
console = Console()
POLICY_ARGUMENT = typer.Argument(Path("boundari.yaml"), help="Policy file.")
CREATE_POLICY_ARGUMENT = typer.Argument(Path("boundari.yaml"), help="Policy file to create.")
TRACE_ARGUMENT = typer.Argument(..., help="JSONL trace to replay.")
EXPLAIN_TRACE_ARGUMENT = typer.Argument(..., help="JSONL audit or replay trace.")
FORCE_OPTION = typer.Option(False, "--force", "-f", help="Overwrite an existing policy.")
POLICY_OPTION = typer.Option(Path("boundari.yaml"), "--policy", "-p", help="Policy file.")


@app.command()
def init(
    path: Path = CREATE_POLICY_ARGUMENT,
    force: bool = FORCE_OPTION,
) -> None:
    """Create a starter Boundari YAML policy."""

    if path.exists() and not force:
        console.print(f"[red]{path} already exists. Use --force to overwrite.[/red]")
        raise typer.Exit(1)
    path.write_text(sample_policy(), encoding="utf-8")
    console.print(f"[green]Created {path}[/green]")


@app.command()
def validate(path: Path = POLICY_ARGUMENT) -> None:
    """Validate a Boundari policy file."""

    result = validate_policy_file(path)
    if not result.passed:
        for error in result.errors:
            console.print(f"[red]{error}[/red]")
        raise typer.Exit(1)
    console.print(f"[green]Policy is valid: {path}[/green]")


@app.command(name="test")
def test_policy(path: Path = POLICY_ARGUMENT) -> None:
    """Run CI-friendly policy checks."""

    result = run_policy_tests(path)
    if not result.passed:
        for error in result.errors:
            console.print(f"[red]{error}[/red]")
        raise typer.Exit(1)
    console.print(
        f"[green]Policy tests passed: {path} ({result.checked_traces} trace events)[/green]"
    )


@app.command()
def replay(
    trace_path: Path = TRACE_ARGUMENT,
    policy: Path = POLICY_OPTION,
) -> None:
    """Replay a JSONL trace against a policy without executing tools."""

    boundary = load_boundary(policy)
    result = replay_trace(boundary, trace_path)
    if not result.passed:
        for error in result.errors:
            console.print(f"[red]{error}[/red]")
        raise typer.Exit(1)
    console.print(f"[green]Replay passed: {trace_path} ({result.checked_traces} events)[/green]")


@app.command()
def explain(trace_path: Path = EXPLAIN_TRACE_ARGUMENT) -> None:
    """Summarize why calls were allowed or denied in a trace."""

    counters: Counter[str] = Counter()
    tools: Counter[str] = Counter()
    for line in trace_path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        event = json.loads(line)
        reason = str(event.get("reason") or "unknown")
        tool = str(event.get("tool") or event.get("tool_name") or "unknown")
        counters[reason] += 1
        tools[tool] += 1

    table = Table(title=f"Boundari explanation: {trace_path}")
    table.add_column("Reason")
    table.add_column("Count", justify="right")
    for reason, count in counters.most_common():
        table.add_row(reason, str(count))
    console.print(table)

    tool_table = Table(title="Tools")
    tool_table.add_column("Tool")
    tool_table.add_column("Count", justify="right")
    for tool, count in tools.most_common():
        tool_table.add_row(tool, str(count))
    console.print(tool_table)


if __name__ == "__main__":
    app()
