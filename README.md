# Boundari

Policy-as-code runtime boundaries for Python AI agents.

Boundari gives AI agents hard runtime boundaries: tool permissions, approval gates,
budgets, schemas, redaction, and audit logs without forcing you into a new agent
framework.

It is designed to sit around tools from Pydantic AI, OpenAI Agents SDK, LangGraph,
CrewAI, or a custom Python loop. Your agent can reason freely, but before it mutates
the world, Boundari checks the contract.

## Install

```bash
pip install boundari
```

For local development:

```bash
uv venv
uv sync --extra dev
uv run pytest
```

## Quickstart

```python
from boundari import Boundary, Budget, ToolPolicy

def send_email(to: str, subject: str, body: str) -> dict[str, str]:
    return {"message_id": "msg_123", "status": "sent", "to": to}

boundary = Boundary(
    name="support_agent",
    budget=Budget(max_tool_calls=20, max_runtime_seconds=180),
    tools=[
        ToolPolicy("email.send").require_approval(
            when="recipient_domain not in trusted_domains"
        ),
        ToolPolicy("docs.search").allow(),
        ToolPolicy("shell.run").deny(),
    ],
    trusted_domains=["example.com"],
)

safe_send_email = boundary.wrap_tool("email.send", send_email)

result = safe_send_email(
    to="customer@outside.test",
    subject="Refund update",
    body="We can help with that.",
)

assert result.allowed is False
assert result.reason == "approval_denied"
```

Boundari returns a structured `Decision` for denied calls. If you prefer exceptions,
wrap with `raise_on_denied=True`.

## Core Concepts

`Boundary` is the runtime contract for one agent or workflow.

`ToolPolicy` says whether a named tool is allowed, denied, schema-validated,
approval-gated, table-scoped, or amount-limited.

`RunContext` tracks per-run budgets such as tool calls, runtime, tokens, and cost.

`Redactor` masks sensitive strings before tool outputs are returned to the model.

`AuditEvent` records allow, deny, approval, and output decisions in a structured way.

## Python API

```python
from decimal import Decimal

from pydantic import BaseModel, EmailStr

from boundari import Boundary, Budget, ToolPolicy


class EmailInput(BaseModel):
    to: EmailStr
    subject: str
    body: str


class EmailResult(BaseModel):
    message_id: str
    status: str
    to: EmailStr


boundary = Boundary(
    name="customer_support_agent",
    budget=Budget(max_tool_calls=12, max_runtime_seconds=120, max_cost_usd=Decimal("0.25")),
    tools=[
        ToolPolicy("zendesk.search").allow(),
        ToolPolicy("zendesk.reply").require_approval(),
        ToolPolicy("stripe.refund").require_approval().max_amount("100.00"),
        ToolPolicy("email.send").input(EmailInput).output(EmailResult),
        ToolPolicy("shell.run").deny(),
    ],
)
```

## Decorator API

Use `boundary_tool` to attach Boundari metadata to a plain callable. Framework
adapters can inspect this metadata, and you can also pull the generated policy from
`__boundari_tool_policy__`.

```python
from boundari import boundary_tool


@boundary_tool(
    name="email.send",
    risk="high",
    scopes=["email:send"],
    require_approval=True,
)
async def send_email(to: str, subject: str, body: str) -> dict[str, str]:
    return {"message_id": "msg_123", "status": "queued"}
```

## YAML Policies

Create a policy file with:

```bash
boundari init
```

Example `boundari.yaml`:

```yaml
agent: sales_ops_agent

budgets:
  max_tool_calls: 20
  max_runtime_seconds: 180
  max_cost_usd: "0.50"

tools:
  crm.read_contact:
    allow: true
    scopes: ["crm:read"]

  crm.update_contact:
    allow: true
    require_approval: true
    scopes: ["crm:write"]

  email.send:
    allow: true
    require_approval:
      when: "recipient_domain not in trusted_domains"
    input_schema: EmailInput
    output_schema: EmailResult

  shell.run:
    allow: false

data:
  redact:
    - api_key
    - credit_card
    - email
    - phone
  trusted_domains:
    - example.com

outputs:
  require_schema: true
  block_if_contains:
    - "{{SECRET}}"

policy_tests:
  forbidden_tools:
    - shell.run
```

Load it from Python:

```python
from boundari import Boundary

boundary = Boundary.from_file("boundari.yaml")
```

## Human Approval

Approval callbacks receive an `ApprovalRequest` with the exact tool name, argument
summary, risk, reason, and run id.

```python
from boundari import Boundary


def approve(request):
    return request.tool_name != "stripe.refund"


boundary = Boundary.from_file("boundari.yaml", approver=approve)
```

For local demos, pass `console_approver`:

```python
from boundari import Boundary, console_approver

boundary = Boundary.from_file("boundari.yaml", approver=console_approver)
```

FastAPI users can build an approval route with `fastapi_approval_router` after
installing `boundari[web]`.

## Redaction

Boundari redacts common sensitive values from tool outputs before returning them to
the agent. Built-in rules include email addresses, phone numbers, credit-card-like
numbers, and API keys.

```python
from boundari import Redactor

redactor = Redactor(["email", "api_key"])
assert redactor.redact_text("alice@example.com sk-test-secret") == (
    "[REDACTED:email] [REDACTED:api_key]"
)
```

Raw tool inputs and outputs are not stored by default. `JSONLAuditLog` stores
structured, redacted audit events.

## CLI

```bash
boundari init
boundari validate boundari.yaml
boundari test boundari.yaml
boundari replay traces/run_123.jsonl --policy boundari.yaml
boundari explain traces/run_123.jsonl
```

`boundari test` fails when a policy is invalid, a configured forbidden tool is
allowed, required output schema markers are missing, or a golden trace violates the
contract.

## Golden Traces

A replay trace is JSONL. Each line should include a tool name and optional args.
Use `expected_allowed` when the trace should assert a specific outcome.

```json
{"tool": "docs.search", "args": {"query": "refund policy"}, "expected_allowed": true}
{"tool": "shell.run", "args": {"command": "rm -rf /"}, "expected_allowed": false}
```

## Framework Adapters

Install optional extras as adapters mature:

```bash
pip install "boundari[pydantic-ai]"
pip install "boundari[openai-agents]"
```

Current adapters keep the core package framework-agnostic and expose lightweight
wrappers that preserve the original agent object while carrying the active boundary.

```python
from boundari import Boundary
from boundari.adapters.pydantic_ai import wrap_agent

safe_agent = wrap_agent(agent, boundary=Boundary.from_file("boundari.yaml"))
```

## Development

```bash
uv venv
uv sync --extra dev
uv run ruff check .
uv run mypy src
uv run pytest
uv run python -m build
uv run twine check dist/*
```

## Security Positioning

Boundari reduces an agent's blast radius by enforcing deterministic runtime policy.
It is not a prompt-injection scanner, hosted security product, model gateway, or
secret manager. The core package does not make network calls.

## License

MIT License. See `LICENSE`.
