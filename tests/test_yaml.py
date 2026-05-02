from __future__ import annotations

import pytest

from boundari import PolicyValidationError
from boundari.yaml import load_boundary, load_config, sample_policy


def test_loads_sample_policy(tmp_path) -> None:
    path = tmp_path / "boundari.yaml"
    path.write_text(sample_policy(), encoding="utf-8")

    boundary = load_boundary(path)

    assert boundary.name == "support_agent"
    assert boundary.budget.max_tool_calls == 20
    assert boundary.tools["email.send"].approval_condition == (
        "recipient_domain not in trusted_domains"
    )
    assert boundary.outputs_require_schema is True


def test_invalid_yaml_policy_reports_validation_error(tmp_path) -> None:
    path = tmp_path / "bad.yaml"
    path.write_text("tools:\n  email.send:\n    surprise: true\n", encoding="utf-8")

    with pytest.raises(PolicyValidationError):
        load_config(path)
