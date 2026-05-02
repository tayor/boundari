"""Sensitive data redaction utilities."""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from re import Pattern
from typing import Any

from pydantic import BaseModel


@dataclass(frozen=True)
class RedactionRule:
    """A named regular-expression redaction rule."""

    name: str
    pattern: Pattern[str]
    replacement: str


DEFAULT_PATTERNS: dict[str, tuple[str, str]] = {
    "api_key": (
        r"\bsk-[a-z0-9_-]{8,}\b|\bapi[_-]?key\s*[=:]\s*[a-z0-9_./+=-]{8,}",
        "[REDACTED:api_key]",
    ),
    "credit_card": (
        r"(?<!\d)(?:\d{4}[ -]?){3}\d{4}(?!\d)|(?<!\d)\d{13,19}(?!\d)",
        "[REDACTED:credit_card]",
    ),
    "email": (r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", "[REDACTED:email]"),
    "phone": (r"(?<!\d)(?:\+?1[ .-]?)?(?:\(?\d{3}\)?[ .-]?){2}\d{4}(?!\d)", "[REDACTED:phone]"),
}

SENSITIVE_KEY_PATTERNS: dict[str, tuple[Pattern[str], ...]] = {
    "api_key": (
        re.compile(r"(?:^|_)api_key(?:$|_)", re.IGNORECASE),
        re.compile(r"(?:^|_)(?:access_|auth_|refresh_)?token(?:$|_)", re.IGNORECASE),
        re.compile(r"(?:^|_)(?:client_)?secret(?:$|_)", re.IGNORECASE),
        re.compile(r"(?:^|_)private_key(?:$|_)", re.IGNORECASE),
        re.compile(r"(?:^|_)pass(?:word|wd)(?:$|_)", re.IGNORECASE),
    ),
    "credit_card": (
        re.compile(r"(?:^|_)credit_card(?:$|_)", re.IGNORECASE),
        re.compile(r"(?:^|_)card_number(?:$|_)", re.IGNORECASE),
        re.compile(r"(?:^|_)cc_number(?:$|_)", re.IGNORECASE),
        re.compile(r"(?:^|_)pan(?:$|_)", re.IGNORECASE),
    ),
    "email": (
        re.compile(r"(?:^|_)email(?:$|_)", re.IGNORECASE),
        re.compile(r"(?:^|_)email_address(?:$|_)", re.IGNORECASE),
    ),
    "phone": (
        re.compile(r"(?:^|_)phone(?:$|_)", re.IGNORECASE),
        re.compile(r"(?:^|_)phone_number(?:$|_)", re.IGNORECASE),
        re.compile(r"(?:^|_)mobile(?:$|_)", re.IGNORECASE),
        re.compile(r"(?:^|_)cell(?:$|_)", re.IGNORECASE),
    ),
}


class Redactor:
    """Redact sensitive values from strings and JSON-like structures."""

    def __init__(
        self,
        rules: Iterable[str | RedactionRule] | None = None,
        *,
        custom_patterns: Mapping[str, str] | None = None,
    ) -> None:
        selected_rules = tuple(rules or ("api_key", "email", "phone", "credit_card"))
        compiled: list[RedactionRule] = []

        for rule in selected_rules:
            if isinstance(rule, RedactionRule):
                compiled.append(rule)
                continue
            if rule not in DEFAULT_PATTERNS:
                raise ValueError(f"Unknown redaction rule: {rule}")
            pattern, replacement = DEFAULT_PATTERNS[rule]
            compiled.append(RedactionRule(rule, re.compile(pattern, re.IGNORECASE), replacement))

        for name, pattern in (custom_patterns or {}).items():
            compiled.append(
                RedactionRule(name, re.compile(pattern, re.IGNORECASE), f"[REDACTED:{name}]")
            )

        self.rules = tuple(compiled)

    def redact_text(self, text: str) -> str:
        redacted = text
        for rule in self.rules:
            redacted = rule.pattern.sub(rule.replacement, redacted)
        return redacted

    def redact_value(self, value: Any) -> Any:
        if isinstance(value, str):
            return self.redact_text(value)
        if isinstance(value, BaseModel):
            return self.redact_value(value.model_dump(mode="json"))
        if isinstance(value, Mapping):
            redacted_mapping: dict[Any, Any] = {}
            for key, item in value.items():
                replacement = self._replacement_for_key(key)
                redacted_mapping[key] = (
                    replacement if replacement is not None else self.redact_value(item)
                )
            return redacted_mapping
        if isinstance(value, tuple):
            return tuple(self.redact_value(item) for item in value)
        if isinstance(value, list):
            return [self.redact_value(item) for item in value]
        return value

    def _replacement_for_key(self, key: Any) -> str | None:
        normalized_key = _normalize_key_name(str(key))
        for rule in self.rules:
            patterns = SENSITIVE_KEY_PATTERNS.get(rule.name, ())
            if any(pattern.search(normalized_key) for pattern in patterns):
                return rule.replacement
        return None


def _normalize_key_name(key: str) -> str:
    with_word_boundaries = re.sub(r"(?<!^)(?=[A-Z])", "_", key)
    normalized = re.sub(r"[^a-z0-9]+", "_", with_word_boundaries.lower())
    return normalized.strip("_")
