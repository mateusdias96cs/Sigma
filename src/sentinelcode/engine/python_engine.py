"""A pure-Python, dependency-light offline Sigma evaluation engine.

This engine walks the parsed pySigma condition AST and evaluates it directly
against ECS-shaped JSON events. It is the default engine for ``sentinel test``
because it is fast, deterministic and requires no external binaries or Docker,
which keeps the inner development loop tight (architecture principle #2).

The Zircolite engine (:mod:`sentinelcode.engine.zircolite_engine`) implements the
same interface for production-grade, SQL-backed evaluation.

Supported Sigma subset (intentionally constrained to what our rules use):

* boolean composition: ``and`` / ``or`` / ``not`` / ``1 of`` / ``all of``;
* string matching with ``*`` wildcards (case-insensitive), including the
  ``contains`` / ``startswith`` / ``endswith`` / ``all`` modifiers;
* regular expressions (``|re``);
* numeric and boolean equality;
* null checks;
* keyword (fieldless) search across all event values.

Unsupported constructs raise :class:`DetectionEngineError` loudly rather than
silently mis-evaluating a rule.
"""

from __future__ import annotations

import json
import logging
import re
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from sigma.conditions import (
    ConditionAND,
    ConditionFieldEqualsValueExpression,
    ConditionNOT,
    ConditionOR,
    ConditionValueExpression,
)
from sigma.types import (
    SigmaBool,
    SigmaNull,
    SigmaNumber,
    SigmaRegularExpression,
    SigmaString,
    SpecialChars,
)

from sentinelcode.engine.base import DetectionEngine, DetectionEngineError
from sentinelcode.rules import LoadedRule

logger = logging.getLogger(__name__)

# Sentinel for "field not present in event", distinct from an explicit null.
_MISSING = object()


def _sigma_string_to_regex(value: SigmaString) -> re.Pattern[str]:
    """Compile a SigmaString (with ``*``/``?`` wildcards) into an anchored regex."""
    parts: list[str] = []
    for token in value.s:
        if token is SpecialChars.WILDCARD_MULTI:
            parts.append(".*")
        elif token is SpecialChars.WILDCARD_SINGLE:
            parts.append(".")
        else:
            parts.append(re.escape(str(token)))
    return re.compile("^" + "".join(parts) + "$", re.IGNORECASE | re.DOTALL)


class PythonSigmaEngine(DetectionEngine):
    """Evaluate Sigma rules against JSONL log events in pure Python."""

    name = "python"

    def evaluate(self, rules: Sequence[LoadedRule], log_file: Path) -> set[str]:
        events = self._load_events(log_file)
        fired: set[str] = set()
        for loaded in rules:
            if any(self._rule_matches(loaded, event) for event in events):
                fired.add(loaded.id)
        return fired

    # -- event loading ----------------------------------------------------

    @staticmethod
    def _load_events(log_file: Path) -> list[dict[str, Any]]:
        if not log_file.exists():
            raise DetectionEngineError(f"Log file not found: {log_file}")
        events: list[dict[str, Any]] = []
        for lineno, line in enumerate(log_file.read_text(encoding="utf-8").splitlines(), 1):
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise DetectionEngineError(
                    f"{log_file}:{lineno}: invalid JSON event: {exc}"
                ) from exc
        return events

    # -- rule evaluation --------------------------------------------------

    def _rule_matches(self, loaded: LoadedRule, event: dict[str, Any]) -> bool:
        condition = loaded.rule.detection.parsed_condition[0].parse()
        return self._eval(condition, event)

    def _eval(self, node: Any, event: dict[str, Any]) -> bool:
        if isinstance(node, ConditionAND):
            return all(self._eval(arg, event) for arg in node.args)
        if isinstance(node, ConditionOR):
            return any(self._eval(arg, event) for arg in node.args)
        if isinstance(node, ConditionNOT):
            return not self._eval(node.args[0], event)
        if isinstance(node, ConditionFieldEqualsValueExpression):
            return self._eval_field(node.field, node.value, event)
        if isinstance(node, ConditionValueExpression):
            return self._eval_keyword(node.value, event)
        raise DetectionEngineError(
            f"Unsupported Sigma condition node for the Python engine: {type(node).__name__}"
        )

    # -- leaf matchers ----------------------------------------------------

    def _eval_field(self, field: str, value: Any, event: dict[str, Any]) -> bool:
        actual = self._resolve_field(event, field)
        if actual is _MISSING:
            # An explicit `field: null` should match a missing field.
            return isinstance(value, SigmaNull)
        candidates = actual if isinstance(actual, list) else [actual]
        return any(self._match_value(value, candidate) for candidate in candidates)

    def _eval_keyword(self, value: Any, event: dict[str, Any]) -> bool:
        for candidate in self._iter_all_values(event):
            if self._match_value(value, candidate):
                return True
        return False

    def _match_value(self, expected: Any, actual: Any) -> bool:
        if actual is None:
            return isinstance(expected, SigmaNull)
        if isinstance(expected, SigmaNull):
            return actual is None
        if isinstance(expected, SigmaString):
            return bool(_sigma_string_to_regex(expected).match(str(actual)))
        if isinstance(expected, SigmaRegularExpression):
            return bool(re.search(str(expected.regexp), str(actual)))
        if isinstance(expected, SigmaNumber):
            return self._match_number(expected, actual)
        if isinstance(expected, SigmaBool):
            return isinstance(actual, bool) and actual is expected.boolean
        raise DetectionEngineError(
            f"Unsupported Sigma value type for the Python engine: {type(expected).__name__}"
        )

    @staticmethod
    def _match_number(expected: SigmaNumber, actual: Any) -> bool:
        try:
            return float(actual) == float(expected.number)
        except (TypeError, ValueError):
            return str(actual) == str(expected.number)

    # -- ECS field resolution --------------------------------------------

    def _resolve_field(self, event: dict[str, Any], field: str) -> Any:
        """Resolve a (possibly dotted) ECS field from a nested or flat event.

        Tries the flat key first (``{"process.name": ...}``) then walks the
        nested structure (``{"process": {"name": ...}}``). Returns ``_MISSING``
        when the field is absent.
        """
        if field in event:
            return event[field]
        current: Any = event
        for part in field.split("."):
            if isinstance(current, dict) and part in current:
                current = current[part]
            else:
                return _MISSING
        return current

    def _iter_all_values(self, value: Any) -> list[Any]:
        """Flatten every scalar value in a nested event (for keyword search)."""
        out: list[Any] = []
        if isinstance(value, dict):
            for v in value.values():
                out.extend(self._iter_all_values(v))
        elif isinstance(value, list):
            for v in value:
                out.extend(self._iter_all_values(v))
        else:
            out.append(value)
        return out
