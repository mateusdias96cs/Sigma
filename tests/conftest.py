"""Shared pytest fixtures and rule/log discovery helpers."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import pytest

from sentinelcode.rules import LoadedRule, load_rules

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DETECTIONS_DIR = PROJECT_ROOT / "detections"
LOGS_DIR = Path(__file__).resolve().parent / "logs"


@dataclass(frozen=True)
class RuleFixture:
    """A rule paired with its true-positive / false-positive sample logs."""

    rule: LoadedRule
    true_positive: Path
    false_positive: Path

    @property
    def id(self) -> str:
        return self.rule.id

    def __str__(self) -> str:  # nice pytest parametrize ids
        return f"{self.rule.path.parent.name}/{self.rule.path.name}"


def discover_rule_fixtures() -> list[RuleFixture]:
    """Pair every rule with its TP/FP log files under ``tests/logs/<rule_id>/``."""
    fixtures: list[RuleFixture] = []
    for rule in load_rules(DETECTIONS_DIR):
        log_dir = LOGS_DIR / rule.id
        fixtures.append(
            RuleFixture(
                rule=rule,
                true_positive=log_dir / "true_positive.jsonl",
                false_positive=log_dir / "false_positive.jsonl",
            )
        )
    return fixtures


@pytest.fixture(scope="session")
def rule_fixtures() -> list[RuleFixture]:
    return discover_rule_fixtures()
