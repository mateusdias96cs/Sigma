"""Offline true-positive / false-positive tests for every detection rule.

For each rule we assert two things against sample logs, fully offline (no SIEM):

* the **true-positive** event MUST make the rule fire;
* the **false-positive** (benign) event MUST NOT make the rule fire.

This is the core guarantee of the project: every rule is proven to detect what
it claims and to stay quiet on look-alike benign activity.
"""

from __future__ import annotations

import pytest

from conftest import DETECTIONS_DIR, RuleFixture, discover_rule_fixtures
from sentinelcode.engine import get_engine
from sentinelcode.rules import validate_rules

_FIXTURES = discover_rule_fixtures()


def test_rules_are_discovered() -> None:
    """Guard against an empty/misconfigured detections directory."""
    assert _FIXTURES, "no detection rules were discovered under detections/"


@pytest.mark.parametrize("fixture", _FIXTURES, ids=[str(f) for f in _FIXTURES])
def test_sample_logs_present(fixture: RuleFixture) -> None:
    assert fixture.true_positive.exists(), (
        f"missing true_positive.jsonl for rule {fixture.id} ({fixture.rule.path.name})"
    )
    assert fixture.false_positive.exists(), (
        f"missing false_positive.jsonl for rule {fixture.id} ({fixture.rule.path.name})"
    )


@pytest.mark.parametrize("fixture", _FIXTURES, ids=[str(f) for f in _FIXTURES])
def test_true_positive_fires(fixture: RuleFixture) -> None:
    engine = get_engine()
    fired = engine.evaluate([fixture.rule], fixture.true_positive)
    assert fixture.id in fired, (
        f"rule '{fixture.rule.title}' did NOT fire on its true-positive event "
        f"(engine={engine.name})"
    )


@pytest.mark.parametrize("fixture", _FIXTURES, ids=[str(f) for f in _FIXTURES])
def test_false_positive_silent(fixture: RuleFixture) -> None:
    engine = get_engine()
    fired = engine.evaluate([fixture.rule], fixture.false_positive)
    assert fixture.id not in fired, (
        f"rule '{fixture.rule.title}' incorrectly fired on its benign "
        f"false-positive event (engine={engine.name})"
    )


def test_all_rules_validate() -> None:
    """Every shipped rule must pass `sentinel validate`."""
    results = [r for r in validate_rules(DETECTIONS_DIR) if not r.ok]
    assert not results, "rules failed validation: " + "; ".join(
        f"{r.path.name}: {r.errors}" for r in results
    )
