"""Tests for ATT&CK coverage generation."""

from __future__ import annotations

import json
from pathlib import Path

from conftest import DETECTIONS_DIR
from sentinelcode.coverage import build_report, generate_coverage
from sentinelcode.rules import load_rules


def test_report_aggregates_techniques_per_tactic() -> None:
    report = build_report(load_rules(DETECTIONS_DIR))
    # Every shipped rule contributes at least one technique.
    assert report.covered_technique_count >= 6
    # The discovery rule carries two techniques (T1033 + T1082).
    assert report.tactics["discovery"].covered == 2
    # Percentages are bounded.
    for tc in report.tactics.values():
        assert 0.0 <= tc.percentage <= 100.0


def test_generate_writes_layer_and_summary(tmp_path: Path) -> None:
    layer_path, summary_path, report = generate_coverage(DETECTIONS_DIR, tmp_path)
    assert layer_path.exists() and summary_path.exists()

    layer = json.loads(layer_path.read_text())
    assert layer["domain"] == "enterprise-attack"
    technique_ids = {t["techniqueID"] for t in layer["techniques"]}
    assert "T1059.004" in technique_ids
    assert len(layer["techniques"]) == report.covered_technique_count

    summary = summary_path.read_text()
    assert "ATT&CK Coverage Summary" in summary
    assert "Coverage by tactic" in summary
