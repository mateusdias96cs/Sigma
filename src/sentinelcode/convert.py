"""Convert Sigma rules into Elastic Detection Engine rules (NDJSON).

The Sigma rule is the single source of truth; the NDJSON produced here is a
derived artifact and must never be hand-edited. Each converted rule preserves
the title, description, severity (derived from the Sigma ``level``) and the
ATT&CK tags/threat mapping, and carries a stable ``rule_id`` (the Sigma UUID)
so deployment is idempotent.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

from sigma.backends.elasticsearch import LuceneBackend
from sigma.processing.pipeline import ProcessingPipeline

from sentinelcode.rules import LoadedRule, load_rules

logger = logging.getLogger(__name__)

# Sigma level -> (Elastic severity, risk_score).
_SEVERITY_MAP: dict[str, tuple[str, int]] = {
    "informational": ("low", 11),
    "low": ("low", 21),
    "medium": ("medium", 47),
    "high": ("high", 73),
    "critical": ("critical", 99),
}

# Minimal ATT&CK catalog for the tactics/techniques this repository uses, so the
# generated rules carry a proper `threat` block in the Detection Engine UI.
_TACTICS: dict[str, tuple[str, str]] = {
    "execution": ("TA0002", "Execution"),
    "persistence": ("TA0003", "Persistence"),
    "privilege_escalation": ("TA0004", "Privilege Escalation"),
    "defense_evasion": ("TA0005", "Defense Evasion"),
    "credential_access": ("TA0006", "Credential Access"),
    "discovery": ("TA0007", "Discovery"),
}

_TECHNIQUES: dict[str, str] = {
    "T1059": "Command and Scripting Interpreter",
    "T1059.004": "Unix Shell",
    "T1098": "Account Manipulation",
    "T1098.004": "SSH Authorized Keys",
    "T1003": "OS Credential Dumping",
    "T1003.008": "/etc/passwd and /etc/shadow",
    "T1070": "Indicator Removal",
    "T1070.003": "Clear Command History",
    "T1548": "Abuse Elevation Control Mechanism",
    "T1548.001": "Setuid and Setgid",
    "T1033": "System Owner/User Discovery",
    "T1082": "System Information Discovery",
}

# Default index patterns the generated Elastic rules query.
DEFAULT_INDEX = ["logs-*", "auditbeat-*", "endgame-*"]


def load_pipeline(pipeline_path: Path) -> ProcessingPipeline:
    if not pipeline_path.exists():
        raise FileNotFoundError(f"Sigma pipeline not found: {pipeline_path}")
    return ProcessingPipeline.from_yaml(pipeline_path.read_text(encoding="utf-8"))


def _technique_url(technique: str) -> str:
    return "https://attack.mitre.org/techniques/" + technique.replace(".", "/") + "/"


def _build_threat(rule: LoadedRule) -> list[dict]:
    """Build the Detection Engine `threat` block from the rule's ATT&CK tags."""
    # Group covered (sub-)techniques under their base technique.
    base_to_subs: dict[str, list[str]] = {}
    for technique in rule.techniques:
        base = technique.split(".", 1)[0]
        base_to_subs.setdefault(base, [])
        if "." in technique:
            base_to_subs[base].append(technique)

    technique_entries = []
    for base, subs in sorted(base_to_subs.items()):
        entry: dict = {
            "id": base,
            "name": _TECHNIQUES.get(base, base),
            "reference": _technique_url(base),
        }
        if subs:
            entry["subtechnique"] = [
                {
                    "id": sub,
                    "name": _TECHNIQUES.get(sub, sub),
                    "reference": _technique_url(sub),
                }
                for sub in sorted(subs)
            ]
        technique_entries.append(entry)

    threats = []
    for tactic in rule.tactics:
        if tactic not in _TACTICS:
            continue
        ta_id, ta_name = _TACTICS[tactic]
        threats.append(
            {
                "framework": "MITRE ATT&CK",
                "tactic": {
                    "id": ta_id,
                    "name": ta_name,
                    "reference": f"https://attack.mitre.org/tactics/{ta_id}/",
                },
                "technique": technique_entries,
            }
        )
    return threats


def rule_to_elastic(rule: LoadedRule, query: str) -> dict:
    """Render a single Sigma rule as a Detection Engine rule object."""
    severity, risk_score = _SEVERITY_MAP.get(rule.level, ("medium", 47))
    references = rule.raw.get("references") or []
    false_positives = rule.raw.get("falsepositives") or []
    if isinstance(false_positives, str):
        false_positives = [false_positives]

    return {
        "rule_id": rule.id,  # stable id -> idempotent import (upsert)
        "name": rule.title,
        "description": rule.description or rule.title,
        "type": "query",
        "language": "lucene",
        "query": query,
        "index": DEFAULT_INDEX,
        "severity": severity,
        "risk_score": risk_score,
        "from": "now-360s",
        "interval": "5m",
        "enabled": True,
        "author": [rule.raw.get("author", "sentinel-as-code")],
        "references": list(references),
        "false_positives": list(false_positives),
        "tags": [f"attack.{t}" for t in rule.techniques] + [f"tactic.{t}" for t in rule.tactics],
        "threat": _build_threat(rule),
        "meta": {"sentinel_as_code": {"source_rule": rule.path.name}},
    }


def convert_rules(
    detections_dir: Path, out_dir: Path, pipeline_path: Path
) -> tuple[Path, list[tuple[str, str]]]:
    """Convert all rules to a single importable NDJSON file.

    Returns the NDJSON path and a list of ``(rule_title, lucene_query)`` pairs
    for inspection.
    """
    pipeline = load_pipeline(pipeline_path)
    backend = LuceneBackend(processing_pipeline=pipeline)
    rules = load_rules(detections_dir)

    out_dir.mkdir(parents=True, exist_ok=True)
    ndjson_path = out_dir / "sentinel-rules.ndjson"

    lines: list[str] = []
    queries: list[tuple[str, str]] = []
    for rule in rules:
        converted = backend.convert_rule(rule.rule)
        if not converted:
            raise ValueError(f"{rule.path}: backend produced no query")
        query = converted[0]
        queries.append((rule.title, query))
        lines.append(json.dumps(rule_to_elastic(rule, query)))

    ndjson_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    logger.info("Converted %d rule(s) -> %s", len(rules), ndjson_path)
    return ndjson_path, queries
