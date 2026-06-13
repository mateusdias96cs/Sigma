"""Load, parse and validate Sigma detection rules.

This module is the single source of truth for *what a valid rule looks like* in
this project. Everything else (testing, conversion, coverage, deployment)
consumes :class:`LoadedRule` objects produced here, so the rest of the codebase
never has to touch raw YAML or the pySigma object model directly.
"""

from __future__ import annotations

import logging
import re
import uuid
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from pathlib import Path

import yaml
from sigma.collection import SigmaCollection
from sigma.rule import SigmaRule
from sigma.validation import SigmaValidator
from sigma.validators.core.metadata import (
    IdentifierExistenceValidator,
    IdentifierUniquenessValidator,
)
from sigma.validators.core.tags import (
    DuplicateTagValidator,
    TLPv2TagValidator,
)

logger = logging.getLogger(__name__)

# Metadata fields every rule in this repository must define. The Sigma spec
# makes several of these optional, but for a portfolio-grade detection library
# we require them so each rule is self-documenting and auditable.
REQUIRED_METADATA_FIELDS: tuple[str, ...] = (
    "title",
    "id",
    "status",
    "description",
    "references",
    "author",
    "date",
    "tags",
    "logsource",
    "detection",
    "falsepositives",
    "level",
)

ALLOWED_STATUS = {"stable", "test", "experimental", "deprecated", "unsupported"}
ALLOWED_LEVEL = {"informational", "low", "medium", "high", "critical"}

# Canonical MITRE ATT&CK Enterprise tactics (SigmaHQ underscore convention).
# We validate tactic tags against this list ourselves instead of using pySigma's
# bundled ATTACKTagValidator, whose embedded tactic data is non-standard in the
# pinned version (it renames "defense_evasion" to "stealth"/"defense-impairment").
ALLOWED_ATTACK_TACTICS = {
    "reconnaissance",
    "resource_development",
    "initial_access",
    "execution",
    "persistence",
    "privilege_escalation",
    "defense_evasion",
    "credential_access",
    "discovery",
    "lateral_movement",
    "collection",
    "command_and_control",
    "exfiltration",
    "impact",
}

# Curated pySigma validators. These are meaningful (unique/present identifiers,
# well-formed/duplicate tags) and every rule we ship passes them, so
# `sentinel validate` stays green while still catching real mistakes.
PYSIGMA_VALIDATORS = (
    DuplicateTagValidator,
    TLPv2TagValidator,
    IdentifierExistenceValidator,
    IdentifierUniquenessValidator,
)

_TECHNIQUE_RE = re.compile(r"^t\d{4}(\.\d{3})?$", re.IGNORECASE)


@dataclass(frozen=True)
class LoadedRule:
    """A parsed Sigma rule plus the metadata the platform cares about."""

    path: Path
    rule: SigmaRule
    raw: dict

    @property
    def id(self) -> str:
        return str(self.rule.id) if self.rule.id else ""

    @property
    def title(self) -> str:
        return self.rule.title or ""

    @property
    def status(self) -> str:
        return self.rule.status.name.lower() if self.rule.status else ""

    @property
    def level(self) -> str:
        return self.rule.level.name.lower() if self.rule.level else ""

    @property
    def description(self) -> str:
        return self.rule.description or ""

    @property
    def tactics(self) -> list[str]:
        """ATT&CK tactic names from `attack.<tactic>` tags (e.g. 'execution').

        Tag spellings are normalised to the underscore convention so
        ``defense-evasion`` and ``defense_evasion`` are treated identically.
        """
        tactics: list[str] = []
        for tag in self.rule.tags:
            if tag.namespace == "attack" and not _TECHNIQUE_RE.match(tag.name):
                tactics.append(tag.name.lower().replace("-", "_"))
        return tactics

    @property
    def techniques(self) -> list[str]:
        """ATT&CK technique IDs from `attack.tXXXX[.YYY]` tags, upper-cased."""
        techniques: list[str] = []
        for tag in self.rule.tags:
            if tag.namespace == "attack" and _TECHNIQUE_RE.match(tag.name):
                techniques.append(tag.name.upper())
        return techniques

    @property
    def logsource(self) -> dict[str, str]:
        ls = self.rule.logsource
        return {
            k: v
            for k, v in {
                "category": ls.category,
                "product": ls.product,
                "service": ls.service,
            }.items()
            if v is not None
        }


@dataclass
class ValidationResult:
    """Outcome of validating a single rule file."""

    path: Path
    rule_id: str
    errors: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.errors


def iter_rule_files(detections_dir: Path) -> list[Path]:
    """Return every Sigma rule file under ``detections_dir`` (sorted, stable)."""
    if not detections_dir.exists():
        raise FileNotFoundError(f"Detections directory not found: {detections_dir}")
    return sorted(p for p in detections_dir.rglob("*.yml") if p.is_file()) + sorted(
        p for p in detections_dir.rglob("*.yaml") if p.is_file()
    )


def load_rule(path: Path) -> LoadedRule:
    """Parse a single Sigma rule file into a :class:`LoadedRule`.

    Raises :class:`ValueError` (wrapping the underlying pySigma error) when the
    file cannot be parsed at all.
    """
    text = path.read_text(encoding="utf-8")
    try:
        raw = yaml.safe_load(text)
    except yaml.YAMLError as exc:  # pragma: no cover - defensive
        raise ValueError(f"{path}: invalid YAML: {exc}") from exc
    if not isinstance(raw, dict):
        raise ValueError(f"{path}: rule must be a YAML mapping at the top level")
    try:
        collection = SigmaCollection.from_yaml(text)
    except Exception as exc:  # pySigma raises a family of SigmaError subclasses
        raise ValueError(f"{path}: failed to parse Sigma rule: {exc}") from exc
    if len(collection.rules) != 1:
        raise ValueError(
            f"{path}: expected exactly one rule per file, found {len(collection.rules)}"
        )
    rule = collection.rules[0]
    if not isinstance(rule, SigmaRule):
        raise ValueError(f"{path}: correlation rules are not supported; expected a single rule")
    return LoadedRule(path=path, rule=rule, raw=raw)


def load_rules(detections_dir: Path) -> list[LoadedRule]:
    """Load every rule under ``detections_dir``.

    Files that fail to parse raise immediately — a broken rule should never be
    silently skipped.
    """
    rules = [load_rule(path) for path in iter_rule_files(detections_dir)]
    logger.debug("Loaded %d rules from %s", len(rules), detections_dir)
    return rules


def _check_required_metadata(raw: dict) -> list[str]:
    errors: list[str] = []
    for key in REQUIRED_METADATA_FIELDS:
        if key not in raw or raw[key] in (None, "", [], {}):
            errors.append(f"missing required metadata field: '{key}'")
    status = raw.get("status")
    if status is not None and status not in ALLOWED_STATUS:
        errors.append(f"invalid status '{status}' (allowed: {sorted(ALLOWED_STATUS)})")
    level = raw.get("level")
    if level is not None and level not in ALLOWED_LEVEL:
        errors.append(f"invalid level '{level}' (allowed: {sorted(ALLOWED_LEVEL)})")
    rule_id = raw.get("id")
    if rule_id is not None:
        try:
            uuid.UUID(str(rule_id))
        except (ValueError, AttributeError, TypeError):
            errors.append(f"id '{rule_id}' is not a valid UUID")
    return errors


def _check_attack_tags(raw: dict) -> list[str]:
    """Validate ATT&CK tagging: >=1 technique and only canonical tactics."""
    tags = raw.get("tags") or []
    if not isinstance(tags, list):
        return ["tags must be a list"]
    errors: list[str] = []
    has_technique = False
    for tag in tags:
        if not isinstance(tag, str) or not tag.lower().startswith("attack."):
            continue
        name = tag.split(".", 1)[1].lower()
        if _TECHNIQUE_RE.match(name):
            has_technique = True
        elif name.replace("-", "_") not in ALLOWED_ATTACK_TACTICS:
            errors.append(f"unknown ATT&CK tactic tag 'attack.{name}'")
    if not has_technique:
        errors.append("tags must include at least one ATT&CK technique (attack.tXXXX[.YYY])")
    return errors


def _run_pysigma_validators(rules: Sequence[LoadedRule]) -> dict[str, list[str]]:
    """Run the curated pySigma validators across the whole rule set.

    Returns a mapping of rule id -> list of issue strings. Validators that need
    the full set (uniqueness checks) see every rule at once.
    """
    validator = SigmaValidator(PYSIGMA_VALIDATORS)
    issues_by_id: dict[str, list[str]] = {}
    sigma_rules = [lr.rule for lr in rules]
    for issue in validator.validate_rules(iter(sigma_rules)):
        rid = str(issue.rules[0].id) if issue.rules else "<unknown>"
        issues_by_id.setdefault(rid, []).append(f"{type(issue).__name__}: {issue.description}")
    return issues_by_id


def validate_rules(detections_dir: Path) -> list[ValidationResult]:
    """Validate every rule and return a per-rule result.

    Combines three layers of checks:

    1. required metadata presence and well-formedness (status, level, UUID);
    2. at least one ATT&CK technique tag;
    3. the curated pySigma validator suite (valid ATT&CK tags, unique ids, ...).
    """
    results: list[ValidationResult] = []
    loaded: list[LoadedRule] = []

    for path in iter_rule_files(detections_dir):
        try:
            lr = load_rule(path)
        except ValueError as exc:
            results.append(ValidationResult(path=path, rule_id="", errors=[str(exc)]))
            continue
        errors = _check_required_metadata(lr.raw) + _check_attack_tags(lr.raw)
        results.append(ValidationResult(path=path, rule_id=lr.id, errors=errors))
        loaded.append(lr)

    if loaded:
        pysigma_issues = _run_pysigma_validators(loaded)
        by_id = {r.rule_id: r for r in results if r.rule_id}
        for rid, issues in pysigma_issues.items():
            if rid in by_id:
                by_id[rid].errors.extend(issues)

    return results


def find_rule_by_id(rules: Iterable[LoadedRule], rule_id: str) -> LoadedRule | None:
    for rule in rules:
        if rule.id == rule_id:
            return rule
    return None
