"""Publish converted rules to a local Kibana Detection Engine, idempotently.

The Sigma rule is the single source of truth (architecture principle #1); this
module never edits rules, it only ships the *derived* NDJSON produced by
:mod:`sentinelcode.convert`. Publication is idempotent (principle #4): every
Elastic rule carries the Sigma UUID as its ``rule_id``, so re-deploying updates
the existing rule in place instead of creating a duplicate.

Credentials are read from the environment only (principle #6):

* ``ELASTIC_URL``        — base Kibana URL, e.g. ``http://localhost:5601``.
* ``ELASTIC_API_KEY``    — a Kibana/Elasticsearch API key (preferred), or
* ``ELASTIC_USERNAME`` / ``ELASTIC_PASSWORD`` — HTTP basic auth fallback.

Nothing here is logged that could leak a secret.
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass
from pathlib import Path

import requests

from sentinelcode.convert import convert_rules

logger = logging.getLogger(__name__)

# Kibana requires this header on every state-changing request as CSRF protection.
_KBN_HEADERS = {"kbn-xsrf": "true", "Content-Type": "application/json"}

_RULES_API = "/api/detection_engine/rules"
_DEFAULT_TIMEOUT = 30


class DeployError(RuntimeError):
    """Raised for configuration or connectivity problems during deployment."""


@dataclass
class DeploySummary:
    """Outcome of a deploy run."""

    created: int = 0
    updated: int = 0
    skipped: int = 0


@dataclass
class _Credentials:
    base_url: str
    api_key: str | None = None
    username: str | None = None
    password: str | None = None


def _load_credentials() -> _Credentials:
    """Read connection settings from the environment with clear errors."""
    base_url = os.environ.get("ELASTIC_URL", "").rstrip("/")
    if not base_url:
        raise DeployError(
            "ELASTIC_URL is not set. Copy config/elastic.example.env to .env, fill it "
            "in, and `source` it (or export the variables) before deploying."
        )
    api_key = os.environ.get("ELASTIC_API_KEY")
    username = os.environ.get("ELASTIC_USERNAME")
    password = os.environ.get("ELASTIC_PASSWORD")
    if not api_key and not (username and password):
        raise DeployError(
            "No credentials found. Set ELASTIC_API_KEY, or both ELASTIC_USERNAME and "
            "ELASTIC_PASSWORD."
        )
    return _Credentials(base_url=base_url, api_key=api_key, username=username, password=password)


def _session(creds: _Credentials) -> requests.Session:
    session = requests.Session()
    session.headers.update(_KBN_HEADERS)
    if creds.api_key:
        session.headers["Authorization"] = f"ApiKey {creds.api_key}"
    elif creds.username and creds.password:
        session.auth = (creds.username, creds.password)
    return session


def _read_ndjson(ndjson_path: Path) -> list[dict]:
    if not ndjson_path.exists():
        raise DeployError(f"NDJSON not found: {ndjson_path}. Run `sentinel convert` first.")
    rules: list[dict] = []
    for line in ndjson_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            rules.append(json.loads(line))
    return rules


def _rule_exists(session: requests.Session, base_url: str, rule_id: str) -> bool:
    """Check whether a Detection Engine rule with this ``rule_id`` already exists."""
    try:
        resp = session.get(
            f"{base_url}{_RULES_API}",
            params={"rule_id": rule_id},
            timeout=_DEFAULT_TIMEOUT,
        )
    except requests.RequestException as exc:
        raise DeployError(f"Cannot reach Kibana at {base_url}: {exc}") from exc
    return resp.status_code == 200


def _upsert_rule(session: requests.Session, base_url: str, rule: dict) -> str:
    """Create the rule, or update it in place if its ``rule_id`` already exists.

    Returns ``"created"`` or ``"updated"``. The Detection Engine keys on
    ``rule_id``, so PUT-by-rule_id is a true upsert and the whole operation is
    idempotent.
    """
    rule_id = rule["rule_id"]
    exists = _rule_exists(session, base_url, rule_id)
    try:
        if exists:
            resp = session.put(
                f"{base_url}{_RULES_API}", data=json.dumps(rule), timeout=_DEFAULT_TIMEOUT
            )
            action = "updated"
        else:
            resp = session.post(
                f"{base_url}{_RULES_API}", data=json.dumps(rule), timeout=_DEFAULT_TIMEOUT
            )
            action = "created"
    except requests.RequestException as exc:
        raise DeployError(f"Request to Kibana failed for rule '{rule_id}': {exc}") from exc

    if resp.status_code in (200, 201):
        return action
    # A 409 on create means it was created between our check and POST: retry as update.
    if resp.status_code == 409 and not exists:
        put = session.put(
            f"{base_url}{_RULES_API}", data=json.dumps(rule), timeout=_DEFAULT_TIMEOUT
        )
        if put.status_code in (200, 201):
            return "updated"
        resp = put
    raise DeployError(f"Kibana rejected rule '{rule_id}' ({resp.status_code}): {resp.text[:500]}")


def deploy_rules(
    detections_dir: Path,
    build_dir: Path,
    pipeline_path: Path,
    *,
    dry_run: bool = False,
) -> DeploySummary:
    """Convert rules and idempotently publish them to the Kibana Detection Engine.

    Always rebuilds the NDJSON from source so the deploy matches the rules on
    disk. With ``dry_run=True`` it converts and reports the plan without making
    any network call.
    """
    ndjson_path, _ = convert_rules(detections_dir, build_dir, pipeline_path)
    rules = _read_ndjson(ndjson_path)

    summary = DeploySummary()
    if dry_run:
        logger.info("Dry run: %d rule(s) would be deployed from %s", len(rules), ndjson_path)
        summary.skipped = len(rules)
        return summary

    creds = _load_credentials()
    session = _session(creds)
    logger.info("Deploying %d rule(s) to %s", len(rules), creds.base_url)
    for rule in rules:
        action = _upsert_rule(session, creds.base_url, rule)
        if action == "created":
            summary.created += 1
        else:
            summary.updated += 1
        logger.info("%s: %s", action, rule.get("name", rule["rule_id"]))
    return summary
