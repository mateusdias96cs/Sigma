"""AI-assisted Sigma rule generation with a human in the loop.

This is deliberately the *least* automated module in the project. It turns a
free-text threat report into a **draft** Sigma rule plus a matching pair of
true-positive / false-positive sample logs, writes them under ``drafts/`` and
validates them — but it **never** merges or publishes anything (architecture
principle #5). A human must review the draft, confirm it makes sense, and move
it into ``detections/`` for it to ever reach the pipeline.

The AI provider is pluggable behind :class:`AIProvider`. The primary
implementation targets Google Gemini (``GEMINI_API_KEY``) over its REST API. A
deterministic, offline :class:`TemplateProvider` is used as a fallback when no
API key is configured, so the command (and CI) work without network access or
secrets — the human-review philosophy is identical either way.
"""

from __future__ import annotations

import json
import logging
import os
import re
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path

import requests
import yaml

from sentinelcode.rules import _check_attack_tags, _check_required_metadata, load_rule

logger = logging.getLogger(__name__)

_GEMINI_ENDPOINT = "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
_DEFAULT_GEMINI_MODEL = "gemini-2.5-flash"
_DEFAULT_TIMEOUT = 60


@dataclass
class GeneratedDraft:
    """The raw artifacts an :class:`AIProvider` returns."""

    rule_yaml: str
    true_positive: list[dict]
    false_positive: list[dict]


@dataclass
class DraftResult:
    """Where a generated draft landed on disk, plus any validation issues."""

    rule_path: Path
    true_positive_path: Path
    false_positive_path: Path
    validation_errors: list[str] = field(default_factory=list)


class AIProviderError(RuntimeError):
    """Raised when an AI provider cannot produce a draft."""


# The system prompt is shared by every model-backed provider so behaviour is
# consistent regardless of vendor.
_SYSTEM_PROMPT = """\
You are a senior detection engineer. Given a threat report, produce ONE Sigma
detection rule for Linux process_creation telemetry mapped to Elastic Common
Schema (ECS) field names (e.g. process.command_line, process.executable,
user.name), plus a matching pair of sample log events.

Return ONLY a single JSON object, no markdown fences, with this exact shape:
{
  "rule_yaml": "<a complete, valid Sigma rule as YAML>",
  "true_positive": [ <one ECS JSON event that MUST trigger the rule> ],
  "false_positive": [ <one benign ECS JSON event that must NOT trigger it> ]
}

The Sigma rule MUST include all of: title, id (a fresh random UUIDv4), status
(experimental), description, references (list), author, date (YYYY-MM-DD), tags
(at least one attack.<tactic> and one attack.tXXXX[.YYY] technique), logsource
(product: linux, category: process_creation), detection, falsepositives, level.
"""


class AIProvider(ABC):
    """Turn a threat report into a draft Sigma rule and sample logs."""

    name: str = "base"

    @abstractmethod
    def generate(self, report_text: str) -> GeneratedDraft:
        """Produce a draft from the given threat report text."""
        raise NotImplementedError


class GeminiProvider(AIProvider):
    """Google Gemini, called over its public REST API using ``requests``."""

    name = "gemini"

    def __init__(self, api_key: str | None = None, model: str | None = None) -> None:
        self.api_key = api_key or os.environ.get("GEMINI_API_KEY")
        self.model = model or os.environ.get("GEMINI_MODEL", _DEFAULT_GEMINI_MODEL)
        if not self.api_key:
            raise AIProviderError(
                "GEMINI_API_KEY is not set. Export it, or use the offline 'template' "
                "provider (AI_PROVIDER=template)."
            )

    def generate(self, report_text: str) -> GeneratedDraft:
        url = _GEMINI_ENDPOINT.format(model=self.model)
        payload = {
            "system_instruction": {"parts": [{"text": _SYSTEM_PROMPT}]},
            "contents": [{"parts": [{"text": f"Threat report:\n\n{report_text}"}]}],
            "generationConfig": {"temperature": 0.2, "responseMimeType": "application/json"},
        }
        try:
            resp = requests.post(
                url,
                params={"key": self.api_key},
                json=payload,
                timeout=_DEFAULT_TIMEOUT,
            )
        except requests.RequestException as exc:
            raise AIProviderError(f"Gemini request failed: {exc}") from exc
        if resp.status_code != 200:
            raise AIProviderError(f"Gemini returned {resp.status_code}: {resp.text[:500]}")
        try:
            text = resp.json()["candidates"][0]["content"]["parts"][0]["text"]
        except (KeyError, IndexError, ValueError) as exc:
            raise AIProviderError(f"Unexpected Gemini response shape: {exc}") from exc
        return _parse_model_json(text)


class TemplateProvider(AIProvider):
    """Deterministic offline provider — no network, no API key.

    It extracts suspicious command tokens from the report and emits a valid,
    self-consistent draft (rule + TP/FP logs that actually agree with it). This
    keeps ``sentinel genrule`` usable in CI and demos while still requiring a
    human to review and promote the result.
    """

    name = "template"

    # Keyword -> (tactic tag, technique tag) heuristics for tagging the draft.
    _HEURISTICS: tuple[tuple[str, str, str], ...] = (
        ("/etc/shadow", "credential_access", "t1003.008"),
        ("authorized_keys", "persistence", "t1098.004"),
        ("history", "defense_evasion", "t1070.003"),
        ("chmod +s", "privilege_escalation", "t1548.001"),
        ("| bash", "execution", "t1059.004"),
        ("|bash", "execution", "t1059.004"),
        ("whoami", "discovery", "t1033"),
    )

    def generate(self, report_text: str) -> GeneratedDraft:
        token = _extract_command_token(report_text)
        tactic, technique = self._classify(report_text)
        rule_id = str(uuid.uuid4())
        rule = {
            "title": f"AI draft: suspicious activity ({token})",
            "id": rule_id,
            "status": "experimental",
            "description": (
                "AI-GENERATED DRAFT — human review required. Derived from a threat "
                f"report describing activity involving '{token}'. Review the logic, "
                "tighten the selection, and validate the ATT&CK mapping before promoting."
            ),
            "references": ["https://attack.mitre.org/"],
            "author": "ai-draft (template provider)",
            "date": date.today().isoformat(),
            "tags": [f"attack.{tactic}", f"attack.{technique}"],
            "logsource": {"product": "linux", "category": "process_creation"},
            "detection": {
                "selection": {"process.command_line|contains": token},
                "condition": "selection",
            },
            "falsepositives": [
                "Legitimate administrative use — tune by allow-listing known-good context."
            ],
            "level": "medium",
        }
        rule_yaml = yaml.safe_dump(rule, sort_keys=False, allow_unicode=True)
        tp = [_ecs_event(f"/usr/bin/env sh -c '{token} --do-the-thing'")]
        fp = [_ecs_event("/usr/bin/ls -la /home/user")]
        return GeneratedDraft(rule_yaml=rule_yaml, true_positive=tp, false_positive=fp)

    def _classify(self, report_text: str) -> tuple[str, str]:
        lowered = report_text.lower()
        for needle, tactic, technique in self._HEURISTICS:
            if needle in lowered:
                return tactic, technique
        return "execution", "t1059.004"


_PROVIDERS: dict[str, type[AIProvider]] = {
    "gemini": GeminiProvider,
    "template": TemplateProvider,
}


def _resolve_provider(provider: str | None) -> AIProvider:
    """Pick a provider: explicit arg > AI_PROVIDER env > Gemini-if-keyed > template."""
    name = (provider or os.environ.get("AI_PROVIDER") or "").lower()
    if not name:
        name = "gemini" if os.environ.get("GEMINI_API_KEY") else "template"
    try:
        cls = _PROVIDERS[name]
    except KeyError:
        raise AIProviderError(
            f"Unknown AI provider '{name}'. Available: {', '.join(sorted(_PROVIDERS))}."
        ) from None
    return cls()


def _extract_command_token(report_text: str) -> str:
    """Pull a representative command-ish token out of free text for the rule."""
    # Prefer something inside backticks or quotes; fall back to a known binary.
    for pattern in (r"`([^`]+)`", r"'([^']+)'", r'"([^"]+)"'):
        match = re.search(pattern, report_text)
        if match:
            return match.group(1).strip().split("\n")[0][:80]
    for binary in ("curl", "wget", "chmod", "cat", "whoami", "nc", "bash"):
        if re.search(rf"\b{binary}\b", report_text):
            return binary
    return "suspicious-command"


def _ecs_event(command_line: str) -> dict:
    """A minimal ECS process_creation event matching the test log schema."""
    return {
        "@timestamp": "2026-06-12T00:00:00.000Z",
        "event": {"category": "process", "type": "start", "action": "exec"},
        "host": {"name": "demo-host", "os": {"type": "linux"}},
        "user": {"name": "user"},
        "process": {
            "executable": command_line.split(" ", 1)[0],
            "command_line": command_line,
            "name": Path(command_line.split(" ", 1)[0]).name,
        },
    }


def _parse_model_json(text: str) -> GeneratedDraft:
    """Parse a model's JSON reply into a :class:`GeneratedDraft`, tolerantly."""
    cleaned = text.strip()
    # Strip ```json fences if the model added them despite instructions.
    cleaned = re.sub(r"^```(?:json)?\s*|\s*```$", "", cleaned, flags=re.MULTILINE).strip()
    try:
        data = json.loads(cleaned)
    except json.JSONDecodeError as exc:
        raise AIProviderError(f"Model did not return valid JSON: {exc}") from exc
    rule_yaml = data.get("rule_yaml")
    if not isinstance(rule_yaml, str):
        raise AIProviderError("Model JSON is missing a string 'rule_yaml' field.")
    return GeneratedDraft(
        rule_yaml=rule_yaml,
        true_positive=list(data.get("true_positive") or []),
        false_positive=list(data.get("false_positive") or []),
    )


def _slug(text: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "_", text.lower()).strip("_")
    return slug[:50] or "ai_draft"


def _validate_draft_file(rule_path: Path) -> list[str]:
    """Run the same validation `sentinel validate` uses on the draft rule."""
    try:
        loaded = load_rule(rule_path)
    except ValueError as exc:
        return [str(exc)]
    return _check_required_metadata(loaded.raw) + _check_attack_tags(loaded.raw)


def generate_rule_draft(
    report_path: Path,
    drafts_dir: Path,
    *,
    provider: str | None = None,
) -> DraftResult:
    """Generate, persist and validate a Sigma rule draft from a threat report.

    The draft is written under ``drafts/<slug>/`` and validated, but never
    merged or deployed — promotion to ``detections/`` is a manual human step.
    """
    if not report_path.exists():
        raise FileNotFoundError(f"Threat report not found: {report_path}")
    report_text = report_path.read_text(encoding="utf-8")

    ai = _resolve_provider(provider)
    logger.info("Generating rule draft with the '%s' provider", ai.name)
    draft = ai.generate(report_text)

    out_dir = drafts_dir / _slug(report_path.stem)
    out_dir.mkdir(parents=True, exist_ok=True)
    rule_path = out_dir / "rule.yml"
    tp_path = out_dir / "true_positive.jsonl"
    fp_path = out_dir / "false_positive.jsonl"

    rule_path.write_text(draft.rule_yaml, encoding="utf-8")
    tp_path.write_text(
        "\n".join(json.dumps(e) for e in draft.true_positive) + "\n", encoding="utf-8"
    )
    fp_path.write_text(
        "\n".join(json.dumps(e) for e in draft.false_positive) + "\n", encoding="utf-8"
    )

    errors = _validate_draft_file(rule_path)
    if errors:
        logger.warning("Draft has %d validation issue(s) for the human to fix", len(errors))
    return DraftResult(
        rule_path=rule_path,
        true_positive_path=tp_path,
        false_positive_path=fp_path,
        validation_errors=errors,
    )
