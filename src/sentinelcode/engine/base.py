"""The :class:`DetectionEngine` interface.

A detection engine applies a set of Sigma rules to a local log file and reports
which rules fired. Keeping this behind a small abstract interface means the test
suite, the CLI and CI never depend on a concrete engine — we can ship a fast
pure-Python evaluator for local development and swap in Zircolite (or Chainsaw)
without touching any caller.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Sequence
from pathlib import Path

from sentinelcode.rules import LoadedRule


class DetectionEngineError(RuntimeError):
    """Raised when an engine cannot evaluate rules (e.g. Docker unavailable)."""


class DetectionEngine(ABC):
    """Apply Sigma rules to a local log file, offline.

    Implementations must be side-effect free with respect to the input files and
    must not require a running SIEM.
    """

    #: Short, stable identifier used by the CLI/`DETECTION_ENGINE` env var.
    name: str = "base"

    @abstractmethod
    def evaluate(self, rules: Sequence[LoadedRule], log_file: Path) -> set[str]:
        """Return the ids of the rules that fired on at least one event.

        Args:
            rules: the rules to evaluate.
            log_file: a path to a JSON-lines (``.jsonl``) file of log events.

        Returns:
            The set of rule ids (``LoadedRule.id``) that matched at least one
            event in ``log_file``.
        """
        raise NotImplementedError

    def is_available(self) -> bool:
        """Whether this engine can run in the current environment."""
        return True
