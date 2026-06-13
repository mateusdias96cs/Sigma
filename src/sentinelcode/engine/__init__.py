"""Offline detection engines and the factory that selects one.

The active engine is chosen by the ``DETECTION_ENGINE`` environment variable
(or the ``--engine`` CLI flag). The default is the pure-Python engine, which
needs no external dependencies; ``zircolite`` selects the Docker-backed,
SQL-based engine for production-grade evaluation.
"""

from __future__ import annotations

import os

from sentinelcode.engine.base import DetectionEngine, DetectionEngineError
from sentinelcode.engine.python_engine import PythonSigmaEngine
from sentinelcode.engine.zircolite_engine import ZircoliteEngine

__all__ = [
    "DEFAULT_ENGINE",
    "DetectionEngine",
    "DetectionEngineError",
    "PythonSigmaEngine",
    "ZircoliteEngine",
    "get_engine",
]

DEFAULT_ENGINE = "python"

_ENGINES: dict[str, type[DetectionEngine]] = {
    "python": PythonSigmaEngine,
    "zircolite": ZircoliteEngine,
}


def get_engine(name: str | None = None) -> DetectionEngine:
    """Instantiate a detection engine by name.

    Resolution order: explicit ``name`` argument, then the ``DETECTION_ENGINE``
    environment variable, then :data:`DEFAULT_ENGINE`.
    """
    resolved = (name or os.environ.get("DETECTION_ENGINE") or DEFAULT_ENGINE).lower()
    try:
        engine_cls = _ENGINES[resolved]
    except KeyError:
        raise DetectionEngineError(
            f"Unknown detection engine '{resolved}'. Available: {', '.join(sorted(_ENGINES))}"
        ) from None
    return engine_cls()
