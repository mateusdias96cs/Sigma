"""Zircolite-backed offline detection engine (runs in Docker).

Zircolite loads JSON/auditd events into an in-memory SQLite database and runs
Sigma rules compiled to SQL against it. This engine containerises Zircolite so
``sentinel test --engine zircolite`` works without the user installing Zircolite
or its dependencies on the host — only Docker is required.

The pure-Python engine (:mod:`sentinelcode.engine.python_engine`) is the default
for the everyday test loop because it is faster and needs no Docker. This engine
exists to (a) exercise the exact same rules through a real, production-grade
SQL engine and (b) demonstrate the swappable :class:`DetectionEngine` interface
(Chainsaw could be added the same way).

Container contract (see ``config/zircolite/``):

* ``/rules``  — read-only mount of the native Sigma rule files;
* ``/logs``   — read-only mount containing ``events.json`` (the JSONL log file);
* the entrypoint compiles the rules, runs Zircolite, and prints a JSON array of
  the **rule ids** that fired to stdout (one final line, prefixed ``FIRED=``).
"""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
import tempfile
from collections.abc import Sequence
from pathlib import Path

from sentinelcode.engine.base import DetectionEngine, DetectionEngineError
from sentinelcode.rules import LoadedRule

logger = logging.getLogger(__name__)

IMAGE_TAG = "sentinel-as-code/zircolite:latest"
_CONFIG_DIR = Path(__file__).resolve().parents[3] / "config" / "zircolite"
_FIRED_PREFIX = "FIRED="


class ZircoliteEngine(DetectionEngine):
    """Evaluate Sigma rules with Zircolite inside a Docker container."""

    name = "zircolite"

    def __init__(self, image_tag: str = IMAGE_TAG, config_dir: Path = _CONFIG_DIR) -> None:
        self.image_tag = image_tag
        self.config_dir = config_dir

    # -- availability -----------------------------------------------------

    def is_available(self) -> bool:
        docker = shutil.which("docker")
        if docker is None:
            return False
        try:
            subprocess.run(
                [docker, "info"],
                check=True,
                capture_output=True,
                timeout=20,
            )
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            return False
        return True

    def ensure_image(self) -> None:
        """Build the Zircolite image if it is not already present."""
        if not self.is_available():
            raise DetectionEngineError(
                "Docker is not available; the Zircolite engine requires Docker. "
                "Use the default Python engine for offline tests."
            )
        exists = subprocess.run(
            ["docker", "image", "inspect", self.image_tag],
            capture_output=True,
        )
        if exists.returncode == 0:
            return
        logger.info("Building Zircolite image %s ...", self.image_tag)
        build = subprocess.run(
            ["docker", "build", "-t", self.image_tag, str(self.config_dir)],
            capture_output=True,
            text=True,
        )
        if build.returncode != 0:
            raise DetectionEngineError(f"Failed to build Zircolite image:\n{build.stderr}")

    # -- evaluation -------------------------------------------------------

    def evaluate(self, rules: Sequence[LoadedRule], log_file: Path) -> set[str]:
        self.ensure_image()
        with tempfile.TemporaryDirectory(prefix="sentinel-zircolite-") as tmp:
            tmp_path = Path(tmp)
            rules_dir = tmp_path / "rules"
            logs_dir = tmp_path / "logs"
            rules_dir.mkdir()
            logs_dir.mkdir()

            # Stage the exact rules under evaluation and the log events.
            for loaded in rules:
                shutil.copy2(loaded.path, rules_dir / loaded.path.name)
            shutil.copy2(log_file, logs_dir / "events.json")

            result = subprocess.run(
                [
                    "docker",
                    "run",
                    "--rm",
                    "--network",
                    "none",
                    "-v",
                    f"{rules_dir}:/rules:ro",
                    "-v",
                    f"{logs_dir}:/logs:ro",
                    self.image_tag,
                ],
                capture_output=True,
                text=True,
            )
            if result.returncode != 0:
                raise DetectionEngineError(
                    f"Zircolite container failed (exit {result.returncode}):\n"
                    f"{result.stderr}\n{result.stdout}"
                )
            return self._parse_fired(result.stdout)

    @staticmethod
    def _parse_fired(stdout: str) -> set[str]:
        for line in reversed(stdout.splitlines()):
            if line.startswith(_FIRED_PREFIX):
                payload = line[len(_FIRED_PREFIX) :].strip()
                try:
                    return {str(rid) for rid in json.loads(payload)}
                except json.JSONDecodeError as exc:  # pragma: no cover - defensive
                    raise DetectionEngineError(
                        f"Could not parse Zircolite output line: {line!r}: {exc}"
                    ) from exc
        raise DetectionEngineError(
            "Zircolite produced no FIRED= result line; output was:\n" + stdout
        )
