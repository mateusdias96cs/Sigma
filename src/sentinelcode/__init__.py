"""sentinel-as-code — a Detection-as-Code platform built around Sigma rules.

The package exposes independent modules wired together by the Typer CLI:

* :mod:`sentinelcode.rules`     — load, parse and validate Sigma rules.
* :mod:`sentinelcode.engine`    — offline detection engines (TP/FP testing).
* :mod:`sentinelcode.convert`   — Sigma -> Elastic Detection Engine conversion.
* :mod:`sentinelcode.coverage`  — MITRE ATT&CK coverage measurement.
* :mod:`sentinelcode.deploy`    — idempotent publishing to Kibana.
* :mod:`sentinelcode.genrule`   — AI-assisted rule drafting (human in the loop).

Each module depends only on small, explicit interfaces from the others.
"""

from __future__ import annotations

__version__ = "0.1.0"
__all__ = ["__version__"]
