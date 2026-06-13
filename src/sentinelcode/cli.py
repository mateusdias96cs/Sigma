"""The unified ``sentinel`` command line interface.

Each subcommand maps 1:1 to a Makefile target so contributors and CI invoke the
exact same code paths. Heavy modules are imported lazily inside each command so
that, for example, ``sentinel validate`` does not import the Elastic backend.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path

import typer
from rich.console import Console
from rich.logging import RichHandler
from rich.table import Table

app = typer.Typer(
    name="sentinel",
    help="Detection-as-Code: manage Sigma rules as code (test, convert, cover, deploy, generate).",
    no_args_is_help=True,
    add_completion=False,
)
console = Console()
err_console = Console(stderr=True)

# Default project paths, all overridable per command.
DEFAULT_DETECTIONS = Path("detections")
DEFAULT_TESTS_LOGS = Path("tests/logs")
DEFAULT_BUILD = Path("build")
DEFAULT_COVERAGE = Path("coverage")
DEFAULT_CONFIG = Path("config")
DEFAULT_DRAFTS = Path("drafts")


def _configure_logging(verbose: bool) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(message)s",
        datefmt="[%X]",
        handlers=[RichHandler(console=err_console, show_path=False, rich_tracebacks=True)],
    )


@app.callback()
def main(
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable debug logging."),
) -> None:
    """Top-level options shared by all subcommands."""
    _configure_logging(verbose)


@app.command()
def validate(
    detections: Path = typer.Option(DEFAULT_DETECTIONS, help="Directory of Sigma rules."),
) -> None:
    """Validate every Sigma rule (metadata + ATT&CK tags + pySigma validators)."""
    from sentinelcode.rules import validate_rules

    results = validate_rules(detections)
    failures = [r for r in results if not r.ok]

    table = Table(title="Sigma rule validation", show_lines=False)
    table.add_column("Rule", style="cyan", no_wrap=False)
    table.add_column("Status")
    table.add_column("Issues")
    for res in results:
        status = "[green]PASS[/green]" if res.ok else "[red]FAIL[/red]"
        issues = "\n".join(res.errors) if res.errors else "-"
        table.add_row(res.path.name, status, issues)
    console.print(table)

    if failures:
        err_console.print(f"[red]{len(failures)} rule(s) failed validation.[/red]")
        raise typer.Exit(code=1)
    console.print(f"[green]All {len(results)} rule(s) passed validation.[/green]")


@app.command()
def test(
    detections: Path = typer.Option(DEFAULT_DETECTIONS, help="Directory of Sigma rules."),
    logs: Path = typer.Option(DEFAULT_TESTS_LOGS, help="Directory of TP/FP sample logs."),
    engine: str | None = typer.Option(
        None, help="Detection engine: 'python' (default) or 'zircolite'."
    ),
) -> None:
    """Run the offline TP/FP detection tests (no Elastic required)."""
    from sentinelcode.engine import get_engine
    from sentinelcode.rules import load_rules

    det_engine = get_engine(engine)
    rules = load_rules(detections)
    console.print(f"Testing {len(rules)} rule(s) with the [bold]{det_engine.name}[/bold] engine.\n")

    failures = 0
    table = Table(title="True-positive / false-positive results")
    table.add_column("Rule", style="cyan")
    table.add_column("TP fires")
    table.add_column("FP silent")
    for rule in rules:
        log_dir = logs / rule.id
        tp_file = log_dir / "true_positive.jsonl"
        fp_file = log_dir / "false_positive.jsonl"
        if not tp_file.exists() or not fp_file.exists():
            table.add_row(rule.title, "[red]missing logs[/red]", "[red]missing logs[/red]")
            failures += 1
            continue
        tp_ok = rule.id in det_engine.evaluate([rule], tp_file)
        fp_ok = rule.id not in det_engine.evaluate([rule], fp_file)
        table.add_row(
            rule.title,
            "[green]yes[/green]" if tp_ok else "[red]no[/red]",
            "[green]yes[/green]" if fp_ok else "[red]no[/red]",
        )
        if not (tp_ok and fp_ok):
            failures += 1
    console.print(table)

    if failures:
        err_console.print(f"[red]{failures} rule(s) failed TP/FP testing.[/red]")
        raise typer.Exit(code=1)
    console.print(f"[green]All {len(rules)} rule(s) passed TP/FP testing.[/green]")


@app.command()
def coverage(
    detections: Path = typer.Option(DEFAULT_DETECTIONS, help="Directory of Sigma rules."),
    out_dir: Path = typer.Option(DEFAULT_COVERAGE, help="Output directory for coverage artifacts."),
) -> None:
    """Generate the ATT&CK Navigator layer and the Markdown coverage summary."""
    from sentinelcode.coverage import generate_coverage

    layer_path, summary_path, report = generate_coverage(detections, out_dir)
    console.print(
        f"[green]Coverage generated:[/green] {report.covered_technique_count} technique(s) "
        f"across {len(report.tactics)} tactic(s)."
    )
    console.print(f"  Navigator layer: {layer_path}")
    console.print(f"  Summary:         {summary_path}")


@app.command()
def convert(
    detections: Path = typer.Option(DEFAULT_DETECTIONS, help="Directory of Sigma rules."),
    out_dir: Path = typer.Option(DEFAULT_BUILD / "elastic", help="Output directory for NDJSON."),
    pipeline: Path = typer.Option(
        DEFAULT_CONFIG / "sigma_pipeline.yml", help="ECS processing pipeline."
    ),
) -> None:
    """Convert every rule to Elastic Detection Engine NDJSON."""
    from sentinelcode.convert import convert_rules

    ndjson_path, queries = convert_rules(detections, out_dir, pipeline)
    console.print(f"[green]Converted {len(queries)} rule(s).[/green]")
    console.print(f"  NDJSON: {ndjson_path}")
    for rule_title, query in queries:
        console.print(f"  [dim]{rule_title}[/dim]: {query}")


@app.command()
def deploy(
    detections: Path = typer.Option(DEFAULT_DETECTIONS, help="Directory of Sigma rules."),
    build_dir: Path = typer.Option(DEFAULT_BUILD / "elastic", help="NDJSON build directory."),
    pipeline: Path = typer.Option(
        DEFAULT_CONFIG / "sigma_pipeline.yml", help="ECS processing pipeline."
    ),
    dry_run: bool = typer.Option(False, help="Convert and show the plan without calling Kibana."),
) -> None:
    """Idempotently publish rules to the local Kibana Detection Engine."""
    from sentinelcode.deploy import deploy_rules

    summary = deploy_rules(detections, build_dir, pipeline, dry_run=dry_run)
    console.print(
        f"[green]Deploy {'(dry run) ' if dry_run else ''}complete:[/green] "
        f"{summary.created} created, {summary.updated} updated, {summary.skipped} skipped."
    )


@app.command()
def genrule(
    report: Path = typer.Option(..., help="Path to a threat report (plain text)."),
    drafts_dir: Path = typer.Option(DEFAULT_DRAFTS, help="Output directory for AI drafts."),
    provider: str | None = typer.Option(
        None, help="AI provider (default: env AI_PROVIDER or 'gemini')."
    ),
) -> None:
    """Generate a Sigma rule DRAFT from a threat report (human-in-the-loop)."""
    from sentinelcode.genrule import generate_rule_draft

    result = generate_rule_draft(report, drafts_dir, provider=provider)
    console.print("[green]Draft generated for human review (NOT published):[/green]")
    console.print(f"  Rule:  {result.rule_path}")
    console.print(f"  TP log: {result.true_positive_path}")
    console.print(f"  FP log: {result.false_positive_path}")
    if result.validation_errors:
        err_console.print("[yellow]Draft has validation issues to fix before review:[/yellow]")
        for issue in result.validation_errors:
            err_console.print(f"  - {issue}")
    else:
        console.print(
            "[green]Draft passes validation.[/green] Review it, then move it into detections/."
        )


def _env_flag(name: str) -> bool:
    return os.environ.get(name, "").lower() in {"1", "true", "yes"}


if __name__ == "__main__":  # pragma: no cover
    app()
