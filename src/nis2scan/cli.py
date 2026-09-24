"""Command-line entry point."""

from pathlib import Path
from typing import Annotated

import typer
import yaml
from pydantic import ValidationError
from rich.console import Console
from rich.table import Table

from nis2scan.catalog import load_requirements
from nis2scan.config import load_profile, load_target
from nis2scan.models import CheckStatus, Requirement, Verdict
from nis2scan.registry import CHECKS, load_all
from nis2scan.scan import run_scan, write_results

app = typer.Typer(no_args_is_help=True, help="NIS2 evidence scanner.")
console = Console()

VERDICT_STYLE = {
    Verdict.EVIDENCED: "green",
    Verdict.PARTIALLY_EVIDENCED: "yellow",
    Verdict.NOT_SATISFIED: "bold red",
    Verdict.NOT_ASSESSED: "dim",
}
STATUS_STYLE = {
    CheckStatus.PASS: "green",
    CheckStatus.FAIL: "bold red",
    CheckStatus.ERROR: "magenta",
    CheckStatus.NOT_APPLICABLE: "dim",
}


@app.command()
def validate_catalog(path: Path = Path("catalog/requirements")) -> None:
    """Validate every requirement YAML file against the schema."""
    errors = 0
    files = sorted(path.glob("*.yaml"))
    for file in files:
        try:
            Requirement.model_validate(yaml.safe_load(file.read_text()))
        except ValidationError as exc:
            errors += 1
            typer.echo(f"FAIL {file}\n{exc}", err=True)
    typer.echo(f"{len(files) - errors}/{len(files)} requirement files valid")
    raise typer.Exit(code=1 if errors else 0)


@app.command("checks")
def list_checks() -> None:
    """List every check and the requirements it maps to."""
    load_all()
    table = Table("Check", "Title", "Requirements", "Coverage", "Severity")
    for chk in sorted(CHECKS.values(), key=lambda c: c.meta.id):
        m = chk.meta
        table.add_row(m.id, m.title, ", ".join(m.requirements), m.coverage, m.severity)
    console.print(table)


@app.command()
def scan(
    target: Annotated[Path, typer.Option(help="Target description file.")] = Path(
        "lab/target.yaml"
    ),
    profile: Annotated[Path, typer.Option(help="Organisational profile.")] = Path(
        "catalog/profile.yaml"
    ),
    catalog: Annotated[Path, typer.Option(help="Requirement catalog.")] = Path(
        "catalog/requirements"
    ),
    out: Annotated[Path, typer.Option(help="Directory for scan results.")] = Path("out"),
    include_drafts: Annotated[
        bool, typer.Option(help="Also evaluate requirements still in 'draft' review status.")
    ] = False,
) -> None:
    """Collect evidence, run all checks and write findings and verdicts."""
    requirements = load_requirements(catalog, include_drafts=include_drafts)
    if not requirements:
        console.print(
            "[red]No requirements loaded.[/] All requirements are drafts until reviewed; "
            "pass --include-drafts to evaluate them anyway."
        )
        raise typer.Exit(code=2)

    with console.status("Collecting evidence and running checks..."):
        result = run_scan(load_target(target), load_profile(profile), requirements)
    run_dir = write_results(result, out, profile)

    findings = Table("Check", "Status", "Result", title=f"Findings: {result.target}")
    for f in result.findings:
        style = STATUS_STYLE[f.status]
        findings.add_row(f.check_id, f"[{style}]{f.status.value}[/]", f.message)
    console.print(findings)

    verdicts = Table("Requirement", "Provision", "Verdict", "Review", title="Requirement verdicts")
    for v in result.verdicts:
        style = VERDICT_STYLE[v.verdict]
        verdicts.add_row(
            f"{v.requirement_id}\n[dim]{v.title}[/]",
            v.provision,
            f"[{style}]{v.verdict.value}[/]",
            v.review_status.value,
        )
    console.print(verdicts)
    if any(v.review_status != "reviewed" for v in result.verdicts):
        console.print("[yellow]Includes draft requirements that have not been reviewed yet.[/]")
    console.print(f"Results written to [bold]{run_dir}[/]")


if __name__ == "__main__":
    app()
