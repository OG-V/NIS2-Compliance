"""Command-line entry point."""

from pathlib import Path

import typer
import yaml
from pydantic import ValidationError

from nis2scan.models import Requirement

app = typer.Typer(no_args_is_help=True, help="NIS2 evidence scanner.")


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


@app.command()
def scan() -> None:
    """Run deterministic checks against the lab target (milestone 3)."""
    raise NotImplementedError


if __name__ == "__main__":
    app()
