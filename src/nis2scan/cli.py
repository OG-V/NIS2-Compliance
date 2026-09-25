"""Command-line entry point."""

import json
from collections import Counter
from pathlib import Path
from typing import Annotated

import typer
import yaml
from pydantic import ValidationError
from rich.console import Console
from rich.table import Table

from nis2scan.catalog import load_all_requirements, load_requirements
from nis2scan.config import load_profile, load_target
from nis2scan.extract import sources as legal_sources
from nis2scan.extract.compare import compare as compare_runs
from nis2scan.extract.evaluate import evaluate as run_evaluation
from nis2scan.extract.evaluate import load_gold
from nis2scan.extract.verify import SourceIndex, check_quote
from nis2scan.models import CheckStatus, Requirement, Verdict
from nis2scan.registry import CHECKS, load_all
from nis2scan.scan import NotAuthorised, run_scan, write_results

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
    files = sorted(path.rglob("*.yaml"))
    for file in files:
        try:
            Requirement.model_validate(yaml.safe_load(file.read_text()))
        except ValidationError as exc:
            errors += 1
            typer.echo(f"FAIL {file}\n{exc}", err=True)
    typer.echo(f"{len(files) - errors}/{len(files)} requirement files valid")
    raise typer.Exit(code=1 if errors else 0)


@app.command("checks")
def list_checks(
    markdown: Annotated[
        bool, typer.Option("--markdown", help="Print the mapping document (docs/check-mapping.md).")
    ] = False,
    catalog: Annotated[Path, typer.Option(help="Requirement catalog.")] = Path(
        "catalog/requirements"
    ),
) -> None:
    """List every check and the requirements it maps to."""
    if markdown:
        from nis2scan.mapping import render_markdown

        typer.echo(render_markdown(catalog), nl=False)
        return
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

    scan_target = load_target(target)
    if scan_target.engagement is None:
        console.print(
            "[yellow]No engagement recorded in the target:[/] active tests are skipped. "
            "Add an engagement section with the client's authorisation (see lab/target.yaml)."
        )
    try:
        with console.status("Collecting evidence and running checks..."):
            result = run_scan(scan_target, load_profile(profile), requirements)
    except NotAuthorised as exc:
        console.print(f"[red]Scan refused:[/] {exc}")
        raise typer.Exit(code=2) from None
    run_dir = write_results(result, out, profile)

    findings = Table("Check", "Status", "Result", title=f"Findings: {result.target}")
    per_check = Counter(f.check_id for f in result.findings)
    for f in result.findings:
        style = STATUS_STYLE[f.status]
        label = f"{f.check_id}\n[dim]{f.asset}[/]" if per_check[f.check_id] > 1 else f.check_id
        findings.add_row(label, f"[{style}]{f.status.value}[/]", f.message)
    console.print(findings)

    assessed = [v for v in result.verdicts if v.verdict != Verdict.NOT_ASSESSED]
    verdicts = Table("Requirement", "Provision", "Verdict", title="Assessed requirements")
    for v in assessed:
        style = VERDICT_STYLE[v.verdict]
        verdicts.add_row(
            f"{v.requirement_id}\n[dim]{v.title}[/]", v.provision, f"[{style}]{v.verdict.value}[/]"
        )
    console.print(verdicts)
    counts = {status: sum(v.verdict == status for v in result.verdicts) for status in Verdict}
    console.print(
        ", ".join(f"{n} {status.value}" for status, n in counts.items() if n)
        + f" (of {len(result.verdicts)} requirements; not-assessed ones are listed in the report)"
    )
    if any(v.review_status != "reviewed" for v in result.verdicts):
        console.print("[yellow]Includes draft requirements that have not been reviewed yet.[/]")
    console.print(f"Results written to [bold]{run_dir}[/]")


SOURCES_DIR = Path("sources")
EXTRACTED_DIR = Path("catalog/requirements/cir-2024-2690")
GOLD = Path("eval/gold-cir-2024-2690.yaml")


@app.command("fetch-sources")
def fetch_sources(
    directory: Annotated[Path, typer.Option(help="Where to store the texts.")] = SOURCES_DIR,
) -> None:
    """Download the legal texts from EUR-Lex and store normalised plain text + hashes."""
    manifest_path = directory / "manifest.json"
    old = json.loads(manifest_path.read_text()) if manifest_path.exists() else {}
    entries = {}
    for source in legal_sources.SOURCES.values():
        entries[source.key] = legal_sources.fetch(source, directory)
        changed = old.get(source.key, {}).get("sha256") not in (None, entries[source.key]["sha256"])
        note = "  [yellow]changed: extracted requirements may be stale[/]" if changed else ""
        console.print(f"{source.instrument}: {entries[source.key]['sha256'][:16]}…{note}")
    legal_sources.write_manifest(directory, entries)


@app.command("verify-quotes")
def verify_quotes(
    catalog: Annotated[Path, typer.Option(help="Requirement catalog.")] = Path(
        "catalog/requirements"
    ),
    directory: Annotated[Path, typer.Option(help="Legal source texts.")] = SOURCES_DIR,
) -> None:
    """Check that every non-rejected requirement quotes its provision verbatim."""
    index = SourceIndex(directory)
    reqs = [r for r in load_all_requirements(catalog) if r.review.status != "rejected"]
    failures = [c for c in (check_quote(r, index) for r in reqs) if not c.ok]
    for c in failures:
        console.print(f"[red]{c.status.value}[/] {c.requirement_id} {c.detail}")
    console.print(f"{len(reqs) - len(failures)}/{len(reqs)} quotes verbatim in the cited provision")
    raise typer.Exit(code=1 if failures else 0)


@app.command()
def extract(
    provision: Annotated[
        list[str] | None, typer.Option(help="Annex point to extract, e.g. 11.7.1 (repeatable).")
    ] = None,
    gold: Annotated[bool, typer.Option("--gold", help="Extract the gold-set provisions.")] = False,
    all_provisions: Annotated[
        bool, typer.Option("--all", help="Extract all 159 provisions.")
    ] = False,
    out: Annotated[Path, typer.Option(help="Output directory for draft requirements.")] = (
        EXTRACTED_DIR
    ),
    workers: Annotated[int, typer.Option(help="Parallel API requests.")] = 4,
    model: Annotated[str | None, typer.Option(help="Claude model ID.")] = None,
    effort: Annotated[str | None, typer.Option(help="low, medium, high, xhigh or max.")] = None,
) -> None:
    """Extract draft requirements from the CIR 2024/2690 Annex with Claude (costs API credits)."""
    try:
        import anthropic

        from nis2scan.extract.llm import EFFORT, EFFORTS, MODEL, extract_all
    except ImportError:
        console.print("[red]The LLM extra is not installed:[/] pip install -e '.[llm]'")
        raise typer.Exit(code=2) from None

    text = legal_sources.read_text(legal_sources.CIR_2690, SOURCES_DIR)
    by_number = {p.number: p for p in legal_sources.parse_annex(text)}
    if all_provisions:
        wanted = list(by_number)
    else:
        wanted = list(provision or []) + (list(load_gold(GOLD).provisions) if gold else [])
    unknown = [n for n in wanted if n not in by_number]
    if unknown or not wanted:
        console.print(
            f"[red]Choose provisions with --provision, --gold or --all.[/] Unknown: {unknown}"
        )
        raise typer.Exit(code=2)

    model, effort = model or MODEL, effort or EFFORT
    if effort not in EFFORTS:
        console.print(f"[red]Unknown effort {effort!r}.[/] Choose from {', '.join(EFFORTS)}.")
        raise typer.Exit(code=2)
    client = anthropic.Anthropic()
    try:  # free preflight: fails fast on missing credentials or model access
        client.models.retrieve(model)
    except (TypeError, anthropic.AnthropicError) as exc:
        console.print(
            f"[red]Cannot reach {model}:[/] {exc}\n"
            "Set ANTHROPIC_API_KEY (or log in with `ant auth login`) and try again."
        )
        raise typer.Exit(code=2) from None

    console.print(
        f"Extracting {len(wanted)} provision(s) with {model} (effort {effort}) into {out}"
    )
    source_sha = legal_sources.sha256(SOURCES_DIR / legal_sources.CIR_2690.filename)
    with console.status("Calling the model..."):
        outcomes = extract_all(
            client,
            [by_number[n] for n in wanted],
            out,
            SourceIndex(SOURCES_DIR),
            source_sha,
            workers,
            model,
            effort,
        )
    table = Table("Point", "Written", "Auto-rejected", "Note")
    for o in outcomes:
        table.add_row(o.number, str(o.written), str(o.rejected), o.error or o.skipped)
    console.print(table)
    console.print("Drafts are excluded from scans until reviewed (see catalog/README.md).")


@app.command("evaluate")
def evaluate_extraction(
    directory: Annotated[Path, typer.Argument(help="Directory of extracted requirements.")] = (
        EXTRACTED_DIR
    ),
    gold_file: Annotated[Path, typer.Option("--gold", help="Gold set.")] = GOLD,
    json_out: Annotated[Path | None, typer.Option(help="Also write the results as JSON.")] = None,
) -> None:
    """Score extracted requirements against the gold set (deterministic, no LLM)."""
    gold_set = load_gold(gold_file)
    result = run_evaluation(directory, gold_set, SourceIndex(SOURCES_DIR))
    if gold_set.status != "reviewed":
        console.print(f"[yellow]Gold set status is '{gold_set.status}': not human-verified yet.[/]")

    table = Table(
        "Point",
        "Extracted",
        "Quotes ok",
        "Count ok",
        "Obligations",
        "Invented terms",
        "Vague values",
    )
    for p in result.scores:
        invented = "; ".join(
            f"{i.rsplit('-', 1)[1]}: {', '.join(t)}" for i, t in p.invented.items()
        )
        table.add_row(
            p.number,
            str(p.extracted),
            f"{p.quotes_valid}/{p.extracted}",
            "yes" if p.count_ok else "[red]no[/]",
            f"{p.obligations_found}/{p.obligations_total}",
            invented,
            str(len(p.vague)) if p.vague else "",
        )
    console.print(table)
    summary = result.summary()
    for key, value in summary.items():
        console.print(f"{key:28} {value}")
    if result.not_extracted:
        console.print(f"[yellow]Not extracted yet:[/] {', '.join(result.not_extracted)}")
    if json_out:
        json_out.write_text(
            json.dumps(
                {"summary": summary, "provisions": [vars(p) for p in result.scores]}, indent=2
            )
            + "\n"
        )


@app.command("compare")
def compare_extractions(
    run_a: Annotated[Path, typer.Argument(help="First extraction directory.")],
    run_b: Annotated[Path, typer.Argument(help="Second extraction directory.")],
    json_out: Annotated[Path | None, typer.Option(help="Also write the results as JSON.")] = None,
) -> None:
    """Measure how much two extraction runs of the same provisions agree."""
    result = compare_runs(run_a, run_b)
    table = Table("Point", "Count A", "Count B", "Same clauses", "Overlap", "Testability agrees")
    for d in result.diffs:
        table.add_row(
            d.number,
            str(d.count_a),
            str(d.count_b),
            str(d.matched),
            f"{d.overlap:.2f}",
            f"{d.testability_agree}/{d.matched}",
        )
    console.print(table)
    summary = result.summary()
    for key, value in summary.items():
        console.print(f"{key:28} {value}")
    for label, missing in (("only in A", result.only_in_a), ("only in B", result.only_in_b)):
        if missing:
            console.print(f"[yellow]Provisions {label}:[/] {', '.join(missing)}")
    if json_out:
        json_out.write_text(
            json.dumps(
                {"summary": summary, "provisions": [vars(d) for d in result.diffs]}, indent=2
            )
            + "\n"
        )


@app.command()
def report(
    run_dir: Annotated[Path, typer.Argument(help="Scan result directory (out/<target>-<time>).")],
    narrate: Annotated[
        bool, typer.Option("--narrate", help="Add an AI-drafted narrative (costs API credits).")
    ] = False,
    model: Annotated[str | None, typer.Option(help="Claude model ID for --narrate.")] = None,
    effort: Annotated[str | None, typer.Option(help="Effort for --narrate.")] = None,
) -> None:
    """Render a scan as an HTML report, optionally with a validated AI narrative."""
    from dataclasses import asdict

    from nis2scan.report.data import load_run
    from nis2scan.report.render import render

    data = load_run(run_dir)
    if narrate:
        try:
            import anthropic

            from nis2scan.report.narrate import EFFORT, MODEL
            from nis2scan.report.narrate import narrate as write_narrative
        except ImportError:
            console.print("[red]The LLM extra is not installed:[/] pip install -e '.[llm]'")
            raise typer.Exit(code=2) from None
        model, effort = model or MODEL, effort or EFFORT
        client = anthropic.Anthropic()
        try:
            client.models.retrieve(model)
        except (TypeError, anthropic.AnthropicError) as exc:
            console.print(f"[red]Cannot reach {model}:[/] {exc}")
            raise typer.Exit(code=2) from None
        with console.status(f"Drafting and validating the narrative with {model}..."):
            result = write_narrative(client, data, model, effort)
        (run_dir / "narrative.json").write_text(json.dumps(asdict(result), indent=2) + "\n")
        if result.status == "accepted":
            console.print(f"Narrative accepted on attempt {result.attempts}.")
        else:
            console.print("[yellow]Narrative rejected; the report is rendered without it:[/]")
            for problem in result.violations:
                console.print(f"  - {problem}")

    html_path, json_path = render(data, run_dir)
    console.print(f"Report written to [bold]{html_path}[/] and {json_path.name}")


@app.command()
def onboard(
    target: Annotated[Path, typer.Option(help="Target description file.")] = Path(
        "lab/target.yaml"
    ),
    probe: Annotated[
        bool, typer.Option(help="Check reachability, detect products and look for secrets.")
    ] = True,
    checklist: Annotated[
        Path | None, typer.Option(help="Also write the checklist as Markdown for the client.")
    ] = None,
) -> None:
    """List the access each system needs for a scan, and whether it is in place."""
    from datetime import UTC, datetime

    from nis2scan.onboarding import MISSING, OK, OPTIONAL, authorisation, checklist_markdown, plan

    scan_target = load_target(target)
    with console.status("Checking access..."):
        systems = plan(scan_target, probe=probe)
    auth = authorisation(scan_target, datetime.now(UTC).astimezone().date())  # local date
    mark = {OK: "[green]✓[/]", MISSING: "[red]✗[/]", OPTIONAL: "[yellow]○[/]"}

    def line(a) -> str:
        note = f" [dim]· {a.note}[/]" if a.note else ""
        return f"  {mark.get(a.status, '[dim]?[/]')} {a.what}{note}"

    console.print(f"[bold]Onboarding: {scan_target.name}[/]\n")
    console.print("[bold]Authorisation[/]")
    console.print(line(auth))
    for s in systems:
        product = f" · {s.product}" if s.product else ""
        how = f"\n  [dim]{s.identified_by}[/]" if s.identified_by else ""
        console.print(f"\n[bold]{s.name}[/] [dim]{s.kind}[/]{product}{how}")
        for a in s.access:
            console.print(line(a))
    ready = sum(s.ready for s in systems)
    console.print(
        f"\n{ready} of {len(systems)} systems ready"
        + ("" if auth.status == OK else "; [red]authorisation missing or not valid today[/]")
        + ("" if probe else " [dim](not probed: ? means not checked)[/]")
    )
    if checklist:
        checklist.write_text(checklist_markdown(scan_target, systems, auth))
        console.print(f"Checklist written to [bold]{checklist}[/]")


@app.command("diff")
def diff(
    before: Annotated[Path, typer.Argument(help="The earlier scan result directory.")],
    after: Annotated[Path, typer.Argument(help="The later scan result directory.")],
    out: Annotated[
        Path | None, typer.Option(help="Where to write the HTML (default: AFTER/diff.html).")
    ] = None,
) -> None:
    """Compare two scans of the same target: what was fixed, what is still open, what is new."""
    from nis2scan.report.compare import render_comparison

    html_path, json_path, c = render_comparison(before, after, out or after / "diff.html")
    for warning in c.warnings:
        console.print(f"[yellow]{warning}[/]")
    console.print(
        f"[green]{len(c.fixed)} fixed[/] · {len(c.still_open)} still open · "
        f"[red]{len(c.new)} new[/]"
        + (f" · {len(c.unresolved)} could not be compared" if c.unresolved else "")
    )
    console.print(f"Comparison written to [bold]{html_path}[/] and {json_path.name}")


if __name__ == "__main__":
    app()
