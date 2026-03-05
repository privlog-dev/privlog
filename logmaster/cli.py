import typer
from pathlib import Path
from logmaster.runner import run_analysis
from logmaster.formatter import print_findings

app = typer.Typer(add_completion=False, no_args_is_help=True)

@app.command()
def check(
    path: Path = typer.Argument(Path("."), exists=True),
    config: Path = typer.Option(None, "--config", "-c", help="Optional LogMaster config YAML"),
    rules: Path = typer.Option(None, "--rules", "-r", help="Override rules file/folder"),
    json: bool = typer.Option(False, "--json", help="Output JSON (raw Semgrep)"),
    verbose: bool = typer.Option(False, "--verbose", help="Verbose output"),
    warnings: bool = typer.Option(
        False, "--warnings", "-w", help="Show WARNING findings in addition to ERRORs."
    ),
):
    """
    Run LogMaster checks on a codebase path.
    Exits non-zero if ERROR violations are found.
    """
    result = run_analysis(path=path, config=config, rules=rules, verbose=verbose)

    if json:
        typer.echo(result.raw_json)
    else:
        findings_to_print = result.findings
        if not warnings:
            findings_to_print = [f for f in result.findings if f.severity == "ERROR"]

        # If there are findings, but none to print (because they are warnings),
        # give a specific success message.
        if result.findings and not findings_to_print:
            typer.secho("✅ Logmaster passed. No errors found.", fg=typer.colors.GREEN)
            typer.secho("  (Warnings were found. Run with -w to show them)")
        else:
            print_findings(findings_to_print)

    # The exit code from run_analysis is now based on ERROR-level findings only
    raise typer.Exit(code=result.exit_code)