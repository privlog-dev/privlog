import typer
from pathlib import Path
from typing import Optional
import importlib.metadata
from privlog.runner import run_analysis
from privlog.formatter import print_findings

__version__ = "0.2.1"

def version_callback(value: bool):
    if value:
        typer.echo(f"privlog version {__version__}")
        raise typer.Exit()

app = typer.Typer(add_completion=False, no_args_is_help=False)

@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    path: Path = typer.Argument(Path("."), exists=True, help="Path to scan."),
    config: Path = typer.Option(None, "--config", "-c", help="Optional privlog config YAML"),
    rules: Path = typer.Option(None, "--rules", "-r", help="Override rules file/folder"),
    json: bool = typer.Option(False, "--json", help="Output JSON (raw Semgrep)"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose output"),
    warnings: bool = typer.Option(
        False, "--warnings", "-w", help="Show WARNING findings in addition to ERRORs."
    ),
    version: Optional[bool] = typer.Option(
        None, "--version", callback=version_callback, is_eager=True, help="Show the version and exit."
    ),
):
    """
    Run privlog checks on a codebase path.
    Exits non-zero if ERROR violations are found.
    """
    if ctx.invoked_subcommand is not None:
        return  # Should not happen with a single command, but good practice

    result = run_analysis(path=path, config=config, rules=rules, verbose=verbose)

    if json:
        typer.echo(result.raw_json)
    else:
        findings_to_print = result.findings
        if not warnings:
            findings_to_print = [f for f in result.findings if f.severity == "ERROR"]

        if result.findings and not findings_to_print:
            typer.secho("✅ privlog passed. No errors found.", fg=typer.colors.GREEN)
            typer.secho("  (Warnings were found. Run with -w to show them)")
        else:
            print_findings(findings_to_print)

    raise typer.Exit(code=result.exit_code)