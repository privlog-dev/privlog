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
):
    """
    Run LogMaster checks on a codebase path.
    Exits non-zero if violations are found.
    """
    result = run_analysis(path=path, config=config, rules=rules, verbose=verbose)

    if json:
        typer.echo(result.raw_json)
    else:
        print_findings(result.findings)

    raise typer.Exit(code=0 if result.exit_code == 0 else 1)