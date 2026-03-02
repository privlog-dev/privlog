import typer
from logmaster.runner import Finding

def print_findings(findings: list[Finding]) -> None:
    """
    Prints findings in a Flake8-like format.
    If no findings are present, prints a success message.
    """
    if not findings:
        typer.secho("✅ Logmaster passed. No issues found.", fg=typer.colors.GREEN)
        return

    # Flake8-like: path:line:col CODE message
    for f in findings:
        code = f.rule_id
        msg = f.message.strip() or "LogMaster finding"
        print(f"{f.path}:{f.line}:{f.col} {code} {msg}")