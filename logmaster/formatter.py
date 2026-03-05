import typer
from logmaster.runner import Finding

def get_severity_color(severity: str) -> str:
    """Returns a color for a given severity."""
    if severity == "ERROR":
        return typer.colors.RED
    if severity == "WARNING":
        return typer.colors.YELLOW
    return typer.colors.BLUE  # For INFO or other levels

def print_findings(findings: list[Finding]) -> None:
    """
    Prints findings in a Flake8-like format with color-coded severities.
    If no findings are present, prints a success message.
    """
    if not findings:
        typer.secho("✅ Logmaster passed. No issues found.", fg=typer.colors.GREEN)
        return

    # Flake8-like: path:line:col [SEVERITY] CODE message
    for f in findings:
        severity_color = get_severity_color(f.severity)
        severity_text = f"[{f.severity}]".ljust(10) # Pad to align
        code = f.rule_id
        msg = f.message.strip() or "LogMaster finding"

        typer.secho(f"{f.path}:{f.line}:{f.col} ", nl=False)
        typer.secho(severity_text, fg=severity_color, nl=False)
        typer.secho(f" {code} {msg}")