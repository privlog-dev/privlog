from __future__ import annotations
import json
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from importlib.resources import files

# Use tomllib for Python 3.11+, otherwise tomli
try:
    import tomllib
except ImportError:
    import tomli as tomllib

from .ast_checks import run_ast_checks, AstFinding


@dataclass
class PrivlogConfig:
    custom_wrappers: dict[str, dict[str, str]] = field(default_factory=dict)


@dataclass
class Finding:
    rule_id: str
    severity: str
    message: str
    path: str
    line: int
    col: int


@dataclass
class RunResult:
    findings: list[Finding]
    exit_code: int
    raw_json: str


def _load_config(path: Path) -> PrivlogConfig:
    """Finds and loads privlog config from pyproject.toml."""
    # Find pyproject.toml in the target path or its parents
    root = path.is_dir() and path or path.parent
    pyproject_path = root / "pyproject.toml"
    
    # Search upwards for the config file
    while not pyproject_path.exists():
        if pyproject_path.parent == pyproject_path.parent.parent: # At fs root
            break
        pyproject_path = pyproject_path.parent.parent / "pyproject.toml"

    if not pyproject_path.exists():
        return PrivlogConfig() # Return default config if not found

    try:
        with open(pyproject_path, "rb") as f:
            data = tomllib.load(f)
        
        config_data = data.get("tool", {}).get("privlog", {})
        return PrivlogConfig(
            custom_wrappers=config_data.get("custom_wrappers", {})
        )
    except Exception:
        # On parsing error, return default config
        return PrivlogConfig()


def _default_rules_path() -> Path:
    # Package data path: privlog/rules/privlog.yml
    return Path(files("privlog").joinpath("rules", "privlog.yml"))


def _run_semgrep(path: Path, config: Path | None, rules: Path | None, verbose: bool = False) -> RunResult:
    """Helper to run Semgrep and parse its results."""
    semgrep = shutil.which("semgrep")
    if not semgrep:
        raise RuntimeError(
            "Semgrep not found on PATH. Install with: pip install semgrep "
            "or ensure the semgrep binary is available."
        )

    rules_path = rules if rules else _default_rules_path()
    cmd = [semgrep, "--config", str(rules_path), "--json", str(path)]
    if verbose:
        cmd.insert(1, "--verbose")

    proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8")
    raw = proc.stdout.strip() if proc.stdout else ""

    findings: list[Finding] = []
    if raw:
        data = json.loads(raw)
        for r in data.get("results", []):
            raw_rid = r.get("check_id", "UNKNOWN")
            pl_index = raw_rid.find("PL")
            rid = raw_rid[pl_index:] if pl_index != -1 else raw_rid

            findings.append(
                Finding(
                    rule_id=rid,
                    severity=(r.get("extra", {}).get("severity") or "INFO"),
                    message=(r.get("extra", {}).get("message") or r.get("extra", {}).get("metadata", {}).get("message") or ""),
                    path=r.get("path", ""),
                    line=r.get("start", {}).get("line", 0),
                    col=r.get("start", {}).get("col", 0),
                )
            )
    
    has_errors = any(f.severity == "ERROR" for f in findings)
    exit_code = 1 if has_errors else 0
    return RunResult(findings=findings, exit_code=exit_code, raw_json=raw)


def run_analysis(path: Path, config: Path | None, rules: Path | None, verbose: bool = False) -> RunResult:
    """
    Runs all analysis on the given path, combining Semgrep and AST checks.
    """
    # Load config from the target path
    privlog_config = _load_config(path)

    semgrep_result = _run_semgrep(path, config, rules, verbose)
    ast_findings = run_ast_checks(path, privlog_config)

    # Convert AST findings to the common Finding type
    converted_ast_findings = [
        Finding(
            rule_id=f.code,
            severity=f.severity,
            message=f.message,
            path=f.path,
            line=f.line,
            col=f.col,
        )
        for f in ast_findings
    ]

    # Combine and sort findings
    all_findings = semgrep_result.findings + converted_ast_findings
    all_findings.sort(key=lambda f: (f.path, f.line, f.col))
    
    # Final exit code depends only on ERROR-level findings
    has_errors = any(f.severity == "ERROR" for f in all_findings)
    final_exit_code = 1 if has_errors else 0
    
    # For now, the raw_json from semgrep is preserved. This could be updated
    # to be a combined JSON report if needed in the future.
    return RunResult(
        findings=all_findings,
        exit_code=final_exit_code,
        raw_json=semgrep_result.raw_json
    )
