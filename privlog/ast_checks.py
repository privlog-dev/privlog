from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path
import typer

# A forward declaration is needed for the type hint in this file
class PrivlogConfig: ...

LOG_FUNCS = {"debug", "info", "warning", "error", "critical", "exception"}

# High-confidence = ERROR
HIGH_CONFIDENCE_SENSITIVE_NAMES = {
    "wix_user_id",
    "email",
    "ip",
    "client_ip",
    "remote_ip",
    "x_forwarded_for",
    "authorization",
    "cookie",
    "set_cookie",
    "token",
    "jwt",
    "secret",
    "api_key",
    "password",
    # Stripe IDs
    "stripe_subscription_id",
    "stripe_customer_id",
    "stripe_payment_intent_id",
    "stripe_charge_id",
    "stripe_invoice_id",
    "stripe_price_id",
}

# Medium-confidence = WARNING
WARNING_SENSITIVE_NAMES = {
    "identifier",
    "id",
    "key",
}

SAFE_NAMES = {
    "hashed_ip",
    "salted_hash",
    "ip_hash",
    "identifier_hash",
}

SAFE_WRAPPERS = {"get_salted_identifier"}


@dataclass
class AstFinding:
    code: str
    message: str
    severity: str
    path: str
    line: int
    col: int


def _is_logging_call(node: ast.Call) -> bool:
    # Matches logging.info(...) or logger.info(...)
    if isinstance(node.func, ast.Attribute) and node.func.attr in LOG_FUNCS:
        return True
    return False

def _is_print_call(node: ast.Call) -> bool:
    return isinstance(node.func, ast.Name) and node.func.id == 'print'


def _names_in_expr(expr: ast.AST) -> set[str]:
    names: set[str] = set()
    for n in ast.walk(expr):
        if isinstance(n, ast.Name):
            names.add(n.id)
        elif isinstance(n, ast.Attribute):
            # capture attribute base name if simple: request.state.ip -> request
            if isinstance(n.value, ast.Name):
                names.add(n.value.id)
    return names


def _is_safe_wrapper(expr: ast.AST) -> bool:
    # get_salted_identifier(...)
    return (
        isinstance(expr, ast.Call)
        and isinstance(expr.func, ast.Name)
        and expr.func.id in SAFE_WRAPPERS
    )


def _get_expr_sensitivity(expr: ast.AST) -> tuple[str, str] | None:
    """
    Checks an expression for sensitive names.
    Returns a tuple of (severity, sensitive_name) or None if not sensitive.
    """
    # Allow slicing, which is a form of truncation
    if isinstance(expr, ast.Subscript):
        return None

    # Allow safe wrapper calls directly
    if _is_safe_wrapper(expr):
        return None

    names = _names_in_expr(expr)
    # Allow known-safe name variables
    if any(n in SAFE_NAMES for n in names):
        return None

    # Flag if any sensitive name appears
    for name in names:
        if name.lower() in HIGH_CONFIDENCE_SENSITIVE_NAMES:
            return "ERROR", name
            
    for name in names:
        if name.lower() in WARNING_SENSITIVE_NAMES:
            return "WARNING", name

    return None


class _Visitor(ast.NodeVisitor):
    def __init__(self, path: str, config: PrivlogConfig) -> None:
        self.path = path
        self.config = config
        self.findings: list[AstFinding] = []

    def _add_finding(self, node: ast.Call, code: str, message: str, severity: str) -> None:
        # Avoid adding duplicate findings for the same line/call
        for f in self.findings:
            if f.line == getattr(node, "lineno", 1) and f.code == code:
                return
        self.findings.append(
            AstFinding(
                code=code,
                message=message,
                severity=severity,
                path=self.path,
                line=getattr(node, "lineno", 1),
                col=getattr(node, "col_offset", 0) + 1,
            )
        )

    def visit_Call(self, node: ast.Call) -> None:
        is_log = _is_logging_call(node)
        is_print = _is_print_call(node)
        
        # Determine if it's a custom wrapper call
        func_name = node.func.id if isinstance(node.func, ast.Name) else ""
        is_custom_wrapper = func_name in self.config.custom_wrappers

        if not is_log and not is_print and not is_custom_wrapper:
            self.generic_visit(node)
            return

        # Check 1: Direct sensitive identifiers in formatted strings/args
        if node.args and (is_log or is_print):
            args_to_check: list[ast.AST] = []
            if is_print:
                 args_to_check.extend(node.args)

            first_arg = node.args[0]
            # Case 1a: f-string
            if isinstance(first_arg, ast.JoinedStr):
                args_to_check.extend(part.value for part in first_arg.values if isinstance(part, ast.FormattedValue))
            # Case 1b: .format() call
            elif (isinstance(first_arg, ast.Call) and isinstance(first_arg.func, ast.Attribute) and first_arg.func.attr == "format"):
                args_to_check.extend(first_arg.args)
                args_to_check.extend(kw.value for kw in first_arg.keywords)
            # Case 1c: %-formatting (for logs only)
            elif (is_log and len(node.args) > 1 and isinstance(first_arg, ast.Constant) and isinstance(first_arg.value, str) and "%" in first_arg.value):
                if len(node.args) == 2 and isinstance(node.args[1], (ast.Tuple, ast.Dict)):
                    if isinstance(node.args[1], ast.Tuple):
                        args_to_check.extend(node.args[1].elts)
                else:
                    args_to_check.extend(node.args[1:])

            for arg in args_to_check:
                sensitivity = _get_expr_sensitivity(arg)
                if sensitivity:
                    severity, name = sensitivity
                    code = "PL2301" if is_print else "PL2101"
                    call_type = "print()" if is_print else "log"
                    message = f'Sensitive identifier "{name}" passed to {call_type}. Hash, pseudonymize, or omit before logging.'
                    self._add_finding(node, code, message, severity)
                    break
        
        # Check 2: Heuristic checks for dictionary/object logging
        if is_log:
            for keyword in node.keywords:
                if keyword.arg == 'extra':
                    self._add_finding(node, "PL2201", "Logging with 'extra' parameter may leak sensitive data. Please review manually.", "WARNING")
                    break
        
        # Check 3: Custom wrapper checks
        if is_custom_wrapper:
            wrapper_rules = self.config.custom_wrappers[func_name]
            for kw in node.keywords:
                if kw.arg in wrapper_rules:
                    severity = wrapper_rules[kw.arg]
                    self._add_finding(node, "PL2401", f"Sensitive argument '{kw.arg}' passed to custom wrapper '{func_name}'.", severity)

        # Common heuristic checks for all call types
        for arg in node.args:
            if isinstance(arg, ast.Call) and isinstance(arg.func, ast.Attribute):
                if isinstance(arg.func.value, ast.Name) and arg.func.value.id == 'json' and arg.func.attr == 'dumps':
                    code = "PL2302" if is_print else "PL2202"
                    self._add_finding(node, code, "Object serialized as JSON may be sensitive. Review manually.", "WARNING")
                if arg.func.attr == 'to_dict':
                    code = "PL2303" if is_print else "PL2203"
                    self._add_finding(node, code, "Object converted to dict may be sensitive. Review manually.", "WARNING")

        self.generic_visit(node)


DEFAULT_IGNORE_DIRS = {
    ".venv",
    "venv",
    "env",
    "site-packages",
    "__pycache__",
    "dist",
    "build",
    ".git",
}

def _collect_python_files(root: Path) -> list[Path]:
    """Recursively finds all Python files in a directory, respecting ignores."""
    all_files = []
    for py in root.rglob("*.py"):
        if any(part in DEFAULT_IGNORE_DIRS for part in py.parts):
            continue
        all_files.append(py)
    return all_files


def run_ast_checks(root: Path, config: PrivlogConfig) -> list[AstFinding]:
    """
    Scans for sensitive data in Python files using AST checks.
    """
    findings: list[AstFinding] = []
    
    files_to_scan = _collect_python_files(root)
    total_files = len(files_to_scan)

    typer.secho(f"Running AST checks on {total_files} Python files...", fg=typer.colors.BLUE)

    for i, py in enumerate(files_to_scan):
        # \r to return to start of line, \x1b[K to clear line
        progress_msg = f"Scanning [{i + 1}/{total_files}] {str(py)}"
        typer.secho(f"\r\x1b[K{progress_msg}", fg=typer.colors.WHITE, nl=False)

        try:
            text = py.read_text(encoding="utf-8", errors="replace")
            tree = ast.parse(text)
            v = _Visitor(str(py), config)
            v.visit(tree)
            findings.extend(v.findings)
        except SyntaxError:
            continue
        except Exception:
            # Fallback for other file-read errors
            continue
    
    # Clear the line and print a final message
    typer.secho("\r\x1b[KAST checks complete.", fg=typer.colors.BLUE)

    return findings