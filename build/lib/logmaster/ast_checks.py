from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

LOG_FUNCS = {"debug", "info", "warning", "error", "critical", "exception"}

# High-signal sensitive identifiers (tune as needed)
SENSITIVE_NAMES = {
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
    path: str
    line: int
    col: int

def _is_logging_call(node: ast.Call) -> bool:
    # Matches logging.info(...) or logger.info(...)
    if isinstance(node.func, ast.Attribute) and node.func.attr in LOG_FUNCS:
        return True
    return False

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

def _check_fstring_for_sensitive(formatted: ast.FormattedValue) -> bool:
    # Return True if it contains sensitive names not safely wrapped
    expr = formatted.value

    # Allow slicing, which is a form of truncation
    if isinstance(expr, ast.Subscript):
        return False

    # Allow safe wrapper calls directly
    if _is_safe_wrapper(expr):
        return False

    # Allow known-safe name variables
    names = _names_in_expr(expr)
    if any(n in SAFE_NAMES for n in names):
        return False

    # Flag if any sensitive name appears
    # NOTE: this catches direct `email`, `wix_user_id`, etc.
    if any(n.lower() in SENSITIVE_NAMES for n in names):
        return True

    return False

class _Visitor(ast.NodeVisitor):
    def __init__(self, path: str) -> None:
        self.path = path
        self.findings: list[AstFinding] = []

    def visit_Call(self, node: ast.Call) -> None:
        if _is_logging_call(node) and node.args:
            first = node.args[0]
            if isinstance(first, ast.JoinedStr):  # f-string
                for part in first.values:
                    if isinstance(part, ast.FormattedValue):
                        if _check_fstring_for_sensitive(part):
                            self.findings.append(
                                AstFinding(
                                    code="LM2101",
                                    message="Sensitive identifier interpolated into f-string log. Hash/pseudonymize or omit.",
                                    path=self.path,
                                    line=getattr(node, "lineno", 1),
                                    col=getattr(node, "col_offset", 0) + 1,
                                )
                            )
                            break
        self.generic_visit(node)

def run_ast_checks(root: Path) -> list[AstFinding]:
    findings: list[AstFinding] = []
    for py in root.rglob("*.py"):
        try:
            text = py.read_text(encoding="utf-8", errors="replace")
            tree = ast.parse(text)
            v = _Visitor(str(py))
            v.visit(tree)
            findings.extend(v.findings)
        except SyntaxError:
            # Ignore files that aren't parseable in current context
            continue
    return findings