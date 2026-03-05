from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path

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


def _get_expr_sensitivity(expr: ast.AST) -> str | None:
    """
    Checks an expression for sensitive names.
    Returns severity ('ERROR', 'WARNING') or None if not sensitive.
    """
    # Allow slicing, which is a form of truncation
    if isinstance(expr, ast.Subscript):
        return None

    # Allow safe wrapper calls directly
    if _is_safe_wrapper(expr):
        return None

    # Allow known-safe name variables
    names = _names_in_expr(expr)
    if any(n in SAFE_NAMES for n in names):
        return None

    # Flag if any sensitive name appears
    if any(n.lower() in HIGH_CONFIDENCE_SENSITIVE_NAMES for n in names):
        return "ERROR"
    
    if any(n.lower() in WARNING_SENSITIVE_NAMES for n in names):
        return "WARNING"

    return None


class _Visitor(ast.NodeVisitor):
    def __init__(self, path: str) -> None:
        self.path = path
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

        if not is_log and not is_print:
            self.generic_visit(node)
            return

        # Check 1: Direct sensitive identifiers in formatted strings/args
        if node.args:
            args_to_check: list[ast.AST] = []
            # For print calls, all arguments are checked directly.
            # For log calls, only format arguments are checked.
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
            # Case 1c: %-formatting (for logs only, print doesn't use this pattern)
            elif (is_log and len(node.args) > 1 and isinstance(first_arg, ast.Constant) and isinstance(first_arg.value, str) and "%" in first_arg.value):
                if len(node.args) == 2 and isinstance(node.args[1], (ast.Tuple, ast.Dict)):
                    if isinstance(node.args[1], ast.Tuple):
                        args_to_check.extend(node.args[1].elts)
                    elif isinstance(node.args[1], ast.Dict):
                        args_to_check.extend(node.args[1].values)
                else:
                    args_to_check.extend(node.args[1:])

            for arg in args_to_check:
                severity = _get_expr_sensitivity(arg)
                if severity:
                    code = "LM2301" if is_print else "LM2101"
                    call_type = "print()" if is_print else "log"
                    self._add_finding(node, code, f"Sensitive identifier passed to {call_type}. Hash/pseudonymize or omit.", severity)
                    break
        
        # Check 2: Heuristic checks for dictionary/object logging
        if is_log:
            # LM2201: Use of 'extra' keyword
            for keyword in node.keywords:
                if keyword.arg == 'extra':
                    self._add_finding(node, "LM2201", "Logging with 'extra' parameter can hide sensitive data. Review manually.", "WARNING")
                    break
        
        # LM2202/LM2203/LM2302/LM2303: Serialized objects
        for arg in node.args:
            if isinstance(arg, ast.Call) and isinstance(arg.func, ast.Attribute):
                # json.dumps(foo)
                if isinstance(arg.func.value, ast.Name) and arg.func.value.id == 'json' and arg.func.attr == 'dumps':
                    code = "LM2302" if is_print else "LM2202"
                    self._add_finding(node, code, "Potentially sensitive object serialized as JSON. Review manually.", "WARNING")
                    break
                # foo.to_dict()
                if arg.func.attr == 'to_dict':
                    code = "LM2303" if is_print else "LM2203"
                    self._add_finding(node, code, "Object converted to dict can hide sensitive data. Review manually.", "WARNING")
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