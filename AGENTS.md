# Agents Guide – privlog

This document is for **coding agents** that work on this repo.
It explains what the project does and where the important code lives.

---

## 1. Purpose of this project

- **`privlog`** is a Python CLI tool built with Typer for finding and preventing sensitive data leaks.
- It uses a hybrid approach, combining pattern-based Semgrep rules with a high-precision, language-aware AST-based scanner.

---

## 2. Key files and modules

- `pyproject.toml`
  - **Purpose:** Defines project metadata, dependencies (`typer`, `pyyaml`, `semgrep`), and the `privlog` entry point.
  - **Responsibilities:** Manages the package and its dependencies.

- `README.md`
  - **Purpose:** Provides a high-level overview for human users.

- `logmaster/`
  - The main Python package directory. (Note: The project is named `privlog`, but the package directory is still `logmaster`).

- `logmaster/cli.py`
  - **Purpose:** The main entry point for the CLI application.
  - **Responsibilities:** Defines commands and arguments using Typer. Implements the `--warnings`/`-w` flag and filters findings based on severity (`ERROR` vs. `WARNING`).

- `logmaster/runner.py`
  - **Purpose:** The main analysis engine.
  - **Responsibilities:** Runs both Semgrep and AST checks, converts all findings into a common `Finding` object, and determines the final exit code based *only* on the presence of `ERROR`-level findings.

- `logmaster/formatter.py`
  - **Purpose:** Handles the presentation of results.
  - **Responsibilities:** Prints findings in a `Flake8`-like format, with color-coding for severities.

- `logmaster/ast_checks.py`
  - **Purpose:** A high-precision Python linter using the `ast` module. It is the core of the tool's intelligence.
  - **Responsibilities:**
    1.  **Severity System**: Divides sensitive variable names into `HIGH_CONFIDENCE_SENSITIVE_NAMES` (`ERROR`) and `WARNING_SENSITIVE_NAMES` (`WARNING`).
    2.  **Multi-Format Detection**: Understands and inspects arguments within f-strings, `.format()` calls, and `%`-style formatting.
    3.  **`print()` Check**: Scans `print()` statements for sensitive variables, applying the same severity logic as logging calls.
    4.  **Heuristic Analysis**: Flags risky but not definitively incorrect patterns as `WARNING`s.
  - **Finding Codes**:
    - `LM2101`: A direct sensitive identifier was found in a logging call. Severity can be `ERROR` or `WARNING`.
    - `LM2201`: A logging call uses the `extra` parameter, which could hide sensitive data. Severity is `WARNING`.
    - `LM2202`: `json.dumps()` is used in a logging call. Severity is `WARNING`.
    - `LM2203`: `.to_dict()` is used in a logging call. Severity is `WARNING`.
    - `LM2301`: A direct sensitive identifier was found in a `print()` call. Severity can be `ERROR` or `WARNING`.
    - `LM2302`: `json.dumps()` is used in a `print()` call. Severity is `WARNING`.
    - `LM2303`: `.to_dict()` is used in a `print()` call. Severity is `WARNING`.

- `logmaster/rules/logmaster.yml`
  - **Purpose:** The core Semgrep ruleset, which complements the AST checker by finding broader, less precise patterns.
  - **Responsibilities:** Defines rules for detecting PII, secrets, and unsafe logging patterns like payload dumping.
