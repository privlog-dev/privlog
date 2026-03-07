# Contributing to Privlog

This guide is for developers who want to contribute to the `privlog` project. It explains the project's architecture and where key logic lives.

---

## 1. Purpose of this project

- **`privlog`** is a privacy-aware linter for Python that uses a Typer CLI. Its analysis is powered by a hybrid engine combining pattern-based Semgrep rules with a high-precision, language-aware AST-based scanner.

---

## 2. Key files and modules

- `pyproject.toml`
  - **Purpose:** Defines project metadata, dependencies, and the `privlog` entry point. It is also the location for user-defined configuration under the `[tool.privlog]` section.

- `README.md`
  - **Purpose:** Provides a high-level overview and usage instructions for users.

- `privlog/`
  - The main Python package directory.

- `privlog/cli.py`
  - **Purpose:** The main entry point for the CLI application.
  - **Responsibilities:** Defines commands and arguments using Typer. Implements the `--warnings`/`-w` flag and filters findings based on severity.

- `privlog/runner.py`
  - **Purpose:** The main analysis engine.
  - **Responsibilities:** 
    1.  Loads user configuration from `pyproject.toml` via the `_load_config` function.
    2.  Runs the Semgrep scanner.
    3.  Runs the AST checker, passing the loaded configuration to it.
    4.  Merges findings from both sources.
    5.  Determines the final exit code based *only* on the presence of `ERROR`-level findings.

- `privlog/formatter.py`
  - **Purpose:** Handles the presentation of results.
  - **Responsibilities:** Prints findings in a `Flake8`-like format, with color-coding for severities.

- `privlog/ast_checks.py`
  - **Purpose:** A high-precision Python linter using the `ast` module. It is the core of the tool's intelligence.
  - **Responsibilities:**
    1.  **Severity System**: Divides sensitive variable names into `HIGH_CONFIDENCE_SENSITIVE_NAMES` (`ERROR`) and `WARNING_SENSITIVE_NAMES` (`WARNING`).
    2.  **Multi-Format Detection**: Understands and inspects arguments within f-strings, `.format()` calls, and `%`-style formatting.
    3.  **`print()` Check**: Scans `print()` statements for sensitive variables.
    4.  **Heuristic Analysis**: Flags risky patterns like logging with `extra=...` or `json.dumps()`.
    5.  **Custom Wrapper Analysis**: Receives the `PrivlogConfig` object and inspects function calls to see if they match a name in the `custom_wrappers` configuration, checking their keyword arguments accordingly.
  - **Finding Codes**:
    - `PL2101`: A direct sensitive identifier was found in a logging call.
    - `PL2201-2203`: A heuristic pattern (like `extra=...` or `json.dumps`) was found in a logging call.
    - `PL2301-2303`: A sensitive identifier or heuristic pattern was found in a `print()` call.
    - `PL2401`: A sensitive argument was passed to a custom logging wrapper defined in the user's configuration.

- `privlog/rules/privlog.yml`
  - **Purpose:** The core Semgrep ruleset, which complements the AST checker.
  - **Responsibilities:** Defines rules for detecting PII, secrets, and unsafe logging patterns.
