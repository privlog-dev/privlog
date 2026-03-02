# Agents Guide – Logmaster

This document is for **coding agents** that work on this repo.
It explains what the project does and where the important code lives.

---

## 1. Purpose of this project

- **`logmaster`** is a Python CLI tool built with Typer.
- Its purpose is to analyze log files, identify patterns, and provide formatted output.
- It uses a `rules/` directory to define custom analysis rules for Semgrep.

---

## 2. Key files and modules

- `pyproject.toml`
  - **Purpose:** Defines project metadata, dependencies (`typer`, `pyyaml`), and entry points.
  - **Responsibilities:** Manages the package and its dependencies using setuptools. Includes configuration for package data to ensure rule files are included.

- `README.md`
  - **Purpose:** Provides a high-level overview of the project for human users.

- `logmaster/`
  - The main Python package directory.

- `logmaster/__init__.py`
  - **Purpose:** Makes the `logmaster` directory a Python package.

- `logmaster/cli.py`
  - **Purpose:** The main entry point for the CLI application.
  - **Responsibilities:** Defines the CLI commands and arguments using Typer. It orchestrates calls to the runner and formatter.

- `logmaster/runner.py`
  - **Purpose:** The main analysis engine, orchestrating checks from multiple sources.
  - **Responsibilities:** Runs both the Semgrep-based pattern checks (`_run_semgrep`) and the high-precision `ast_checks`. It then merges the findings from both sources into a single, unified list for the formatter and CLI. It also contains the data classes for the results (`Finding`, `RunResult`).

- `logmaster/formatter.py`
  - **Purpose:** Handles the presentation of the analysis results.
  - **Responsibilities:** Takes a list of `Finding` objects from the runner and prints them to the console in a compact, `Flake8`-like format (`path:line:col CODE message`).

- `logmaster/ast_checks.py`
  - **Purpose:** A high-precision Python linter using the built-in `ast` module.
  - **Responsibilities:** Parses Python source code into an Abstract Syntax Tree to perform complex, language-aware checks that are difficult with pattern-matching alone. It specializes in detecting sensitive variables inside f-strings that are not wrapped in known sanitizing functions (e.g., `get_salted_identifier`).

- `logmaster/rules/`
  - **Purpose:** Stores custom analysis rules.

- `logmaster/rules/logmaster.yml`
  - **Purpose:** The core Semgrep ruleset for LogMaster, based on production-proven patterns.
  - **Responsibilities:** Defines specific, categorized patterns to detect common logging anti-patterns. The rules are grouped by ID prefixes:
    - `LM11xx`: High-signal PII leaks (e.g., raw emails, user IDs, IP addresses).
    - `LM12xx`: High-confidence secret leakage, focusing on raw authentication headers (`Authorization`, `Cookie`). Complex variable name checks are handled by the AST module.
    - `LM13xx`: Raw payload and header dumping.
    - `LM14xx`: Unsafe exception logging that may leak sensitive data.
    - `LM15xx`: Unbounded logging of vendor API responses.
  Each rule has a unique ID, severity, and a clear message.
