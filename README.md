# Privlog

[![PyPI](https://img.shields.io/pypi/v/privlog)](https://pypi.org/project/privlog/)
[![Python](https://img.shields.io/pypi/pyversions/privlog)](https://pypi.org/project/privlog)
[![License](https://img.shields.io/github/license/privlog-dev/privlog)](https://github.com/privlog-dev/privlog/blob/main/LICENSE)

A privacy-aware linter for Python projects, designed to catch accidental leaks of sensitive data in logs and `print` statements before they reach production.

`privlog` is built to be a developer's first line of defense, integrating directly into your local workflow and CI/CD pipelines to enforce logging hygiene.

## Why Privlog?

Accidentally logging sensitive data is a common source of security and privacy issues in production systems. Tokens, user identifiers, request bodies, and other sensitive values often end up in logs during development and debugging.

Privlog helps detect these risks early by scanning Python code for logging patterns that may expose sensitive data.

## Quick Example

Given a file `app/auth.py`:
```python
import logging

def reauthenticate_user(user_email):
    # ...
    logging.info(f"Initiating re-authentication for {user_email}")
    # ...
```

Running `privlog .` will produce the following error:

```
app/auth.py:5:5 [ERROR]    PL2101 Sensitive identifier passed to log. Hash/pseudonymize or omit.
```

## Features

- **High-Precision AST Analysis**: Goes beyond simple regex to parse Python code, understanding variable names inside f-strings, `.format()` calls, and more.
- **Severity System**: Differentiates between definite leaks (`ERROR`) and suspicious patterns that require manual review (`WARNING`), preventing false positives from breaking your build.
- **Built-in Heuristics**: Flags risky patterns like logging entire dictionaries (`extra=...`) or `json.dumps()` output.
- **`print()` Statement Detection**: Catches sensitive data in leftover `print()` statements, a common source of leaks.
- **CI/CD Friendly**: Exits with a non-zero code only on `ERROR` findings, allowing warnings to be reviewed without blocking development.
- **Configurable & Extensible**: Teach `privlog` about your project's custom logging functions via a simple `pyproject.toml` configuration.

## Installation

It is highly recommended to install `privlog` within a project's virtual environment to avoid dependency conflicts.

**Recommended (Virtual Environment):**
```sh
# 1. Create and activate a virtual environment in your project directory
python -m venv .venv
source .venv/bin/activate  # On Windows, use: .venv\Scripts\activate

# 2. Install privlog
pip install privlog
```

**Global Installation:**
*While not recommended for most workflows, you can also install it globally:*
```sh
pip install privlog
```

## Usage

Once installed, you can run `privlog` against a specific path, or run it by itself to scan the current directory.

> **Note:** `privlog` automatically ignores common dependency and build directories (like `.venv`, `site-packages`, `build`, etc.) to reduce noise.

### Default (Errors Only)

By default, `privlog` only reports high-confidence `ERROR`s. If any are found, it will exit with a non-zero code, failing your build.

```sh
# Scan a specific directory
privlog /path/to/your/project

# Or, from inside a project, scan the current directory
privlog .
```

If only warnings are found, the command will pass and provide a helpful message:
```
✅ privlog passed. No errors found.
  (Warnings were found. Run with -w to show them)
```

### Show Warnings

To see both `ERROR`s and `WARNING`s, use the `-w` or `--warnings` flag.

```sh
# Scan a specific directory with warnings
privlog -w /path/to/your/project

# Or, from inside a project, scan the current directory with warnings
privlog -w .
```

This will display all findings, color-coded by severity, but will still only fail the build if `ERROR`s are present.

### Other Flags

- `--verbose` / `-v`: Enables verbose output from the underlying `semgrep` scanner. This is useful for debugging rules and understanding which files `semgrep` is scanning or skipping. By default, `privlog` always shows a high-level progress indicator; this flag provides much more detail about the `semgrep` scanning phase.
- `--version`: Display the installed version of `privlog`.

### Configuring Custom Wrappers

You can teach `privlog` to recognize your own custom logging functions. In your project's `pyproject.toml` file, add a `[tool.privlog.custom_wrappers]` section.

For each custom function, specify its name and which of its keyword arguments should be treated as sensitive, along with the desired severity (`ERROR` or `WARNING`).

**Example `pyproject.toml`:**
```toml
[tool.privlog.custom_wrappers]
# For a function call like: audit(actor_id=user.id, event="login")
audit = { actor_id = "ERROR" }

# For a function call like: log_event("payment_failed", details=evt)
log_event = { details = "WARNING" }
```
`privlog` will automatically find and use this configuration when you run it.

---

## Status

Privlog is currently in early development (v0.2.2).
Feedback and contributions are welcome.

---

## For Developers

To set up a development environment to contribute to `privlog`:
```sh
# 1. Clone the repository and navigate into the directory
git clone https://github.com/privlog-dev/privlog.git
cd privlog

# 2. Create and activate a virtual environment
python -m venv .venv
source .venv/bin/activate

# 3. Install the tool in editable mode with development dependencies
pip install -e .
```
