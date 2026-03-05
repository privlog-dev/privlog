# privlog

A privacy-aware linter for Python projects, designed to catch accidental leaks of sensitive data in logs and `print` statements before they reach production.

`privlog` is built to be a developer's first line of defense, integrating directly into your local workflow and CI/CD pipelines to enforce logging hygiene.

## Features

- **High-Precision AST Analysis**: Goes beyond simple regex to parse Python code, understanding variable names inside f-strings, `.format()` calls, and more.
- **Severity System**: Differentiates between definite leaks (`ERROR`) and suspicious patterns that require manual review (`WARNING`), preventing false positives from breaking your build.
- **Built-in Heuristics**: Flags risky patterns like logging entire dictionaries (`extra=...`) or `json.dumps()` output.
- **`print()` Statement Detection**: Catches sensitive data in leftover `print()` statements, a common source of leaks.
- **CI/CD Friendly**: Exits with a non-zero code only on `ERROR` findings, allowing warnings to be reviewed without blocking development.
- **Extensible**: Powered by a combination of custom AST checks and a Semgrep rule engine.

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

Once installed, run the `privlog` command on your project directory.

### Default (Errors Only)

By default, `privlog` only reports high-confidence `ERROR`s. If any are found, it will exit with a non-zero code, failing your build.

```sh
privlog /path/to/your/project
```

If only warnings are found, the command will pass and provide a helpful message:
```
✅ privlog passed. No errors found.
  (Warnings were found. Run with -w to show them)
```

### Show Warnings

To see both `ERROR`s and `WARNING`s, use the `-w` or `--warnings` flag.

```sh
privlog -w /path/to/your/project
```
This will display all findings, color-coded by severity, but will still only fail the build if `ERROR`s are present.

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
