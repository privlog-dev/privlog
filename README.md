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

## Usage

First, install the tool in your project's virtual environment:
```sh
pip install -e .
```

To run the checks, use the `privlog` command.

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
