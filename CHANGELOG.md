# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.2] - 2026-03-11

### Added
- Progress indicator during the AST scan when using the `--verbose` flag, showing which file is being scanned.
- `--version` flag to display the current version of the tool.
- Verbose output for scanning stages, making it clear when `semgrep` and `AST` scans are running.

### Changed
- Improved AST check warnings to include the name of the sensitive identifier found, making it easier to locate and fix issues. For example, the warning for `PL2101` will now be `Sensitive identifier "user_email" passed to log...`.
- The progress indicator and scanning stage messages are now shown by default to provide better feedback during scans. The `--verbose` flag now only controls the verbosity of the underlying `semgrep` tool.
- The `check` subcommand has been merged into the main `privlog` command. This simplifies the command-line usage from `privlog check` to `privlog` and aligns the tool's behavior with the `README.md` documentation.
