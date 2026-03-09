# Security Policy

## Supported Versions

Privlog is currently in early development. Security fixes will generally be applied to the latest released version.

Users are encouraged to update to the most recent version available on PyPI.

## Reporting a Vulnerability

If you believe you have discovered a security vulnerability in Privlog, please report it responsibly.

Please **do not publicly disclose the issue immediately**.

Instead, report the issue through one of the following channels:

* Open a **GitHub Security Advisory** (preferred)
* Contact the repository maintainer through GitHub

Include the following information if possible:

* A clear description of the issue
* Steps to reproduce the behavior
* Example code or logs demonstrating the issue
* The version of Privlog affected
* Any suggested mitigation or fix

## Scope of Security Reports

Security reports may include:

* Vulnerabilities in dependency handling
* Packaging or distribution issues
* Bugs that cause sensitive data detection to fail unexpectedly
* Logic errors in rule evaluation that may cause false negatives
* Supply-chain or build integrity concerns

Please note that Privlog is a **static analysis tool** designed to assist developers in identifying potentially sensitive logging patterns. It does not guarantee complete detection of all possible data leaks.

## Disclosure Process

After a report is received:

1. The issue will be reviewed and validated.
2. A fix will be developed if the report is confirmed.
3. A patch release will be issued when appropriate.
4. Public disclosure may occur after a fix is available.

Responsible disclosure helps protect users and maintain the integrity of the project.

## Acknowledgements

We appreciate responsible security research and the efforts of contributors who help improve the safety and reliability of the project.
