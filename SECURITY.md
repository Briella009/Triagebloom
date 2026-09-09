# Security policy

## Supported versions

The project is an early alpha. Only the latest tagged release receives fixes.

## Reporting a vulnerability

Do not open a public issue for a vulnerability that could expose user data, enable code execution, bypass redaction, or corrupt analysis results.

Send a private report to the maintainer with:

- affected version or commit
- reproduction steps using synthetic data
- expected and observed behaviour
- potential impact
- suggested remediation, when available

Do not include real credentials, tokens, client logs, or personal information.

## Security boundaries

TriageBloom is designed to read local event exports and write local reports. It should not make network requests, execute commands from log content, or perform automatic response actions. A change that introduces any of those behaviours requires explicit design review and documentation.
