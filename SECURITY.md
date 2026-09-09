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

The core TriageBloom engine is designed to read event exports and generate reports without making network requests, executing commands from log content, or performing automatic response actions. A change that introduces any of those behaviours requires explicit design review and documentation.

The optional Streamlit interface can be run locally or deployed to a hosting environment. A public hosted deployment is **not** a confidential-log processing service: uploaded content is processed by that hosting environment. Use public deployments only with synthetic, redacted, or explicitly authorised non-confidential data. Use the CLI or a locally run Streamlit instance for sensitive investigations.
