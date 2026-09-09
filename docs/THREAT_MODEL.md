# Lightweight threat model

## Assets

- source log files
- analyst identifiers and case details
- generated reports
- rule configuration
- project integrity

## Main risks

### Sensitive-data disclosure

A user may publish a report containing real names, IP addresses, device names, or case identifiers.

Mitigations:

- local-first CLI and locally runnable Streamlit mode for sensitive investigations
- explicit hosted-interface warning and confirmation before uploaded files are analysed
- 25 MB upload cap in the Streamlit deployment configuration
- optional report pseudonymisation
- redacted reports pseudonymise finding identifiers, configured allow-list identifiers, and the source filename
- raw rows are not embedded in reports
- repeated warnings against publishing confidential logs

### Formula or script injection in reports

Untrusted log strings may contain HTML or executable content.

Mitigations:

- HTML escaping before rendering
- no JavaScript in generated reports
- no command evaluation

### Maliciously large input

A large or crafted file may consume memory or processing time.

Current limitation:

- the engine loads the full file into memory
- the hosted interface therefore enforces a 25 MB upload cap

Planned mitigations:

- streaming ingestion
- input-size warnings
- configurable event limits
- performance tests

### Misleading findings

A rule may generate false positives, false negatives, or overconfident advice.

Mitigations:

- deterministic rules
- visible thresholds and evidence IDs
- separate severity and confidence
- no automated response
- true-positive and benign tests for new rules

### Supply-chain compromise

A malicious dependency or release may alter analysis.

Current mitigations:

- zero third-party runtime dependencies in the core engine
- Streamlit is isolated as an optional UI dependency
- dependency installation is exercised in CI

Planned mitigations:

- signed releases
- release provenance
- software bill of materials
- protected publishing workflow

### Over-broad allow-listing

A trusted-looking user, device, or IP can still be involved in malicious activity. A broad allow-list can therefore hide important findings.

Mitigations:

- exact-value allow-lists rather than wildcard rules
- a multi-entity finding is not suppressed merely because one of several users is allow-listed
- configuration is included in non-redacted analysis metadata for auditability
- documentation warns that allow-lists must be reviewed and justified
