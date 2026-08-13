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

- local processing
- optional report pseudonymisation
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

- the MVP loads the full file into memory

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

Current mitigation:

- zero runtime dependencies

Planned mitigations:

- signed releases
- release provenance
- software bill of materials
- protected publishing workflow
