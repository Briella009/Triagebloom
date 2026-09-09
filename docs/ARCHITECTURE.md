# Architecture

## Design goal

TriageBloom turns exported security-event sets into transparent first-pass triage reports without sending data to a third party or requiring a full SIEM deployment.

## Processing flow

```text
Input file
  CSV / JSON / JSONL / NDJSON
        |
        v
Reader
  validates format and produces dictionaries
        |
        v
Source recognition + normaliser
  recognises Microsoft Entra / Defender-shaped events
  maps vendor fields to a canonical event model
        |
        v
Detection engine
  deterministic authentication and endpoint rules
        |
        +-----------------------+
        |                       |
        v                       v
Single-pattern findings     Incident correlation
                                failures -> success -> process
        |                       |
        +-----------+-----------+
                    v
Allow-list / suppression filter
                    |
                    v
Finding model
  risk, confidence, MITRE mapping, evidence, context, next steps
                    |
                    v
Reporter
  optional pseudonymisation, then HTML and/or JSON output
```

## Canonical event model

Core fields include:

- `event_id`
- `timestamp` in UTC
- `category`
- `event_type`
- `outcome`
- `user`
- `source_ip`
- `device`
- `command_line`

Version 0.2.0 adds optional context:

- `source_product`
- `parent_process`
- `file_name`
- `sha256`
- `conditional_access_status`
- `risk_level`
- `risk_state`
- `authentication_requirement`
- `authentication_method`
- `alert_severity`
- a small non-executable `context` dictionary for useful exported fields

The report never executes values from these fields.

## Detection model

Detectors are pure functions that receive normalised events and a configuration object. They return zero or more findings.

A finding contains:

- stable rule ID
- title and severity
- transparent confidence and risk score
- MITRE ATT&CK mapping
- concise summary
- exact evidence event IDs
- affected entities and source products
- trigger explanation
- recommended investigation steps
- first-seen and last-seen timestamps

No detector can block an IP address, disable an account, delete a file, or execute a command.

## Correlation model

`TB-CORR-001` intentionally uses a narrow deterministic chain:

1. repeated authentication failures for a user
2. successful authentication for that user
3. suspicious endpoint execution for the same user and compatible device context
4. all stages occur within a configurable correlation window

This is not general-purpose incident reconstruction. The narrow definition makes the rule testable and explainable.

## Risk scoring

The release keeps a visible formula:

```text
risk = 75 percent of severity base + 25 percent of confidence
```

Some confidence values are enriched by explicit Microsoft risk context. The output is not a probability of compromise and is not statistically calibrated.

## Configuration and suppression

A built-in profile establishes threshold defaults. Optional JSON configuration can then set thresholds, entity allow-lists, and rule suppressions. CLI overrides are applied last.

Suppression happens after findings are created so the underlying detection logic remains testable.

## Privacy and trust boundaries

The core engine:

- can read local files or in-memory uploaded bytes
- performs no network requests
- treats all log content as untrusted data
- never evaluates or executes log strings
- writes reports only when the CLI is asked to do so

The Streamlit layer calls the same normalisation, detection, and report-rendering functions. In a public hosted deployment, uploaded bytes are processed by the hosting environment and therefore cross a different trust boundary from local CLI use. The interface presents an explicit warning and requires users to confirm that uploaded data is synthetic, redacted, or otherwise authorised and non-confidential.

The `--redact` option and Streamlit download toggle pseudonymise users, source IPs, device names, configured allow-list identifiers, and the source filename in report content. They do not modify the source data.

## Evaluation boundary

The included evaluation dataset is synthetic and rule-level. It exists to verify deterministic behaviour and reproducibility. It does not establish production accuracy or operational effectiveness.
