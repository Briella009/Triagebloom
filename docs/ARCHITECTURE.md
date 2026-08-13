# Architecture

## Design goal

TriageBloom should turn a small exported event set into a transparent first-pass triage report without sending data to a third party or requiring a full SIEM deployment.

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
Normaliser
  maps vendor field aliases to a canonical event model
        |
        v
Detection engine
  executes deterministic, testable rules
        |
        v
Finding model
  risk, confidence, MITRE mapping, evidence, next steps
        |
        v
Reporter
  optional pseudonymisation, then HTML and/or JSON output
```

## Canonical event model

Each event contains:

- `event_id`
- `timestamp` in UTC
- `category`
- `event_type`
- `outcome`
- optional `user`
- optional `source_ip`
- optional `device`
- optional `command_line`
- an in-memory copy of the raw row

The report does not write the full raw row. This reduces accidental disclosure and keeps the output focused on evidence needed for triage.

## Detection model

Detectors are pure functions that receive a list of normalised events and a configuration object. They return zero or more findings.

A finding contains:

- stable rule ID
- title and severity
- transparent confidence and risk score
- MITRE ATT&CK mapping
- concise summary
- exact evidence event IDs
- affected entities
- trigger explanation
- recommended investigation steps
- first-seen and last-seen timestamps

No detector can block an IP address, disable an account, delete a file, or execute a command.

## Risk scoring

The MVP combines a severity base score with rule confidence:

```text
risk = 75 percent of severity base + 25 percent of confidence
```

This formula is intentionally simple and visible. It is not a statistical probability of compromise. Future versions should evaluate calibration against labelled datasets before using more complex scoring.

## Privacy and trust boundaries

The core engine:

- reads a local file
- performs no network requests
- treats all log content as untrusted data
- does not evaluate or execute strings from logs
- writes reports only to the selected local directory

The `--redact` option pseudonymises users, source IPs, and device names in report content. It does not modify the source file.

## Extension points

Planned extension points include:

- schema adapters for named products
- parser plugins
- detection plugins
- suppression and allow-list configuration
- incident correlation across multiple files
- a local browser interface

Each extension must preserve local-first operation by default and keep automated response out of scope.
