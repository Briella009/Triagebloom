# TriageBloom

**Explainable, local-first security log triage for small SOC teams, learners, and incident responders.**

TriageBloom converts exported CSV or JSON security events into an analyst-ready HTML and JSON report. It normalises common vendor fields, detects suspicious authentication and process patterns, maps findings to MITRE ATT&CK, shows the exact evidence that triggered each rule, and recommends next investigation steps.

The core engine runs entirely on the analyst's computer and has no third-party Python dependencies.

> Project status: early public alpha. Use it for learning, controlled pilots, and analyst assistance. Do not treat it as an autonomous incident-response system.

## Why this project exists

Full SIEM platforms are powerful, but they are not always available to students, small organisations, volunteer teams, or analysts reviewing exported evidence outside a production tenant. TriageBloom provides a lightweight bridge between raw exported logs and a structured investigation.

The project is designed around four principles:

1. **Local-first privacy:** logs are processed locally; no API key or cloud upload is required.
2. **Explainability:** each finding lists the threshold, evidence event IDs, affected entities, confidence, and next steps.
3. **Learning value:** the report explains why a pattern matters instead of only labelling it malicious.
4. **Low adoption cost:** the MVP uses the Python standard library and accepts common CSV/JSON exports.

## MVP features

- CSV, JSON, JSONL, and NDJSON ingestion
- Field normalisation for common Microsoft Entra ID, Microsoft Defender, Windows, and generic log exports
- Password-spray detection
- Account brute-force detection
- Successful sign-in after repeated failures
- Suspicious PowerShell detection
- Living-off-the-land binary detection
- Configurable off-hours sign-in review
- MITRE ATT&CK technique mapping
- Transparent risk and confidence scoring
- HTML and JSON reporting
- Optional pseudonymisation of users, IP addresses, and devices
- Synthetic demo data and automated tests

## Quick start

### 1. Install from the repository

```bash
git clone https://github.com/Briella009/triagebloom.git
cd triagebloom
python -m venv .venv
```

Activate the environment:

```bash
# Linux or macOS
source .venv/bin/activate

# Windows PowerShell
.venv\Scripts\Activate.ps1
```

Install:

```bash
python -m pip install -e .
```

### 2. Run the demo

```bash
triagebloom analyze sample_data/demo_events.json --output-dir reports
```

The command creates:

- `reports/demo_events-triagebloom.html`
- `reports/demo_events-triagebloom.json`

Open the HTML file in a browser.

### 3. Protect identifiers in a shareable report

```bash
triagebloom analyze sample_data/demo_events.json --output-dir reports --redact
```

For consistent pseudonyms across repeated runs, define a private salt before running:

```bash
export TRIAGEBLOOM_REDACTION_SALT="use-a-long-private-random-value"
```

On Windows PowerShell:

```powershell
$env:TRIAGEBLOOM_REDACTION_SALT = "use-a-long-private-random-value"
```

## Detection catalogue

| Rule ID | Detection | Default severity | MITRE ATT&CK |
|---|---|---:|---|
| `TB-AUTH-001` | Password spray across multiple users | High | T1110.003 |
| `TB-AUTH-002` | Repeated failures against one account | High | T1110.001 |
| `TB-AUTH-003` | Success after repeated failures | Critical | T1078 |
| `TB-AUTH-004` | Success outside configured UTC business hours | Low | T1078 |
| `TB-PROC-001` | Suspicious PowerShell behaviour | High | T1059.001 |
| `TB-PROC-002` | Potential living-off-the-land binary use | Medium | Technique varies |

Thresholds are configurable from the command line. Run `triagebloom analyze --help` for the complete list.

## Accepted fields

TriageBloom automatically recognises common aliases. At minimum, each row needs a timestamp.

| Canonical field | Example aliases |
|---|---|
| Timestamp | `timestamp`, `TimeGenerated`, `createdDateTime`, `@timestamp` |
| Event type | `event_type`, `ActivityDisplayName`, `ActionType`, `OperationName` |
| Outcome | `outcome`, `result`, `status`, `resultType` |
| User | `user`, `UserPrincipalName`, `AccountName`, `Identity` |
| Source IP | `source_ip`, `IPAddress`, `ClientIP`, `CallerIPAddress` |
| Device | `device`, `DeviceName`, `Computer`, `HostName` |
| Command line | `command_line`, `ProcessCommandLine`, `CommandLine` |

Unknown extra fields remain in memory during analysis but are not written into the report.

## Example command options

```bash
triagebloom analyze logs/signins.csv \
  --spray-users 6 \
  --spray-window 15 \
  --bruteforce-failures 10 \
  --business-start 8 \
  --business-end 18 \
  --output-dir reports \
  --redact
```

## Synthetic data and repeatable benchmarks

Generate a deterministic dataset without using real security logs:

```bash
python scripts/generate_synthetic.py --events 10000 --output synthetic-events.json
```

Run a local benchmark:

```bash
python scripts/benchmark.py --events 10000 --repeat 5
```

Any published benchmark should include the exact commit, Python version, operating system, processor, memory, event count, and command used.

## Architecture

```text
CSV / JSON export
        |
        v
Field normalisation
        |
        v
Vendor-neutral event model
        |
        v
Deterministic detection rules
        |
        v
Risk + confidence + MITRE mapping
        |
        v
Explainable HTML / JSON report
```

More detail is available in [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

## Responsible use

Analyse only data you own or are authorised to handle. TriageBloom does not scan remote systems, exploit vulnerabilities, block accounts, or execute response actions. Its output is advisory and can contain false positives or false negatives. Validate each finding with authoritative telemetry and organisational context.

Do not publish real client or employer logs. Use synthetic data, approved anonymised data, or redacted screenshots for demos and public documentation.

## Contributing

Issues, detection ideas, sample schemas, tests, and documentation improvements are welcome. Read [`CONTRIBUTING.md`](CONTRIBUTING.md) before opening a pull request.

A useful first contribution is a sanitised sample export and a mapping of its field names to the canonical event model.

## Roadmap

Near-term priorities include:

- Microsoft Sentinel analytics-rule export support
- Entra ID sign-in risk and conditional-access context
- MFA fatigue detection
- Cross-file incident correlation
- Sigma-rule import for community detections
- Optional browser-based interface
- Evaluation dataset and false-positive measurement

See [`ROADMAP.md`](ROADMAP.md) for milestones and acceptance criteria.

## Licence

MIT. See [`LICENSE`](LICENSE).
