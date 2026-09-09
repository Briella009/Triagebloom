# TriageBloom

**Explainable security log triage with Microsoft security context, incident correlation, a privacy-aware web interface, and reproducible evaluation.**

TriageBloom converts exported CSV or JSON security events into analyst-ready HTML and JSON reports. It normalises common Microsoft Entra ID, Microsoft Defender, Windows, and generic fields, detects suspicious authentication and process behaviour, correlates related events into incident chains, maps findings to MITRE ATT&CK, and explains the evidence behind each rule.

The core engine remains dependency-free and can run entirely on an analyst's computer. An optional Streamlit interface provides a browser workflow for demos and authorised non-confidential datasets.

> **Project status:** public alpha, version 0.2.1. Use it for learning, controlled pilots, research, and analyst assistance. Do not treat it as an autonomous incident-response system or a substitute for SIEM/EDR telemetry.

**Live demo:** https://triagebloom.streamlit.app

> The public demo is for synthetic, redacted, or explicitly authorised non-confidential data only. Use the local CLI or local Streamlit app for sensitive investigations.

## What changed in 0.2.0

Version 0.2.0 combines the planned Microsoft-context and evaluation/correlation milestones into one substantial release.

New capabilities include:

- dedicated Microsoft Entra ID sign-in context
- Microsoft Defender process-event normalisation
- Microsoft Defender alert normalisation
- Conditional Access, sign-in risk, authentication requirement, and MFA detail context
- parent-process, file-name, and SHA256 context for endpoint events
- MFA-fatigue detection followed by successful authentication
- correlation of repeated failures -> successful sign-in -> suspicious endpoint execution
- built-in `learner`, `balanced`, and `strict` rule profiles
- JSON allow-lists and rule suppressions
- labelled synthetic evaluation cases
- precision, recall, F1, false-positive-rate, and accuracy calculation
- expanded automated tests
- 80% minimum CI coverage gate
- Streamlit browser interface with in-memory uploads and downloadable HTML/JSON reports
- Docker deployment option and hosted-interface privacy guardrails

## Why this project exists

Full SIEM and EDR platforms are powerful, but they are not always available to students, small organisations, volunteer teams, educators, or analysts reviewing exported evidence outside a production tenant. TriageBloom provides a lightweight bridge between raw exported events and a structured first-pass investigation.

The project is designed around five principles:

1. **Local-first core:** the CLI processes logs locally; no API key or cloud upload is required. The optional hosted web interface has a separate privacy boundary and must not be used for confidential logs.
2. **Explainability:** findings include thresholds, evidence event IDs, affected entities, context, confidence, and next steps.
3. **Microsoft-aware but vendor-neutral:** common Entra and Defender exports receive dedicated context while the internal model stays generic.
4. **Analyst control:** thresholds, profiles, allow-lists, and suppressions are explicit and inspectable.
5. **Reproducibility:** tests, synthetic fixtures, evaluation data, and benchmark scripts are included in the repository.

## Features

### Input and normalisation

- CSV, JSON, JSONL, and NDJSON ingestion
- generic field aliases
- Microsoft Entra ID adapter
- Microsoft Defender process adapter
- Microsoft Defender alert adapter
- UTC timestamp normalisation

### Authentication detections

| Rule ID | Detection | Severity | MITRE ATT&CK |
|---|---|---:|---|
| `TB-AUTH-001` | Password spray across multiple users | High | T1110.003 |
| `TB-AUTH-002` | Repeated failures against one account | High | T1110.001 |
| `TB-AUTH-003` | Success after repeated failures | Critical | T1078 |
| `TB-AUTH-004` | Successful sign-in outside configured UTC business hours | Low | T1078 |
| `TB-AUTH-005` | MFA fatigue followed by successful authentication | Critical | T1621 |

### Endpoint detections

| Rule ID | Detection | Severity | MITRE ATT&CK |
|---|---|---:|---|
| `TB-PROC-001` | Suspicious PowerShell behaviour | High | T1059.001 |
| `TB-PROC-002` | Potential living-off-the-land binary use | Medium | Technique varies |

### Correlation

| Rule ID | Detection | Severity | Mapping |
|---|---|---:|---|
| `TB-CORR-001` | Repeated auth failures -> successful sign-in -> suspicious process | Critical | T1078 + T1059.001 |

## Browser interface

Run the interface locally:

```bash
python -m pip install -e ".[ui]"
streamlit run streamlit_app.py
```

The interface supports bundled synthetic demos and CSV/JSON/JSONL/NDJSON uploads, configurable detection profiles, prioritised findings, expandable evidence, and downloadable HTML/JSON reports. Identifier pseudonymisation is enabled by default for downloads.

> **Hosted-data warning:** a public Streamlit deployment processes uploads in its hosting environment. Use it only with synthetic, redacted, or explicitly authorised non-confidential data. Use the CLI or a locally run Streamlit instance for sensitive investigations.

Deployment details are in [`docs/STREAMLIT_DEPLOYMENT.md`](docs/STREAMLIT_DEPLOYMENT.md).

## Quick start

### 1. Clone and install

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

For development and coverage checks:

```bash
python -m pip install -e ".[dev]"
```

### 2. Run the combined incident demo

```bash
triagebloom analyze sample_data/combined_incident.json --output-dir reports --disable-off-hours
```

This should produce findings for:

- successful authentication after repeated failures
- suspicious PowerShell
- correlated authentication-to-endpoint compromise chain

### 3. Analyse Microsoft-style fixtures

```bash
triagebloom analyze sample_data/entra_signins.json --output-dir reports
triagebloom analyze sample_data/defender_processes.json --output-dir reports
triagebloom analyze sample_data/defender_alerts.json --output-dir reports
```

### 4. Protect identifiers in a shareable report

```bash
triagebloom analyze sample_data/combined_incident.json --output-dir reports --redact
```

For stable pseudonyms across repeated runs, define a private salt:

```powershell
$env:TRIAGEBLOOM_REDACTION_SALT = "use-a-long-private-random-value"
```

## Rule profiles

Choose one of three profiles:

```bash
triagebloom analyze logs.json --profile learner
triagebloom analyze logs.json --profile balanced
triagebloom analyze logs.json --profile strict
```

- `learner`: lower thresholds for demonstrations and education
- `balanced`: default profile
- `strict`: higher thresholds intended to reduce noise

CLI options can override individual thresholds.

## Allow-lists and suppressions

Copy `config.example.json`, edit it, and run:

```bash
triagebloom analyze logs.json --config my-config.json --output-dir reports
```

Configuration supports:

- allowed users
- allowed source IPs
- allowed devices
- suppressed rule IDs
- authentication thresholds
- MFA threshold/window
- correlation window
- business hours

See [`docs/CONFIGURATION.md`](docs/CONFIGURATION.md).

## Microsoft context

TriageBloom preserves useful fields such as:

- Conditional Access status
- risk level and risk state
- authentication requirement and method detail
- app/resource/client-app context
- parent or initiating process
- file name and SHA256
- Defender alert severity/category/source

See [`docs/MICROSOFT_ADAPTERS.md`](docs/MICROSOFT_ADAPTERS.md).

## Reproducible synthetic evaluation

Run:

```bash
python scripts/evaluate_labelled.py
```

The committed evaluation uses eight synthetic cases across seven evaluated rules. The current synthetic case set produces:

- precision: 1.0000
- recall: 1.0000
- F1 score: 1.0000
- false-positive rate: 0.0000

These values are **not real-world SOC accuracy claims**. The cases are deliberately constructed to verify rule behaviour. See [`docs/EVALUATION.md`](docs/EVALUATION.md) for methodology and limitations.

## Automated tests and coverage

Run:

```bash
python -m unittest discover -s tests -v
```

With the development dependency installed:

```bash
coverage run --source=src/triagebloom -m unittest discover -s tests -v
coverage report --fail-under=80
```

The v0.2.1 validation run passed 36 automated tests and reached 90% statement coverage across the core package.

## Synthetic performance benchmark

Generate and benchmark deterministic synthetic data:

```bash
python scripts/generate_synthetic.py --events 10000 --output synthetic-events.json
python scripts/benchmark.py --events 10000 --repeat 5
```

Always publish the machine specification, Python version, event count, exact commit, and command with any benchmark result.

## Architecture

```text
CSV / JSON export
        |
        v
Source recognition + field normalisation
        |
        v
Vendor-neutral event model
        |
        v
Deterministic detections
        |
        +--> Authentication findings
        +--> Endpoint findings
        +--> Cross-event incident correlation
        |
        v
Allow-list / suppression filtering
        |
        v
Triage score + rule confidence + MITRE context
        |
        v
Explainable HTML / JSON report
```

More detail: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

## Safe sample data

The repository includes synthetic fixtures only. Do not commit real employer, client, patient, customer, or incident data. Sanitise identifiers before sharing screenshots or reports.

## Responsible use

Analyse only data you own or are authorised to handle. TriageBloom does not scan remote systems, exploit vulnerabilities, disable accounts, delete files, or execute remediation actions. Findings can be false positives or false negatives and must be validated against authoritative telemetry and organisational context.

## Current limitations

- synthetic evaluation is not a substitute for external validation
- no direct Microsoft Graph, Sentinel, or Defender API connection
- no geolocation or reputation enrichment
- correlation is intentionally deterministic and narrow
- allow-lists can hide malicious activity if configured carelessly
- upstream Defender alerts are normalised for context rather than duplicated as TriageBloom alerts

## Technical references

Microsoft schema references and MITRE ATT&CK mappings used by the project are listed in [`docs/REFERENCES.md`](docs/REFERENCES.md). Mapping and score-semantics notes are in [`docs/ATTACK_MAPPING_NOTES.md`](docs/ATTACK_MAPPING_NOTES.md).

## Contributing

Issues, detection ideas, sanitised schema examples, tests, and documentation improvements are welcome. Read [`CONTRIBUTING.md`](CONTRIBUTING.md) before opening a pull request.

## Roadmap

The core 0.2.0 engineering milestone is complete. The next priority is **external validation** rather than feature accumulation:

- independent analyst review
- controlled pilot with synthetic or authorised sanitised data
- public or independently curated dataset evaluation where appropriate
- documented feedback and reproducible results
- stable 1.0 release after validation

See [`ROADMAP.md`](ROADMAP.md).

## Licence

MIT. See [`LICENSE`](LICENSE).
