# Changelog

All notable project changes are recorded here.

## Unreleased - AISCN 2027 research track

The product version remains **0.2.1**. The research infrastructure below is merged into `main`; it does not constitute a new product release.

### Added

- External-evaluation protocol and tooling for COMISET profile comparisons, LANL authentication checks, and sequence-correlation ablation, plus an isolated performance benchmark and a measured-results bundle generator. See the [research protocol](docs/RESEARCH_EVALUATION.md) and [experiment runbook](docs/AISCN_EXPERIMENT_RUNBOOK.md).
- Phase 6 reproducible SVG figure generation, merged in [PR #9](https://github.com/Briella009/Triagebloom/pull/9) on 2026-09-10 (`d5bee49`): static architecture and `TB-CORR-001` sequence diagrams, with measured profile and throughput plots conditional on accepted result JSON. See [figure generation and claim boundaries](docs/AISCN_FIGURES.md).

### Research status and claim boundaries

- This is a **pre-results publication layer**; no external-dataset result is claimed.
- Measured COMISET profile figures require the frozen external matrix accepted as final. Throughput figures require accepted isolated benchmark JSON with at least two measured event sizes and the documented machine, Python version, exact commit, event counts, and run procedure.
- Static diagrams are not performance evidence. Synthetic regression results cannot substitute for external evaluation.

## 0.2.1 - 2026-09-09

### Fixed

- Updated MITRE ATT&CK tactic labels to the current Enterprise ATT&CK terminology for T1078, T1105, T1218.005, T1218.010, T1218.011, and T1197.
- Removed an inaccurate Credential Access tactic label from the T1078 + T1059.001 correlation finding.
- Clarified that triage and confidence scores are deterministic prioritisation heuristics, not calibrated probabilities of compromise.
- Improved Streamlit entity readability and score labels.
- Added the live Streamlit demo link to the README.

## 0.2.0 - 2026-09-09

### Added

- Dedicated Microsoft Entra ID sign-in context adapter
- Broader Microsoft Entra sign-in shape recognition for exports without optional risk fields
- Microsoft Defender process-event adapter
- Microsoft Defender alert adapter
- Conditional Access, risk, authentication requirement, and MFA detail context
- Parent-process, file-name, and SHA256 endpoint context
- MFA-fatigue detection (`TB-AUTH-005`)
- Cross-event compromise-chain correlation (`TB-CORR-001`)
- `learner`, `balanced`, and `strict` detection profiles
- JSON configuration for thresholds, allow-lists, and suppressions
- Three Microsoft-style schema fixtures plus a combined incident fixture
- Labelled synthetic rule-level evaluation dataset
- Precision, recall, F1, false-positive-rate, and accuracy evaluation script
- Expanded test suite and CI coverage threshold
- Safer allow-list suppression semantics for multi-entity findings
- Redaction of configured allow-list identifiers and source filenames in shareable reports
- Microsoft adapter, configuration, evaluation, and Streamlit deployment documentation
- Streamlit web interface with demo mode, in-memory file uploads, configuration controls, finding drill-down, and report downloads
- Hosted-interface privacy confirmation and 25 MB upload cap
- Dockerfile and Streamlit Community Cloud deployment configuration
- In-memory CSV/JSON/JSONL/NDJSON loader for browser uploads
- Pure HTML/JSON report rendering for downloadable web reports
- CI smoke test for the Streamlit application

### Changed

- Expanded the canonical event model with Microsoft security and endpoint context
- Enriched findings with Microsoft authentication and process evidence when available
- Updated supported version to 0.2.0
- Python 3.10-compatible UTC handling uses `timezone.utc`

### Evaluation

- 35 automated unit tests passed during final release preparation
- 90% statement coverage measured across the `triagebloom` package in the preparation environment
- Synthetic labelled cases produced precision/recall/F1 of 1.0 with zero false positives in the deliberately constructed case set
- These synthetic results are not real-world accuracy claims

## 0.1.0 - 2026-08-13

### Added

- Local CSV, JSON, JSONL, and NDJSON ingestion
- Vendor-neutral event normalisation
- Six explainable detection types
- MITRE ATT&CK mapping
- HTML and JSON reports
- Optional identifier pseudonymisation
- Synthetic demo dataset
- Automated unit tests
