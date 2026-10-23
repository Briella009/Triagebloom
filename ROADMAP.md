# Roadmap

The roadmap uses measurable release criteria so progress can be independently verified.

## 0.1 - Working MVP

- [x] Parse CSV and JSON exports
- [x] Normalise common security fields
- [x] Detect password spray and brute force
- [x] Detect success after repeated failures
- [x] Detect suspicious PowerShell and common LOLBins
- [x] Generate explainable HTML and JSON reports
- [x] Add automated tests and synthetic data

## 0.2 - Microsoft security + correlation + evaluation

- [x] Add dedicated Microsoft Entra ID schema context
- [x] Add Microsoft Defender process adapter
- [x] Add Microsoft Defender alert adapter
- [x] Include Conditional Access and sign-in risk context
- [x] Preserve authentication-method context where exported
- [x] Preserve parent-process, file-name, and SHA256 context
- [x] Add MFA-fatigue detection
- [x] Correlate authentication and suspicious endpoint activity into incident chains
- [x] Add configurable rule profiles
- [x] Add rule suppression and entity allow-lists
- [x] Publish at least three synthetic Microsoft-style schema fixtures
- [x] Publish a labelled synthetic evaluation dataset
- [x] Report precision, recall, F1, and false-positive rate on the synthetic labelled dataset
- [x] Exceed 80% statement coverage in release preparation
- [x] Add a privacy-aware Streamlit interface for synthetic, redacted, or authorised non-confidential data
- [x] Add Docker and Streamlit Community Cloud deployment configuration

## AISCN 2027 research track - pre-results

This research track is separate from the **0.2.1 public-alpha product version**. Phase 6 merged into `main` in [PR #9](https://github.com/Briella009/Triagebloom/pull/9) on 2026-09-10 (`d5bee49`); this is a pre-results publication layer, not a new product release or completion of the validation milestone below.

- [x] Merge the external-evaluation protocol, COMISET/LANL tooling, and sequence-correlation ablation
- [x] Merge the isolated performance benchmark and measured-results bundle generator
- [x] Merge reproducible static SVG diagrams and conditional measured-figure generation
- [ ] Execute external evaluation on verified, eligible datasets with a frozen commit/configuration
- [ ] Accept final outputs against the [runbook's provenance and result-acceptance requirements](docs/AISCN_EXPERIMENT_RUNBOOK.md)
- [ ] Generate measured COMISET profile and throughput figures from accepted final inputs, preserving limitations and negative results

**Claim boundary:** no external-dataset result is claimed. Static diagrams are not performance evidence, and synthetic regression results cannot substitute for external evaluation. Measured profile figures require the frozen external COMISET matrix; throughput figures require accepted isolated benchmark JSON with at least two measured event sizes and the documented environment and run procedure.

See the [research protocol](docs/RESEARCH_EVALUATION.md) and [figure-generation requirements](docs/AISCN_FIGURES.md).

## Validation milestone before 1.0

- [ ] Obtain independent review from at least three cybersecurity practitioners
- [ ] Complete a controlled pilot with at least 10 participants using synthetic or authorised sanitised data
- [ ] Record usability, clarity, investigation time, correct findings, and false-positive acceptance
- [ ] Incorporate at least three evidence-based improvements if identified
- [ ] Evaluate against an appropriate public or independently curated dataset where schema and licensing permit
- [ ] Document all limitations and negative results

## 1.0 - Validated stable release

- [ ] Stable input schema and compatibility policy
- [ ] Reproducible benchmark and evaluation package
- [ ] Updated security review and threat model
- [ ] External pilot summary
- [ ] Stable release notes and migration guidance

## Deferred ideas

The following are deliberately not required for 1.0:

- direct Sentinel or Defender API connectivity
- Sigma import
- plugin marketplace
- automated response actions

They may be explored only if real users identify a need.
