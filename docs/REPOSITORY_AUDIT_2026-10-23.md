# TriageBloom repository audit and evidence-gap assessment

**Audit date:** 2026-10-23  
**Repository:** https://github.com/Briella009/Triagebloom  
**Live demo:** https://triagebloom.streamlit.app

## Executive assessment

TriageBloom is no longer only a foundational alpha repository. The current default branch contains a working local CLI, a Streamlit interface, Microsoft Entra and Defender context adapters, deterministic detection and correlation rules, pseudonymised reporting, CI, synthetic rule verification, and a separate pre-results research track for external datasets and performance evaluation.

The strongest remaining gaps are not additional detections. They are independent validation, release hygiene, broader robustness evidence, and externally verifiable impact.

## What is already implemented

- CSV, JSON, JSONL, and NDJSON ingestion
- vendor-neutral canonical event model
- Microsoft Entra ID sign-in context
- Microsoft Defender process and alert context
- password-spray detection
- account brute-force detection
- success-after-failures detection
- out-of-hours sign-in review
- MFA-fatigue detection
- suspicious PowerShell detection
- selected LOLBin detection
- cross-event authentication-to-endpoint correlation
- MITRE ATT&CK context
- deterministic triage and rule-confidence scores
- allow-lists and suppressions
- HTML and JSON reports
- identifier pseudonymisation for shareable reports
- local CLI
- hosted/local Streamlit interface
- Docker configuration
- CI across supported Python versions plus Streamlit health check
- labelled synthetic rule-level evaluation
- AISCN research infrastructure for COMISET, LANL, correlation ablation, runtime/memory benchmarking, result compilation, and reproducible figures

## Engineering strengths

### Explainability

Findings retain rule IDs, triggering evidence IDs, affected entities, ATT&CK context, thresholds/context, triage scores, confidence heuristics, and recommended investigation steps.

### Privacy boundary

The core CLI does not require an external API. The hosted Streamlit interface clearly warns users not to upload confidential employer, client, production, regulated, or sensitive logs.

A static repository search during this audit did not identify common outbound network-client imports such as `requests`, `httpx`, `aiohttp`, `urllib`, or `socket` in the default branch. This is supportive evidence, not a formal proof that every execution path is network-isolated.

### Reproducibility

The repository includes automated tests, synthetic fixtures, evaluation scripts, dataset-provenance requirements, benchmark protocols, and a documented distinction between synthetic verification and external research results.

### Claim discipline

The research documentation correctly avoids treating synthetic F1 results as production accuracy, unlabeled real-environment events as automatically benign, static diagrams as performance evidence, or correlation as proof of analyst-productivity gains.

## Defects and risks that remain

### External validation is incomplete

The roadmap still requires independent practitioner review and a controlled analyst pilot. No independent endorsements, user-adoption figures, testimonials, or external-use claims should be made until they exist and can be evidenced.

### Public release hygiene is behind the code

At the time of this audit, the GitHub Releases page exposes the original `v0.1.0` release while the repository code and documentation identify the product as `v0.2.1` and also contain later pre-results research infrastructure. A current signed/tagged release would make the public evidence trail easier to understand.

### Core ingestion is all-or-nothing

`normalise_rows` collects malformed-row errors and then rejects the batch. This is predictable and safe, but one malformed event can prevent analysis of an otherwise useful export. A future tolerant mode should only be added if users request it, with explicit skipped-row accounting.

### Core ingestion is memory-resident

The ordinary CLI/Streamlit path normalises an input into an in-memory event list. This is appropriate for the stated lightweight use case but is not a production streaming-SIEM architecture. The research COMISET tooling has separate streaming support and should not be conflated with the normal product path.

### Detection scope is deliberately narrow

Rules are deterministic and focus on selected authentication/process patterns. They do not establish general attack detection, malware classification, threat-intelligence enrichment, geolocation, or complete ATT&CK coverage.

### Triage/confidence values are heuristics

The repository correctly labels them as deterministic prioritisation heuristics. They must not be presented as probabilities of compromise until separately calibrated and validated.

### Hosted interface privacy depends on deployment environment

The public Streamlit instance processes uploaded content in the hosting environment. The local-first claim applies to the local CLI/local Streamlit path, not to public cloud hosting.

### Supply-chain provenance can improve

The threat model already identifies signed releases, release provenance, and an SBOM as future mitigations. These are reasonable 1.0 hardening tasks, not prerequisites for current controlled evaluation.

## Evidence gaps relevant to an external reviewer

Priority order:

1. independent practitioner feedback tied to a version/commit;
2. controlled pilot results with known ground truth;
3. accepted external-dataset result bundles with provenance;
4. evidence of genuine third-party use, issues, contributions, citations, or adoption;
5. current GitHub release/tag matching the public product version;
6. stable 1.0 release only after the validation milestone.

## Smallest useful next milestone

Do not add more detections yet.

Complete the validation layer:

- run the extended synthetic detection and ingestion-robustness suite in CI;
- obtain at least two independent technical reviews, while keeping the existing roadmap target of three;
- run the controlled analyst pilot;
- execute the frozen external-dataset research protocol without tuning on final-test results;
- publish only aggregate, licence-compatible results;
- create a current tagged release after the evidence is reviewed.

This produces stronger engineering and impact evidence than feature accumulation.
