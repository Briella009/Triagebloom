# External research evaluation protocol

This document defines the pre-results evaluation plan for TriageBloom. Its purpose is to keep research claims narrower than the software capabilities and make later AISCN 2027 results reproducible.

The synthetic cases in `evaluation/labelled_cases.json` remain regression-style software verification. They are **not** evidence of production SOC accuracy.

The machine-readable study protocol is `evaluation/aiscn2027_protocol.json`. The step-by-step execution guide is `docs/AISCN_EXPERIMENT_RUNBOOK.md`.

## Research question

The study asks whether a lightweight, deterministic triage pipeline can provide useful first-pass prioritisation while preserving explicit evidence, analyst-visible rules, MITRE ATT&CK context, reproducibility and local execution.

The study does **not** claim that deterministic alert correlation is novel, that TriageBloom replaces SIEM/EDR platforms, or that every malicious event in an external dataset should be detected.

## Evaluation design

The external evaluation is split across datasets because no public dataset should be forced to validate a capability that its telemetry cannot observe.

### COMISET

COMISET is the primary endpoint/process reference dataset. It contains Windows events from a real working environment and a malicious laboratory environment, with fields including timestamps, command lines, parent process data, process names, host/user context and ATT&CK reference labels.

The adapter is `scripts/research_comiset_eval.py`.

COMISET ATT&CK annotations are treated as **reference labels**, not perfect forensic ground truth. Agreement between a TriageBloom rule and a COMISET reference label does not by itself establish independent forensic truth.

Current quantitative overlap is restricted to process techniques implemented by TriageBloom:

- `T1059.001` — PowerShell
- `T1105` — Ingress Tool Transfer where represented by current LOLBin logic
- `T1197` — BITS Jobs
- `T1218.005` — Mshta
- `T1218.010` — Regsvr32
- `T1218.011` — Rundll32

Other COMISET attack-labelled events must not be counted as false negatives for techniques TriageBloom does not claim to detect.

The evaluator can stream supported data members directly from the official ZIP archives. If an archive contains more than one candidate CSV/JSON/JSONL/NDJSON member, the intended member must be selected explicitly with `--member`.

Publisher integrity values recorded for the official archives are:

- `Comiset23_Lab_Environment_Dataset.zip` — MD5 `e838308bfa31fba1e273d500d588aba6`
- `Comiset23_Real_Environment_Dataset.zip` — MD5 `1718e161dc50b8c49e00020b596974d3`

The evaluator records MD5 and SHA-256 without loading the archive into memory.

### LANL Comprehensive Multi-Source Cyber-Security Events

LANL is a secondary authentication stress/sanity check. Its authentication data contains time, users, computers, authentication/logon types and success/failure, while a separate red-team file identifies known compromised authentication events.

The adapter is `scripts/research_lanl_eval.py`.

The red-team references identify successful stolen-credential authentications. TriageBloom does not claim to detect every stolen-credential login, so LANL must not be presented as a universal accuracy benchmark. Its de-identified process data is also not suitable for a defensible test of PowerShell/LOLBin semantics or the full authentication-to-process correlation rule.

### OTRF Security Datasets / Mordor

Selected Windows OTRF recordings may be used for a separate sequence-correlation experiment because they can preserve Windows Security Auditing and Sysmon context around controlled adversary activity.

A recording is eligible only if the telemetry contains every observable component required by `TB-CORR-001`. Selection criteria must be documented **before** scoring. See `docs/CORRELATION_ABLATION.md`.

## COMISET preflight workflow

Do not begin with a full accuracy run. Verify the archive, inspect the data member, audit schema coverage and inventory supported ATT&CK labels first.

### 1. Fingerprint the archive

```bash
python scripts/research_comiset_eval.py fingerprint \
  /path/to/Comiset23_Lab_Environment_Dataset.zip \
  --output evaluation/external/comiset-lab-fingerprint.json
```

### 2. Audit schema and supported scope

```bash
python scripts/research_comiset_eval.py audit \
  /path/to/Comiset23_Lab_Environment_Dataset.zip \
  --member '<member-name-if-required>' \
  --max-events 100000 \
  --output evaluation/external/comiset-lab-audit-100k.json
```

The audit checks parseability and coverage of timestamp, command line, process, parent process, user, host and ATT&CK-reference fields. It also counts the TriageBloom-supported ATT&CK intersection.

An audit of the first `N` rows is a schema/scope check, not an accuracy result.

### 3. Inventory the full supported-technique distribution

```bash
python scripts/research_comiset_eval.py summary \
  /path/to/Comiset23_Lab_Environment_Dataset.zip \
  --member '<member-name-if-required>' \
  --output evaluation/external/comiset-lab-summary.json
```

Techniques that are absent or too sparse must be disclosed rather than hidden inside an aggregate score.

### 4. Freeze code and configuration

Before final scoring, record:

- TriageBloom git commit SHA;
- dataset MD5/SHA-256;
- archive member;
- threshold profile/configuration;
- evaluation unit;
- supported-technique list;
- inclusion/exclusion rules.

Do not change detection thresholds in response to final-test misses.

### 5. Run the three profiles on the same stream

Use `scripts/research_comiset_matrix.py` so learner, balanced and strict are evaluated in a single streaming pass:

```bash
python scripts/research_comiset_matrix.py \
  /path/to/Comiset23_Lab_Environment_Dataset.zip \
  --member '<member-name-if-required>' \
  --dataset-role lab \
  --profiles learner balanced strict \
  --batch-events 100000 \
  --output evaluation/external/comiset-lab-profile-matrix.json \
  --csv-output evaluation/external/comiset-lab-profile-matrix.csv
```

The runner records configuration, event counts, finding density, runtime, the git commit and optional dataset fingerprints.

## COMISET metric interpretation

### Binary supported-scope metrics

An event is reference-positive when it contains at least one TriageBloom-supported ATT&CK label. It is prediction-positive when TriageBloom surfaces at least one supported technique.

This answers whether supported suspicious behaviour was surfaced at event level. It does **not** establish exact ATT&CK agreement.

### Exact-technique micro metrics

Every `(event, supported-technique)` pair is scored independently. If COMISET references one supported technique but TriageBloom predicts another, exact-technique scoring records the disagreement rather than granting full credit.

### Per-technique metrics

Per-technique precision, recall and F1 must be shown alongside aggregate metrics. Sparse techniques should be labelled as sparse rather than overinterpreted.

### Real-environment interpretation

The real-environment archive is used primarily for **finding density and behaviour**, not automatic false-positive claims.

An unlabeled event is not necessarily independently proven benign. For the real-environment profile matrix, report finding count and findings per 10,000 events. A preregistered sample of findings should be manually reviewed before the phrase `false positive` is used.

## LANL workflow

Extract bounded windows around red-team reference times instead of loading the full authentication file into memory:

```bash
python scripts/research_lanl_eval.py extract \
  /path/to/auth.txt.gz \
  /path/to/redteam.txt.gz \
  evaluation/external/lanl-redteam-windows.jsonl \
  --radius-minutes 30 \
  --summary-output evaluation/external/lanl-extract-summary.json
```

Then evaluate the extracted windows:

```bash
python scripts/research_lanl_eval.py evaluate \
  evaluation/external/lanl-redteam-windows.jsonl \
  --profile balanced \
  --output evaluation/external/lanl-balanced.json
```

The LANL source-computer identifier is mapped into TriageBloom's generic source entity because this file does not provide source IP addresses. Any publication using the result must state this explicitly.

## Planned experiments

### E1 — COMISET process-rule validity

For the supported ATT&CK intersection, report:

- binary event-level TP, FP, FN and TN;
- exact-technique micro metrics;
- per-technique metrics;
- precision, recall and F1;
- false-positive rate only where the negative unit is defensible;
- findings per 10,000 events.

A single aggregate score without per-technique results is insufficient.

### E2 — COMISET real-environment alert behaviour

Run the same frozen process rules against the selected real-environment stream and report finding density across learner, balanced and strict profiles. Do not automatically label every finding as a false positive.

### E3 — LANL authentication stress check

Test whether current authentication rules surface red-team activity under their stated sequence assumptions. Low recall is a valid result because generic stolen-credential use is broader than the current rule definitions.

### E4 — sequence-correlation ablation

Use only independently selected Windows recordings that contain the exact observable sequence required by `TB-CORR-001`.

Compare:

- baseline detection with `TB-CORR-001` suppressed;
- full TriageBloom with `TB-CORR-001` enabled.

The evaluator is `scripts/research_correlation_ablation.py`.

Primary outputs are:

- scenario-level retrieval of the explicit correlation sequence;
- rank of the correlated finding;
- change in highest risk score;
- coverage of independently specified expected event IDs;
- coverage of independently specified attack stages.

**Do not claim duplicate-alert reduction.** The current implementation adds a correlated finding but does not suppress the component findings. Human-productivity claims also remain out of scope unless a separate participant study is conducted.

### E5 — runtime scaling

Run fixed event counts on one documented machine. Perform one warm-up followed by at least five measured runs for each size.

Record:

- Python version;
- operating system;
- processor and RAM;
- exact git commit;
- exact command;
- event count;
- median runtime and interquartile range;
- events per second;
- total-process RSS using an OS-level measurement method.

Do not use `tracemalloc` alone as a manuscript claim for total process memory, and do not claim lower infrastructure cost than another system unless that system is measured under a defensibly comparable setup.

## Leakage and tuning controls

Before final scoring:

1. Freeze the TriageBloom commit and configuration.
2. Use small development samples only for parser/schema debugging.
3. Do not change a detection threshold because a final-test event failed to trigger.
4. Record every excluded technique or event class with a reason.
5. Keep synthetic regression fixtures separate from external evaluation results.
6. Preserve source dataset version, hashes, archive member, commands and sampling seeds.
7. Report negative results and ATT&CK-mapping disagreements.
8. Keep absence of a reference label distinct from independently established benign ground truth.

## Result storage

External raw datasets must **not** be committed to this repository.

Local raw research outputs belong under:

```text
evaluation/external/
```

Only compact, non-sensitive and licence-compatible aggregate results should be considered for publication in the repository. Dataset excerpts must not be committed unless redistribution rights clearly permit it.

## Reproducibility record for final runs

Every result used in the paper must retain:

- dataset title and source/DOI;
- dataset version/date;
- source-file MD5 and SHA-256;
- selected archive member;
- TriageBloom commit SHA;
- exact command line;
- profile and thresholds;
- inclusion/exclusion rules;
- event count;
- evaluation unit and metric definitions;
- environment details;
- known limitations.

## Current status

Implemented research infrastructure now includes:

- streaming COMISET ingestion;
- direct ZIP support;
- archive fingerprinting;
- schema/scope auditing;
- supported-technique and exact-technique scoring;
- single-pass learner/balanced/strict profile evaluation;
- LANL red-team-window extraction and authentication evaluation;
- sequence-correlation ablation tooling;
- regression tests protecting configuration isolation and research adapters.

Full external-dataset performance results are intentionally not claimed until official data is downloaded, verified, audited and executed against a frozen evaluation commit/configuration.
