# External research evaluation protocol

This document describes the pre-results evaluation plan for TriageBloom. It exists to keep the research claims narrower than the software capabilities and to make later conference results reproducible.

The repository still treats the synthetic labelled cases in `evaluation/labelled_cases.json` as regression-style software verification. They are not evidence of production detection accuracy.

## Research question

The current study asks whether a lightweight, deterministic triage pipeline can provide useful first-pass prioritisation while preserving explicit evidence, analyst-visible rules, MITRE ATT&CK context, reproducibility, and local execution.

The study does **not** claim that deterministic alert correlation is novel, that TriageBloom replaces a SIEM/EDR, or that every malicious event in an external dataset should be detected by TriageBloom.

## External datasets

### COMISET

COMISET is the primary endpoint/process reference dataset for the current engineering phase. It contains Windows security events from a real working environment and a malicious laboratory environment. The published dataset includes fields such as timestamps, command lines, parent command lines, process names, host names, users, and `Rule_technique_id` ATT&CK labels.

The research adapter is `scripts/research_comiset_eval.py`.

Important claim boundary: COMISET's ATT&CK labels were created by its own event-based detection and labelling pipeline. They are useful **reference labels**, but this study will not describe them as perfect forensic ground truth. Agreement between a rule-based TriageBloom detector and a rule-generated COMISET reference label does not by itself establish independent forensic ground truth.

Current quantitative overlap is restricted to the process techniques implemented by TriageBloom:

- `T1059.001` — PowerShell
- `T1105` — Ingress Tool Transfer, where represented by implemented LOLBin logic
- `T1197` — BITS Jobs
- `T1218.005` — Mshta
- `T1218.010` — Regsvr32
- `T1218.011` — Rundll32

The evaluator reports results only for this supported intersection. It must not count all other COMISET attack-labelled events as TriageBloom false negatives.

The official Zenodo release contains two large ZIP archives. The research adapter can stream a CSV/JSON/JSONL/NDJSON member directly from a ZIP archive, so extraction of the full archive is not required for the evaluation pipeline. If an archive contains more than one candidate data member, select the intended member explicitly with `--member`.

Official archive integrity values recorded by the dataset publisher are:

- `Comiset23_Lab_Environment_Dataset.zip` — MD5 `e838308bfa31fba1e273d500d588aba6`
- `Comiset23_Real_Environment_Dataset.zip` — MD5 `1718e161dc50b8c49e00020b596974d3`

The evaluator includes a streaming fingerprint command that records both MD5 and SHA-256 without loading the archive into memory.

### LANL Comprehensive Multi-Source Cyber-Security Events

The LANL dataset is a secondary authentication stress/sanity check. Its authentication file contains time, source user, destination user, source computer, destination computer, authentication type, logon type, orientation, and success/failure. The separate red-team file identifies known compromised authentication events.

The research adapter is `scripts/research_lanl_eval.py`.

The LANL red-team labels represent successful stolen-credential authentications. TriageBloom does not claim to detect every stolen-credential login, so LANL results must not be presented as the primary accuracy benchmark. The process names in LANL are also de-identified, which prevents a defensible test of TriageBloom's command-line PowerShell/LOLBin logic or the full authentication-to-suspicious-process correlation rule.

### OTRF Security Datasets / Mordor

A separate sequence-correlation experiment is planned with selected Windows OTRF Security Datasets. These datasets intentionally preserve malicious events plus surrounding contextual events and can include both Windows Security Auditing and Sysmon telemetry. That makes them a better fit than LANL for testing a specific multi-event authentication-to-process sequence.

This experiment will be added only after selecting recordings whose telemetry actually contains all components required by the TriageBloom correlation rule. The selection criteria must be written down before scoring.

## Why the evaluation is split across datasets

No single public dataset should be forced to validate a capability it cannot observe.

COMISET is strong for modern Windows endpoint/process telemetry and ATT&CK-labelled process behaviours. LANL provides large-scale enterprise authentication data and explicit red-team authentication references, but little process semantic detail. OTRF recordings are smaller and controlled, but retain Windows event context needed for sequence-level correlation experiments.

Using each dataset only for the claims its telemetry can support is more defensible than reporting one headline accuracy number across incompatible event types.

## COMISET preflight workflow

Do not start by running a full accuracy evaluation. First verify the downloaded archive, inspect its member names, audit schema coverage, and confirm that the TriageBloom-supported ATT&CK intersection is actually present.

### 1. Fingerprint the official archive

```bash
python scripts/research_comiset_eval.py fingerprint \
  /path/to/Comiset23_Lab_Environment_Dataset.zip \
  --output evaluation/external/comiset-lab-fingerprint.json
```

For the official archive filename, the script automatically compares the MD5 value with the publisher's recorded checksum. It also records SHA-256 for the local reproducibility record.

### 2. Identify the intended data member

If the ZIP contains a single CSV/JSON/JSONL/NDJSON data file, the script selects it automatically. If it contains multiple candidate files, the command exits instead of guessing. Use the candidate name reported by the error message with `--member` in later commands.

### 3. Run a schema/scope audit before scoring

```bash
python scripts/research_comiset_eval.py audit \
  /path/to/Comiset23_Lab_Environment_Dataset.zip \
  --member '<member-name-if-required>' \
  --max-events 100000 \
  --output evaluation/external/comiset-lab-audit-100k.json
```

The audit reports:

- rows scanned and successfully adapted;
- presence/coverage of timestamp, command-line, process-name, parent-process, user, host, and ATT&CK-reference fields;
- overall ATT&CK reference distribution in the scanned portion;
- the exact count of events overlapping TriageBloom's supported techniques;
- parse errors, if any.

An audit of the first `N` records is **not** an accuracy result and must never be reported as one.

### 4. Run the full technique inventory

```bash
python scripts/research_comiset_eval.py summary \
  /path/to/Comiset23_Lab_Environment_Dataset.zip \
  --member '<member-name-if-required>' \
  --output evaluation/external/comiset-lab-summary.json
```

Use this inventory to decide whether every planned TriageBloom-supported technique has enough reference-labelled observations to report separately. Do not combine extremely sparse techniques into a headline metric without showing the individual counts.

### 5. Freeze the evaluation commit and configuration

Before final scoring, record:

- git commit SHA;
- dataset fingerprint;
- archive member;
- profile/configuration;
- evaluation unit;
- supported-technique list;
- inclusion/exclusion rules.

Do not change thresholds after viewing final test results.

### 6. Run the supported-scope evaluator

```bash
python scripts/research_comiset_eval.py evaluate \
  /path/to/Comiset23_Lab_Environment_Dataset.zip \
  --member '<member-name-if-required>' \
  --profile balanced \
  --batch-events 100000 \
  --output evaluation/external/comiset-lab-balanced.json
```

Then repeat the frozen input for `learner` and `strict`.

The reader processes records in bounded batches, so the full COMISET file is not loaded into memory.

## Metric interpretation

The COMISET evaluator intentionally reports two aggregate views plus per-technique metrics.

### Supported-scope binary metrics

An event is positive when its reference labels contain at least one TriageBloom-supported technique. A predicted event is positive when TriageBloom surfaces at least one supported technique. These metrics answer whether TriageBloom surfaced a supported malicious behaviour at the event level.

They do **not** prove that the exact ATT&CK technique agreed.

### Exact-technique micro metrics

Every `(event, supported-technique)` pair is scored independently. If the reference says `T1218.005` but TriageBloom predicts `T1218.011`, the binary view sees that both sides identified supported suspicious behaviour, while exact-technique scoring records a false negative for `T1218.005` and a false positive for `T1218.011`.

This distinction prevents a misleading headline score from hiding ATT&CK-mapping disagreement.

### Per-technique metrics

The paper should report per-technique precision, recall and F1 alongside the aggregate views. Techniques with too few positive reference events should be marked as sparse instead of interpreted aggressively.

## LANL workflow

The original LANL authentication file is very large. Instead of loading it in memory, extract only fixed windows around red-team reference times:

```bash
python scripts/research_lanl_eval.py extract \
  /path/to/auth.txt.gz \
  /path/to/redteam.txt.gz \
  evaluation/external/lanl-redteam-windows.jsonl \
  --radius-minutes 30 \
  --summary-output evaluation/external/lanl-extract-summary.json
```

Then evaluate the extracted authentication window:

```bash
python scripts/research_lanl_eval.py evaluate \
  evaluation/external/lanl-redteam-windows.jsonl \
  --profile balanced \
  --output evaluation/external/lanl-balanced.json
```

The LANL source-computer identifier is placed in TriageBloom's generic source entity field because LANL does not provide a source IP address in this file. Any paper or report using the result must state this explicitly.

## Planned experiments

### E1 — COMISET process-rule validity

For the supported ATT&CK intersection, report:

- binary event-level TP, FP, FN and TN;
- exact-technique micro metrics;
- per-technique TP, FP, FN and TN;
- precision, recall and F1;
- false-positive rate where the negative unit is defensible;
- findings per 10,000 events.

A single aggregate score without per-technique results is not sufficient.

### E2 — real-environment alert behaviour

Run the same frozen process rules on an agreed COMISET real-environment subset. Report findings per 10,000 events and manually inspect a preregistered sample of findings before using the term `false positive`. An unlabeled real-environment event is not automatically proven benign.

This wording is important: absence of a COMISET attack-reference label is evidence for the dataset's labelled-normal setting, not a universal guarantee that the event is harmless.

### E3 — authentication stress check

Use LANL red-team windows to test whether the existing authentication rules happen to surface compromised authentication activity under their stated sequence assumptions. Low recall is a valid result because generic stolen-credential use is broader than TriageBloom's current authentication rules.

### E4 — sequence correlation ablation

Use selected OTRF/Mordor Windows recordings containing the required telemetry. Compare:

- relevant single/local detections with `TB-CORR-001` suppressed;
- the full TriageBloom pipeline with `TB-CORR-001` enabled.

Primary outputs should be incident retrieval, duplicate-alert reduction, and evidence-chain completeness. Do not call this a productivity improvement unless a separate analyst study is performed.

### E5 — runtime scaling

Run fixed event counts on one documented machine and record:

- Python version;
- operating system;
- processor;
- RAM;
- exact git commit;
- exact command;
- event count;
- median runtime over repeated runs;
- events per second;
- process RSS using an OS-level measurement tool.

Do not use `tracemalloc` alone as a manuscript claim for total process memory.

## Leakage and tuning controls

Before final scoring:

1. Freeze the TriageBloom commit and configuration.
2. Use small development samples only for parser/schema debugging.
3. Do not change a detection threshold because a final-test event failed to trigger.
4. Record every excluded technique or event class with a reason.
5. Keep synthetic regression fixtures separate from external evaluation results.
6. Preserve source dataset version, checksums, archive member, commands, and sampling seeds.
7. Report negative results.
8. Keep a clear distinction between absence of a reference label and independently established benign ground truth.

## Result storage

External raw datasets must **not** be committed to this repository.

Local research outputs should be written under:

```text
evaluation/external/
```

Only compact, non-sensitive, licence-compatible aggregate result JSON files should be considered for later publication. Dataset excerpts should not be committed unless their licence and redistribution terms clearly permit it.

## Reproducibility record for every final run

Record:

- dataset title and DOI/source;
- dataset version/date;
- source-file MD5 and SHA-256;
- selected archive member;
- TriageBloom commit SHA;
- exact command line;
- profile and thresholds;
- inclusion/exclusion rules;
- event count;
- evaluation unit;
- metric definitions;
- environment details;
- known limitations.

## Current status

The streaming COMISET adapter, direct-ZIP support, archive fingerprinting, schema/scope audit, supported-technique evaluator, LANL red-team-window extractor, LANL authentication evaluator, and unit tests are implemented. Full dataset results are intentionally not claimed until the official datasets are downloaded, verified, audited, and executed against a frozen evaluation commit/configuration.
