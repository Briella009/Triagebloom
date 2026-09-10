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

Important claim boundary: COMISET's ATT&CK labels were created by its own event-based detection and labelling pipeline. They are useful **reference labels**, but this study will not describe them as perfect forensic ground truth. This matters because a rule-based TriageBloom detector can agree with a rule-generated COMISET label for reasons that do not establish independent clinical-style ground truth.

Current quantitative overlap is restricted to the process techniques implemented by TriageBloom:

- `T1059.001` — PowerShell
- `T1105` — Ingress Tool Transfer, where represented by implemented LOLBin logic
- `T1197` — BITS Jobs
- `T1218.005` — Mshta
- `T1218.010` — Regsvr32
- `T1218.011` — Rundll32

The evaluator reports results only for this supported intersection. It must not count all other COMISET attack-labelled events as TriageBloom false negatives.

### LANL Comprehensive Multi-Source Cyber-Security Events

The LANL dataset is a secondary authentication stress/sanity check. Its authentication file contains time, source user, destination user, source computer, destination computer, authentication type, logon type, orientation, and success/failure. The separate red-team file identifies known compromised authentication events.

The research adapter is `scripts/research_lanl_eval.py`.

The LANL red-team labels represent successful stolen-credential authentications. TriageBloom does not claim to detect every stolen-credential login, so LANL results must not be presented as the primary accuracy benchmark. The process names in LANL are also de-identified, which prevents a defensible test of TriageBloom's command-line PowerShell/LOLBin logic or the full authentication-to-suspicious-process correlation rule.

### OTRF Security Datasets / Mordor

A separate sequence-correlation experiment is planned with selected Windows OTRF Security Datasets. These datasets intentionally preserve malicious events plus surrounding contextual events and can include both Windows Security Auditing and Sysmon telemetry. That makes them a better fit than LANL for testing a specific multi-event authentication-to-process sequence.

This experiment will be added only after selecting recordings whose telemetry actually contains all components required by the TriageBloom correlation rule. The selection criteria must be written down before scoring.

## Why the evaluation is split across datasets

No single public dataset should be forced to validate a capability it cannot observe.

COMISET is strong for modern Windows endpoint/process telemetry and ATT&CK-labelled process behaviours. LANL provides large-scale real enterprise authentication data and explicit red-team authentication references, but little process semantic detail. OTRF recordings are smaller and controlled, but retain the Windows event context needed for sequence-level correlation experiments.

Using each dataset only for the claims its telemetry can support is more defensible than reporting one headline accuracy number across incompatible event types.

## COMISET workflow

After downloading and extracting the official dataset locally, first inspect technique coverage without loading the entire file into memory:

```bash
python scripts/research_comiset_eval.py summary /path/to/comiset.json \
  --output evaluation/external/comiset-summary.json
```

For an initial schema check:

```bash
python scripts/research_comiset_eval.py summary /path/to/comiset.json \
  --max-events 10000
```

Run the supported-scope evaluator:

```bash
python scripts/research_comiset_eval.py evaluate /path/to/comiset.json \
  --profile balanced \
  --batch-events 100000 \
  --output evaluation/external/comiset-balanced.json
```

The reader supports CSV, JSONL/NDJSON, and top-level JSON arrays, with optional gzip or bzip2 compression. The official ZIP archive should be extracted first.

The script processes records in batches so the full COMISET file is not loaded into memory.

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

- true positives;
- false positives;
- false negatives;
- true negatives where the evaluation unit is defensible;
- precision;
- recall;
- F1 score;
- false-positive rate;
- per-technique results.

The final paper should report both the binary supported-scope result and per-technique results. A single aggregate score without the per-technique table can hide major differences between rules.

### E2 — real-environment false-positive behaviour

Run the same frozen process rules on an agreed COMISET real-environment subset. Report findings per 10,000 events in addition to false-positive metrics. Do not tune thresholds on the final test subset.

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
6. Preserve source dataset version, checksums, extraction commands, and sampling seeds.
7. Report negative results.

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
- source-file checksum;
- TriageBloom commit SHA;
- command line;
- profile and thresholds;
- inclusion/exclusion rules;
- event count;
- evaluation unit;
- metric definitions;
- environment details;
- known limitations.

## Current status

The streaming COMISET adapter, supported-technique evaluator, LANL red-team-window extractor, LANL authentication evaluator, and unit tests are implemented on the research branch. Full dataset results are intentionally not claimed until the official datasets are downloaded and the frozen evaluation commands are executed.
