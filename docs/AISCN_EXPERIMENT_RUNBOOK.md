# AISCN 2027 experiment execution runbook

This runbook turns the pre-results research protocol into a fixed execution sequence. It is intentionally kept separate from the unpublished manuscript.

## Goal

Produce reproducible external-evaluation outputs for the paper working title:

**TriageBloom: Explainable Cross-Event Security Triage for Resource-Constrained SOCs**

The experiment package must preserve negative results and disagreements. It must not be used to tune rules against the final evaluation stream.

## Frozen protocol

The machine-readable protocol is:

```text
evaluation/aiscn2027_protocol.json
```

Read it before final scoring. If the research question or evaluation scope changes materially, version the protocol instead of silently replacing the original assumptions after seeing results.

## Primary COMISET sequence

### 1. Download the official lab archive

Expected file name:

```text
Comiset23_Lab_Environment_Dataset.zip
```

Keep it outside the repository or under `evaluation/external/`, which is gitignored.

### 2. Verify the archive before analysis

```bash
python scripts/research_comiset_eval.py fingerprint \
  evaluation/external/Comiset23_Lab_Environment_Dataset.zip \
  --output evaluation/external/comiset-lab-fingerprint.json
```

The expected publisher MD5 currently recorded in the evaluator is:

```text
e838308bfa31fba1e273d500d588aba6
```

A mismatch stops the final experiment until the download source/version is resolved.

### 3. Identify the data member in the ZIP

If the archive contains multiple supported data files, the evaluator deliberately refuses to guess. Inspect the archive and pass the chosen member using `--member`.

Do not choose a member because it gives better results. Selection must be based on the dataset documentation and the telemetry needed for the stated experiment.

### 4. Run the preflight audit before accuracy scoring

Start with 100,000 records:

```bash
python scripts/research_comiset_eval.py audit \
  evaluation/external/Comiset23_Lab_Environment_Dataset.zip \
  --member '<DATA_MEMBER>' \
  --max-events 100000 \
  --output evaluation/external/comiset-lab-audit-100k.json
```

Inspect:

- timestamp coverage;
- command-line coverage;
- process-name coverage;
- parent-process coverage;
- user and host coverage;
- ATT&CK-reference coverage;
- parse errors;
- counts for the TriageBloom-supported ATT&CK intersection.

This step is a schema and scope check only. It is not a performance result.

### 5. Run a full supported-technique inventory

```bash
python scripts/research_comiset_eval.py summary \
  evaluation/external/Comiset23_Lab_Environment_Dataset.zip \
  --member '<DATA_MEMBER>' \
  --output evaluation/external/comiset-lab-technique-summary.json
```

The final paper must disclose techniques that are absent or too sparse for meaningful per-technique evaluation.

### 6. Freeze the evaluation commit

Immediately before the final profile matrix, record:

```bash
git rev-parse HEAD
```

Do not change rules or profile thresholds after the first final-test scoring pass. If a correctness bug is found, document it, fix it in a new commit, and rerun every affected configuration rather than selectively replacing one result.

### 7. Run all three profiles in the same streaming pass

```bash
python scripts/research_comiset_matrix.py \
  evaluation/external/Comiset23_Lab_Environment_Dataset.zip \
  --member '<DATA_MEMBER>' \
  --dataset-role lab \
  --profiles learner balanced strict \
  --batch-events 100000 \
  --output evaluation/external/comiset-lab-profile-matrix.json \
  --csv-output evaluation/external/comiset-lab-profile-matrix.csv
```

This keeps learner, balanced and strict on the same event stream and emits both machine-readable JSON and a compact CSV for the manuscript table.

The matrix keeps two different questions separate:

- **binary supported-scope metrics:** did TriageBloom surface any supported malicious behaviour on that row?
- **exact-technique micro metrics:** did the predicted supported ATT&CK technique agree with the COMISET reference label?

Do not collapse these into one headline score.

## Real-environment COMISET run

The real-environment archive is used for alert-density analysis, not as a source of automatically proven true negatives.

Run the same preflight and then:

```bash
python scripts/research_comiset_matrix.py \
  evaluation/external/Comiset23_Real_Environment_Dataset.zip \
  --member '<DATA_MEMBER>' \
  --dataset-role real \
  --profiles learner balanced strict \
  --batch-events 100000 \
  --output evaluation/external/comiset-real-profile-matrix.json \
  --csv-output evaluation/external/comiset-real-profile-matrix.csv
```

For this dataset role the matrix intentionally omits precision, recall and false-positive-rate claims. Report findings per 10,000 events and investigate representative findings separately before using the phrase `false positive`.

## LANL secondary experiment

LANL remains a secondary authentication stress/sanity check. It is not a universal accuracy benchmark for TriageBloom because a stolen-credential login need not contain the failure sequences used by TriageBloom rules.

Follow the commands in `docs/RESEARCH_EVALUATION.md` to extract fixed windows around the red-team references and evaluate the authentication rules.

## Sequence-correlation experiment

`TB-CORR-001` requires:

1. repeated authentication failures for the same user within the configured window;
2. a subsequent successful authentication;
3. suspicious endpoint execution for that user within the correlation window;
4. compatible device context when both sides provide a device.

Do not select a public attack recording merely because it contains password spraying and PowerShell. The recording must contain the exact observable sequence required by the rule.

Before evaluating an OTRF/Mordor recording, record a small eligibility table with each required component marked present/absent. Only then decide whether the recording can be used for the correlation ablation.

## Performance experiment

Performance numbers used in the manuscript should be produced on one documented machine with a frozen commit.

For each event-count target:

- perform one warm-up run;
- perform at least five measured runs;
- report the median and interquartile range;
- record events/second;
- record total-process RSS with an OS-level measurement utility;
- preserve the command, Python version, OS, processor and RAM.

Do not compare hardware cost with another research system unless that system is actually measured under a defensibly comparable setup.

## Result acceptance checklist

A result is eligible for the paper only if all of the following are known:

- official dataset/version;
- source-file checksum;
- exact archive member or source file;
- TriageBloom commit SHA;
- profile/configuration;
- exact command;
- event count;
- metric definition;
- exclusions;
- environment information;
- known limitations.

If any of these is missing, treat the output as exploratory rather than final.

## Manuscript boundary

Do not commit the unpublished AISCN manuscript, reviewer-response drafts, or private author notes to the public TriageBloom repository. Public repository content should contain only the software, reproducibility protocol, evaluation tooling, licence-compatible aggregates, and documentation needed to reproduce published claims.
