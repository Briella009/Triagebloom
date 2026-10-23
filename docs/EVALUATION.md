# Evaluation methodology

TriageBloom includes a reproducible synthetic evaluation harness so rule behaviour can be checked with labelled cases rather than described only through screenshots.

## Detection-case verification

`evaluation/labelled_cases.json` contains deliberately constructed cases with known expected rule IDs. The current extended set contains **11 detection cases across 8 evaluated rules**, including:

- password spraying;
- account brute force;
- success after repeated failures;
- off-hours successful sign-in;
- MFA fatigue followed by success;
- suspicious PowerShell;
- selected LOLBin behaviour;
- authentication-to-endpoint correlation;
- a benign mixed-activity control;
- a business-hours boundary control;
- a benign PowerShell control.

Per-case configuration overrides are explicit in the dataset where required, for example enabling off-hours review for the dedicated boundary tests.

Run:

```bash
python scripts/evaluate_labelled.py --output evaluation/results-current.json
```

The evaluator reports:

- true positives;
- false positives;
- false negatives;
- true negatives over rule/case pairs;
- precision;
- recall;
- F1 score;
- false-positive rate;
- accuracy.

CI executes the evaluator on Python 3.12 and prints the current metrics in the workflow log.

## Ingestion and robustness verification

Malformed records are not mixed into detection-accuracy cases because an ingestion failure is a different outcome from a detection miss.

`evaluation/robustness_cases.json` covers:

- malformed JSON;
- unsupported file extensions;
- invalid timestamps;
- missing timestamps;
- empty input;
- a valid JSONL edge case.

`tests/test_robustness_evaluation.py` executes those cases as part of the normal unit-test suite.

## Historical v0.2.0 result

The committed `evaluation/results-v0.2.0.json` preserves the original eight-case / seven-rule release-preparation result. That historical controlled set produced precision, recall and F1 of 1.0000 with a false-positive rate of 0.0000.

Those values are **software-verification results, not real-world SOC accuracy claims**. The cases were deliberately constructed around implemented rule behaviour.

Do not assume the extended current suite has any particular metric value until the evaluator has actually been executed for the commit being discussed.

## What the synthetic evaluation does not prove

It does not establish:

- production detection accuracy;
- superiority over Microsoft Sentinel, Defender, Sigma, Hayabusa, Chainsaw, or another tool;
- analyst productivity gains;
- false-positive rates in a real organisation;
- resilience to every log schema;
- generalisation to unseen attacks;
- calibrated probability of compromise.

## Why the synthetic result is useful

Synthetic verification:

1. makes rule behaviour reproducible;
2. provides regression cases for future changes;
3. exercises boundary and benign controls;
4. exposes malformed-input expectations separately;
5. prevents unsupported marketing claims from being substituted for measurable tests.

## External evaluation is a separate track

The external research protocol is documented in `docs/RESEARCH_EVALUATION.md`. It includes pre-results infrastructure for COMISET, LANL, sequence-correlation ablation, runtime/memory measurement, result compilation, and reproducible figures.

Synthetic regression results must not be substituted for external-dataset results.

## Independent validation before 1.0

The project should still complete:

- independent practitioner review;
- the controlled analyst pilot in `docs/PILOT_PLAN.md`;
- accepted external-dataset runs under frozen configuration;
- disclosure of negative results and exclusions;
- evidence-based improvements identified through review.

## Reporting results responsibly

Any future public result should state:

- dataset source and licence;
- number of events/cases;
- ground-truth construction method;
- exact TriageBloom version or commit;
- configuration and thresholds;
- Python version and platform;
- metric definitions;
- limitations and negative results.

Never report a synthetic perfect score without immediately identifying it as controlled regression-style verification.
