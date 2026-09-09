# Evaluation methodology

TriageBloom includes a reproducible synthetic evaluation harness so that rule behaviour can be checked with labelled cases rather than described only through screenshots.

## What the current evaluation measures

`evaluation/labelled_cases.json` contains deliberately constructed cases with known expected rule IDs. The evaluator runs TriageBloom on each case and compares the returned rule IDs with ground truth.

Run:

```bash
python scripts/evaluate_labelled.py
```

The script reports:

- true positives;
- false positives;
- false negatives;
- true negatives over rule/case pairs;
- precision;
- recall;
- F1 score;
- false-positive rate;
- accuracy.

It also writes a machine-readable JSON result file.

## Current release-preparation result

The 0.2.0 preparation set contains eight synthetic cases spanning seven evaluated rules. In the preparation environment the deliberately constructed set produced:

- precision: 1.0000
- recall: 1.0000
- F1 score: 1.0000
- false-positive rate: 0.0000

These numbers are a **software verification result, not a real-world SOC accuracy claim**.

The cases were designed around the implemented thresholds, so a perfect result mainly demonstrates that the rules behave as expected on controlled fixtures.

## What the current evaluation does not prove

It does not establish:

- production detection accuracy;
- superiority over Microsoft Sentinel, Defender, Sigma, or another SIEM/EDR;
- analyst productivity gains;
- false-positive rates in a real organisation;
- resilience to all log formats;
- generalisation to unseen attacks;
- calibrated probability of compromise.

## Why the result is committed

Committing the synthetic evaluation serves three purposes:

1. makes rule behaviour reproducible;
2. provides regression cases for future changes;
3. prevents unsupported marketing claims from being substituted for measurable tests.

## Next validation stage

Before TriageBloom 1.0, the project should add independent evidence through at least two of the following:

- an appropriate licensed public or independently curated dataset;
- an independently prepared synthetic dataset not written around the rules;
- controlled analyst testing comparing raw-log review with TriageBloom-assisted review;
- independent practitioner review of detections and reporting.

The pilot design in `docs/PILOT_PLAN.md` measures investigation time, correct findings, false-positive acceptance, confidence, and report clarity.

## Reporting results responsibly

Any future public result should state:

- dataset source and licence;
- number of events and cases;
- ground-truth construction method;
- exact TriageBloom version or commit;
- configuration and thresholds;
- Python version and platform;
- metric definitions;
- limitations and negative results.

Do not report a synthetic 1.0 F1 score without immediately identifying it as a controlled regression-style evaluation.
