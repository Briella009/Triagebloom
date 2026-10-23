# Evaluation assets

This directory contains reproducible synthetic verification assets plus pre-results research infrastructure.

- `labelled_cases.json` contains synthetic detection cases and expected rule IDs.
- `robustness_cases.json` contains malformed-input and ingestion edge cases.
- `results-v0.2.0.json` preserves the historical v0.2.0 synthetic verification result.
- `evaluation/aiscn2027_protocol.json` and the research scripts define the external pre-results evaluation track.

The current labelled suite includes authentication, process, correlation, benign-control, off-hours, and boundary cases. The robustness suite separately exercises malformed JSON, unsupported extensions, invalid/missing timestamps, empty input, and valid JSONL edge handling.

Run the current synthetic detection evaluation with:

```bash
python scripts/evaluate_labelled.py --output evaluation/results-current.json
```

The CI workflow also runs this evaluation and exposes the metrics in the job log.

These cases are software-verification fixtures. They are not a substitute for independent, public-dataset, or production validation. See `docs/EVALUATION.md` and `docs/RESEARCH_EVALUATION.md`.
