# Sequence-correlation ablation protocol

This protocol evaluates the specific contribution of `TB-CORR-001` without claiming that TriageBloom performs general attack-graph reconstruction or reduces the total number of findings.

## What the current correlation rule actually does

`TB-CORR-001` looks for a narrow sequence for the same user:

1. repeated authentication failures;
2. a later successful authentication;
3. suspicious endpoint execution within the configured correlation window;
4. compatible device context when both authentication and process events contain a device.

When the sequence is present, TriageBloom adds a critical correlated finding that cites the contributing event IDs. It does **not** currently suppress the component authentication or process findings.

For that reason, the AISCN study will not claim `duplicate-alert reduction` from the current implementation.

## Ablation comparison

The evaluator runs every scenario twice with the same threshold profile:

- **baseline:** `TB-CORR-001` is suppressed;
- **full:** `TB-CORR-001` is enabled.

The implementation is `scripts/research_correlation_ablation.py`.

## Required scenario manifest

The input is a JSON object containing a non-empty `scenarios` array. Each scenario must contain:

```json
{
  "scenario_id": "example-001",
  "expected_correlation": true,
  "expected_event_ids": ["fail-1", "fail-2", "success-1", "process-1"],
  "event_stages": {
    "fail-1": "authentication_failure",
    "fail-2": "authentication_failure",
    "success-1": "authentication_success",
    "process-1": "endpoint_execution"
  },
  "events": []
}
```

`expected_event_ids` and `event_stages` are optional for running the detector, but evidence-coverage results are only meaningful when these values are justified independently from TriageBloom's output.

## Primary outputs

The experiment reports:

- scenario-level TP, FP, FN and TN for the explicit correlation rule;
- precision, recall and F1 for the selected positive/negative scenario set;
- rank of the correlated finding in the full TriageBloom output;
- change in highest risk score between baseline and full configurations;
- coverage of independently specified expected event IDs;
- coverage of independently specified attack stages.

These outputs answer whether the correlation rule surfaces the intended sequence and consolidates its evidence into one high-priority finding.

## What is deliberately not measured

The current experiment does not claim:

- reduction in total alerts or findings;
- faster analyst investigation;
- improved human decision quality;
- comprehensive multi-stage attack detection;
- superiority to graph-based or ML/LLM correlation systems.

Any human-productivity claim requires a separate participant study. Any alert-reduction claim requires an implementation that actually suppresses or groups component findings and an evaluation of that behaviour.

## Public-dataset eligibility rule

A public recording can be used only if its telemetry contains every observable component needed by the rule. A recording that contains `password spraying` and `PowerShell` somewhere in the same attack is not automatically eligible.

Before scoring, document whether the recording contains:

| Required observation | Present? |
| --- | --- |
| repeated failures for the same user | yes/no |
| later successful authentication for that user | yes/no |
| suspicious process execution after success | yes/no |
| timestamps sufficient to enforce the configured window | yes/no |
| user linkage across authentication and process events | yes/no |
| compatible device context, where available | yes/no |

If any required element is absent, the recording must not be used as a positive test of `TB-CORR-001`.

## Running the evaluator

```bash
python scripts/research_correlation_ablation.py \
  evaluation/external/correlation-scenarios.json \
  --profile balanced \
  --output evaluation/external/correlation-ablation-balanced.json
```

Repeat on other profiles only if profile sensitivity is a stated research question for the selected scenario set.

## Negative scenarios

Include negative controls that are plausibly confusable with the positive sequence, for example:

- repeated failures with no later success;
- failures and success with no suspicious endpoint execution;
- suspicious PowerShell without the authentication sequence;
- the right event types for different users;
- the right events outside the configured correlation window.

Negative controls should be fixed before scoring and should not be created after seeing which cases cause false positives.

## Reporting rule

The final paper should describe this experiment as a **sequence-correlation ablation**, not as an end-to-end SOC accuracy benchmark. If the selected public datasets provide too few defensible positive scenarios, report that limitation rather than manufacturing additional positives around the detector thresholds.
