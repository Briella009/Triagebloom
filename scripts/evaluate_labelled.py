from __future__ import annotations

import argparse
import json
import platform
import sys
from pathlib import Path
from typing import Any

from triagebloom.config import DetectionConfig, validate_config
from triagebloom.detections import run_detections
from triagebloom.normalize import normalise_rows


def _config_for_case(case: dict[str, Any]) -> DetectionConfig:
    config = DetectionConfig(enable_off_hours=False)
    overrides = case.get("config_overrides", {})
    if not isinstance(overrides, dict):
        raise ValueError(f"Case {case.get('case_id', '<unknown>')} config_overrides must be an object")

    for field_name, value in overrides.items():
        if not hasattr(config, field_name):
            raise ValueError(
                f"Case {case.get('case_id', '<unknown>')} uses unknown config field {field_name!r}"
            )
        setattr(config, field_name, value)

    validate_config(config)
    return config


def evaluate(data: dict[str, Any]) -> dict[str, Any]:
    rule_universe = set(data["rule_universe"])
    cases = data["cases"]
    tp = fp = fn = tn = 0
    details: list[dict[str, Any]] = []

    for case in cases:
        expected = set(case.get("expected_rule_ids", []))
        events = normalise_rows(case.get("events", []))
        config = _config_for_case(case)
        predicted = {
            finding.rule_id
            for finding in run_detections(events, config)
            if finding.rule_id in rule_universe
        }

        case_tp = sorted(expected & predicted)
        case_fp = sorted(predicted - expected)
        case_fn = sorted(expected - predicted)
        case_tn = sorted(rule_universe - expected - predicted)
        tp += len(case_tp)
        fp += len(case_fp)
        fn += len(case_fn)
        tn += len(case_tn)

        details.append(
            {
                "case_id": case["case_id"],
                "expected": sorted(expected),
                "predicted": sorted(predicted),
                "config_overrides": case.get("config_overrides", {}),
                "true_positive_rules": case_tp,
                "false_positive_rules": case_fp,
                "false_negative_rules": case_fn,
            }
        )

    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    fpr = fp / (fp + tn) if fp + tn else 0.0
    accuracy = (tp + tn) / (tp + tn + fp + fn) if tp + tn + fp + fn else 0.0

    return {
        "evaluation_type": "synthetic rule-level case evaluation",
        "case_count": len(cases),
        "rule_count": len(rule_universe),
        "true_positives": tp,
        "false_positives": fp,
        "false_negatives": fn,
        "true_negatives": tn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1_score": round(f1, 4),
        "false_positive_rate": round(fpr, 4),
        "accuracy": round(accuracy, 4),
        "environment": {
            "python": sys.version.split()[0],
            "platform": platform.platform(),
        },
        "limitations": [
            "The evaluation cases are synthetic and do not estimate real-world SOC performance.",
            "Metrics are computed over rule/case pairs, not individual production alerts.",
            "Results should be replicated on public or independently curated datasets before broader claims are made.",
        ],
        "cases": details,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Evaluate TriageBloom against labelled synthetic cases")
    parser.add_argument("--dataset", type=Path, default=Path("evaluation/labelled_cases.json"))
    parser.add_argument("--output", type=Path, default=Path("evaluation/results-current.json"))
    args = parser.parse_args()

    data = json.loads(args.dataset.read_text(encoding="utf-8"))
    result = evaluate(data)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2), encoding="utf-8")

    print(f"cases={result['case_count']}")
    print(f"rules={result['rule_count']}")
    print(f"precision={result['precision']:.4f}")
    print(f"recall={result['recall']:.4f}")
    print(f"f1_score={result['f1_score']:.4f}")
    print(f"false_positive_rate={result['false_positive_rate']:.4f}")
    print(f"result={args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
