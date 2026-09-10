from __future__ import annotations

import argparse
import json
import statistics
import sys
from pathlib import Path
from typing import Any

from triagebloom.config import get_profile
from triagebloom.detections import run_detections
from triagebloom.normalize import InputFormatError, normalise_rows


CORRELATION_RULE = "TB-CORR-001"


def classification_metrics(tp: int, fp: int, fn: int, tn: int) -> dict[str, Any]:
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {
        "true_positives": tp,
        "false_positives": fp,
        "false_negatives": fn,
        "true_negatives": tn,
        "precision": round(precision, 6),
        "recall": round(recall, 6),
        "f1_score": round(f1, 6),
    }


def _top_risk(findings: list[Any]) -> int:
    return max((finding.risk_score for finding in findings), default=0)


def _rank(findings: list[Any], rule_id: str) -> int | None:
    for index, finding in enumerate(findings, start=1):
        if finding.rule_id == rule_id:
            return index
    return None


def _coverage(observed: set[str], expected: set[str]) -> float | None:
    if not expected:
        return None
    return round(len(observed & expected) / len(expected), 6)


def evaluate_scenario(scenario: dict[str, Any], profile: str) -> dict[str, Any]:
    scenario_id = str(scenario.get("scenario_id") or "").strip()
    if not scenario_id:
        raise ValueError("Each scenario requires a non-empty scenario_id")
    if "expected_correlation" not in scenario or not isinstance(scenario["expected_correlation"], bool):
        raise ValueError(f"Scenario {scenario_id!r} requires boolean expected_correlation")
    raw_events = scenario.get("events")
    if not isinstance(raw_events, list) or not all(isinstance(item, dict) for item in raw_events):
        raise ValueError(f"Scenario {scenario_id!r} events must be an array of objects")

    events = normalise_rows(raw_events)
    baseline_config = get_profile(profile)
    baseline_config.enable_off_hours = False
    baseline_config.suppressed_rule_ids.add(CORRELATION_RULE)

    full_config = get_profile(profile)
    full_config.enable_off_hours = False

    baseline = run_detections(events, baseline_config)
    full = run_detections(events, full_config)
    correlated = [finding for finding in full if finding.rule_id == CORRELATION_RULE]
    selected = correlated[0] if correlated else None

    expected_event_ids = {str(value) for value in scenario.get("expected_event_ids", [])}
    stage_map_raw = scenario.get("event_stages", {})
    if not isinstance(stage_map_raw, dict):
        raise ValueError(f"Scenario {scenario_id!r} event_stages must be an object")
    stage_map = {str(event_id): str(stage) for event_id, stage in stage_map_raw.items()}
    expected_stages = {stage_map[event_id] for event_id in expected_event_ids if event_id in stage_map}

    evidence_ids = set(selected.evidence_event_ids) if selected else set()
    observed_stages = {stage_map[event_id] for event_id in evidence_ids if event_id in stage_map}

    baseline_top = _top_risk(baseline)
    full_top = _top_risk(full)
    return {
        "scenario_id": scenario_id,
        "source": scenario.get("source"),
        "expected_correlation": scenario["expected_correlation"],
        "correlation_detected": bool(correlated),
        "baseline_rule_ids": [finding.rule_id for finding in baseline],
        "full_rule_ids": [finding.rule_id for finding in full],
        "baseline_finding_count": len(baseline),
        "full_finding_count": len(full),
        "baseline_top_risk": baseline_top,
        "full_top_risk": full_top,
        "top_risk_uplift": full_top - baseline_top,
        "correlation_rank": _rank(full, CORRELATION_RULE),
        "correlation_risk_score": selected.risk_score if selected else None,
        "correlation_evidence_event_ids": sorted(evidence_ids),
        "expected_event_coverage": _coverage(evidence_ids, expected_event_ids),
        "expected_stage_coverage": _coverage(observed_stages, expected_stages),
        "expected_stages": sorted(expected_stages),
        "observed_stages": sorted(observed_stages),
        "note": scenario.get("note"),
    }


def read_manifest(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, list):
        data = {"scenarios": data}
    if not isinstance(data, dict):
        raise ValueError("Correlation manifest must be a JSON object or array")
    scenarios = data.get("scenarios")
    if not isinstance(scenarios, list) or not scenarios:
        raise ValueError("Correlation manifest requires a non-empty scenarios array")
    ids = [str(item.get("scenario_id") or "") for item in scenarios if isinstance(item, dict)]
    if len(ids) != len(scenarios) or any(not value for value in ids):
        raise ValueError("Every correlation scenario must be an object with scenario_id")
    if len(set(ids)) != len(ids):
        raise ValueError("Correlation scenario_id values must be unique")
    return data


def evaluate_manifest(data: dict[str, Any], profile: str) -> dict[str, Any]:
    details = [evaluate_scenario(scenario, profile) for scenario in data["scenarios"]]
    tp = fp = fn = tn = 0
    positive_coverages: list[float] = []
    stage_coverages: list[float] = []
    risk_uplifts: list[int] = []
    correlation_ranks: list[int] = []

    for detail in details:
        expected = detail["expected_correlation"]
        observed = detail["correlation_detected"]
        if expected and observed:
            tp += 1
        elif observed:
            fp += 1
        elif expected:
            fn += 1
        else:
            tn += 1

        if expected and detail["expected_event_coverage"] is not None:
            positive_coverages.append(detail["expected_event_coverage"])
        if expected and detail["expected_stage_coverage"] is not None:
            stage_coverages.append(detail["expected_stage_coverage"])
        if expected:
            risk_uplifts.append(detail["top_risk_uplift"])
        if expected and detail["correlation_rank"] is not None:
            correlation_ranks.append(detail["correlation_rank"])

    result = {
        "evaluation_type": "TriageBloom sequence-correlation ablation",
        "profile": profile,
        "scenario_count": len(details),
        "scenario_level_detection": classification_metrics(tp, fp, fn, tn),
        "median_expected_event_coverage": round(statistics.median(positive_coverages), 6)
        if positive_coverages
        else None,
        "median_expected_stage_coverage": round(statistics.median(stage_coverages), 6)
        if stage_coverages
        else None,
        "median_top_risk_uplift": round(statistics.median(risk_uplifts), 6) if risk_uplifts else None,
        "median_correlation_rank": round(statistics.median(correlation_ranks), 6) if correlation_ranks else None,
        "scenarios": details,
        "limitations": [
            "The ablation measures whether the explicit TB-CORR-001 sequence is surfaced; it does not claim comprehensive incident detection.",
            "TriageBloom currently adds a correlated finding without suppressing its component findings, so alert-reduction claims are not made.",
            "Evidence and stage coverage are meaningful only when the scenario manifest provides independently justified expected event IDs and stage labels.",
            "Human productivity or usability is not measured by this evaluator.",
        ],
    }
    if data.get("dataset") is not None:
        result["dataset"] = data["dataset"]
    if data.get("dataset_version") is not None:
        result["dataset_version"] = data["dataset_version"]
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Evaluate TB-CORR-001 against independently defined positive and negative event scenarios"
    )
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--profile", choices=("learner", "balanced", "strict"), default="balanced")
    parser.add_argument("--output", type=Path, default=Path("evaluation/external/correlation-ablation.json"))
    args = parser.parse_args(argv)

    try:
        data = read_manifest(args.manifest)
        result = evaluate_manifest(data, args.profile)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(result, indent=2, sort_keys=True), encoding="utf-8")
        metrics = result["scenario_level_detection"]
        print(f"scenarios={result['scenario_count']}")
        print(f"precision={metrics['precision']:.6f}")
        print(f"recall={metrics['recall']:.6f}")
        print(f"f1_score={metrics['f1_score']:.6f}")
        print(f"result={args.output}")
        return 0
    except (FileNotFoundError, ValueError, InputFormatError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
