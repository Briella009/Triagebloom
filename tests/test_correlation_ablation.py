from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def load_script(name: str):
    path = ROOT / "scripts" / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


ablation = load_script("research_correlation_ablation")


def positive_scenario() -> dict:
    events = []
    for index in range(5):
        events.append(
            {
                "timestamp": f"2026-01-01T10:0{index}:00Z",
                "event_id": f"fail-{index + 1}",
                "event_type": "failed sign-in",
                "outcome": "failure",
                "user": "analyst@example.com",
                "source_ip": "203.0.113.10",
                "device": "host01",
            }
        )
    events.extend(
        [
            {
                "timestamp": "2026-01-01T10:05:00Z",
                "event_id": "success-1",
                "event_type": "successful sign-in",
                "outcome": "success",
                "user": "analyst@example.com",
                "source_ip": "203.0.113.10",
                "device": "host01",
            },
            {
                "timestamp": "2026-01-01T10:06:00Z",
                "event_id": "process-1",
                "event_type": "process creation",
                "outcome": "unknown",
                "user": "analyst@example.com",
                "device": "host01",
                "command_line": "powershell.exe -EncodedCommand AAAA",
                "file_name": "powershell.exe",
            },
        ]
    )
    expected_ids = [f"fail-{index + 1}" for index in range(5)] + ["success-1", "process-1"]
    stages = {event_id: "authentication_failure" for event_id in expected_ids[:5]}
    stages["success-1"] = "authentication_success"
    stages["process-1"] = "endpoint_execution"
    return {
        "scenario_id": "positive-chain",
        "expected_correlation": True,
        "expected_event_ids": expected_ids,
        "event_stages": stages,
        "events": events,
    }


def negative_scenario() -> dict:
    return {
        "scenario_id": "negative-normal",
        "expected_correlation": False,
        "events": [
            {
                "timestamp": "2026-01-01T11:00:00Z",
                "event_id": "normal-login",
                "event_type": "successful sign-in",
                "outcome": "success",
                "user": "analyst@example.com",
                "source_ip": "198.51.100.20",
                "device": "host01",
            },
            {
                "timestamp": "2026-01-01T11:01:00Z",
                "event_id": "normal-process",
                "event_type": "process creation",
                "outcome": "unknown",
                "user": "analyst@example.com",
                "device": "host01",
                "command_line": "notepad.exe notes.txt",
                "file_name": "notepad.exe",
            },
        ],
    }


class CorrelationAblationTests(unittest.TestCase):
    def test_positive_chain_is_found_and_preserves_all_expected_stages(self) -> None:
        result = ablation.evaluate_scenario(positive_scenario(), "balanced")
        self.assertTrue(result["correlation_detected"])
        self.assertNotIn("TB-CORR-001", result["baseline_rule_ids"])
        self.assertIn("TB-CORR-001", result["full_rule_ids"])
        self.assertEqual(result["expected_event_coverage"], 1.0)
        self.assertEqual(result["expected_stage_coverage"], 1.0)
        self.assertGreaterEqual(result["top_risk_uplift"], 0)

    def test_manifest_scores_positive_and_negative_scenarios(self) -> None:
        result = ablation.evaluate_manifest(
            {"dataset": "unit-test", "scenarios": [positive_scenario(), negative_scenario()]},
            "balanced",
        )
        metrics = result["scenario_level_detection"]
        self.assertEqual(metrics["true_positives"], 1)
        self.assertEqual(metrics["true_negatives"], 1)
        self.assertEqual(metrics["false_positives"], 0)
        self.assertEqual(metrics["false_negatives"], 0)
        self.assertEqual(metrics["f1_score"], 1.0)

    def test_profile_suppression_does_not_leak_between_runs(self) -> None:
        first = ablation.evaluate_scenario(positive_scenario(), "balanced")
        second = ablation.evaluate_scenario(positive_scenario(), "balanced")
        self.assertTrue(first["correlation_detected"])
        self.assertTrue(second["correlation_detected"])


if __name__ == "__main__":
    unittest.main()
