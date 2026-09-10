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


bundle = load_script("research_results_bundle")


class ResultsBundleTests(unittest.TestCase):
    def test_comiset_lab_keeps_binary_and_exact_metrics_separate(self) -> None:
        data = {
            "events_processed": 100,
            "supported_techniques": ["T1059.001"],
            "profiles": {
                "balanced": {
                    "process_finding_count": 4,
                    "findings_per_10000_events": 400.0,
                    "supported_scope_binary": {"precision": 0.9, "recall": 0.8, "f1_score": 0.8471},
                    "supported_scope_technique_micro": {"precision": 0.7, "recall": 0.6, "f1_score": 0.6462},
                    "per_technique": {
                        "T1059.001": {
                            "true_positives": 3,
                            "false_positives": 1,
                            "false_negatives": 2,
                            "precision": 0.75,
                            "recall": 0.6,
                            "f1_score": 0.6667,
                        }
                    },
                }
            },
        }
        text = bundle.comiset_lab_section(data)
        self.assertIn("Binary F1", text)
        self.assertIn("Exact F1", text)
        self.assertIn("T1059.001", text)
        self.assertIn("binary supported-scope detection and exact ATT&CK-technique agreement", text)

    def test_correlation_section_forbids_alert_reduction_interpretation(self) -> None:
        data = {
            "scenario_count": 2,
            "scenario_level_detection": {"precision": 1.0, "recall": 0.5, "f1_score": 0.6667},
            "median_expected_event_coverage": 0.8,
            "median_expected_stage_coverage": 1.0,
            "median_top_risk_uplift": 7.0,
            "median_correlation_rank": 1.0,
            "scenarios": [],
        }
        text = bundle.correlation_section(data)
        self.assertIn("does not suppress component findings", text)
        self.assertIn("no alert-reduction claim", text)

    def test_readiness_flags_missing_provenance(self) -> None:
        lab = {"events_processed": 100, "profiles": {}}
        performance = {"results": {}}
        checks = bundle.readiness(lab, performance)
        self.assertIn("MISSING: COMISET matrix git commit", checks)
        self.assertIn("MISSING: COMISET dataset SHA-256 fingerprint", checks)
        self.assertIn("MISSING: performance benchmark git commit", checks)

    def test_build_bundle_never_invents_missing_results(self) -> None:
        text = bundle.build_bundle(None, None, None, None, None)
        self.assertIn("MISSING: COMISET laboratory profile matrix", text)
        self.assertIn("MISSING: runtime/memory benchmark", text)
        self.assertNotIn("100.0000", text)


if __name__ == "__main__":
    unittest.main()
