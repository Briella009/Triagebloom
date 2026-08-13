from __future__ import annotations

import unittest
from pathlib import Path

from triagebloom.detections import DetectionConfig, run_detections
from triagebloom.normalize import load_events


ROOT = Path(__file__).resolve().parents[1]


class DetectionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.events = load_events(ROOT / "sample_data" / "demo_events.json")
        self.findings = run_detections(self.events, DetectionConfig())
        self.rule_ids = [finding.rule_id for finding in self.findings]

    def test_password_spray_is_detected(self) -> None:
        self.assertIn("TB-AUTH-001", self.rule_ids)

    def test_brute_force_is_detected(self) -> None:
        self.assertIn("TB-AUTH-002", self.rule_ids)

    def test_success_after_failures_is_detected(self) -> None:
        self.assertIn("TB-AUTH-003", self.rule_ids)

    def test_suspicious_powershell_is_detected(self) -> None:
        self.assertIn("TB-PROC-001", self.rule_ids)

    def test_lolbin_is_detected(self) -> None:
        self.assertIn("TB-PROC-002", self.rule_ids)

    def test_findings_are_sorted_by_risk(self) -> None:
        scores = [finding.risk_score for finding in self.findings]
        self.assertEqual(scores, sorted(scores, reverse=True))


if __name__ == "__main__":
    unittest.main()
