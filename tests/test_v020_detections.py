from __future__ import annotations

import json
import unittest
from pathlib import Path

from triagebloom.config import DetectionConfig, get_profile, load_config
from triagebloom.detections import run_detections
from triagebloom.normalize import load_events, normalise_row, normalise_rows


ROOT = Path(__file__).resolve().parents[1]


class V020DetectionTests(unittest.TestCase):
    def test_mfa_fatigue_is_detected(self) -> None:
        data = json.loads((ROOT / "evaluation" / "labelled_cases.json").read_text(encoding="utf-8"))
        case = next(item for item in data["cases"] if item["case_id"] == "mfa-fatigue-positive")
        findings = run_detections(normalise_rows(case["events"]), DetectionConfig(enable_off_hours=False))
        self.assertIn("TB-AUTH-005", {finding.rule_id for finding in findings})

    def test_incident_chain_is_detected(self) -> None:
        events = load_events(ROOT / "sample_data" / "combined_incident.json")
        findings = run_detections(events, DetectionConfig(enable_off_hours=False))
        self.assertIn("TB-CORR-001", {finding.rule_id for finding in findings})

    def test_incident_chain_requires_suspicious_process(self) -> None:
        events = load_events(ROOT / "sample_data" / "combined_incident.json")
        safe_events = [event for event in events if event.category != "process"]
        findings = run_detections(safe_events, DetectionConfig(enable_off_hours=False))
        self.assertNotIn("TB-CORR-001", {finding.rule_id for finding in findings})

    def test_allowlisted_source_ip_suppresses_spray(self) -> None:
        events = load_events(ROOT / "sample_data" / "demo_events.json")
        config = DetectionConfig(allow_source_ips={"203.0.113.50"})
        findings = run_detections(events, config)
        spray = [finding for finding in findings if finding.rule_id == "TB-AUTH-001"]
        self.assertEqual(spray, [])

    def test_partial_allowlist_does_not_hide_multi_user_spray(self) -> None:
        events = []
        for index, user in enumerate(("allowed@example.org", "u2@example.org", "u3@example.org", "u4@example.org", "u5@example.org")):
            events.append(
                normalise_row(
                    {
                        "timestamp": f"2026-08-20T10:0{index}:00Z",
                        "event_id": f"spray-partial-{index}",
                        "event_type": "SignInFailure",
                        "outcome": "Failure",
                        "user": user,
                        "source_ip": "203.0.113.99",
                    },
                    index + 1,
                )
            )
        config = DetectionConfig(allow_users={"allowed@example.org"})
        findings = run_detections(events, config)
        self.assertIn("TB-AUTH-001", {finding.rule_id for finding in findings})

    def test_suppressed_rule_is_not_returned(self) -> None:
        events = load_events(ROOT / "sample_data" / "demo_events.json")
        config = DetectionConfig(suppressed_rule_ids={"TB-PROC-001"})
        findings = run_detections(events, config)
        self.assertNotIn("TB-PROC-001", {finding.rule_id for finding in findings})

    def test_profiles_have_different_thresholds(self) -> None:
        learner = get_profile("learner")
        strict = get_profile("strict")
        self.assertLess(learner.brute_force_failures, strict.brute_force_failures)
        self.assertTrue(learner.enable_off_hours)
        self.assertFalse(strict.enable_off_hours)

    def test_config_file_loads_allowlists(self) -> None:
        config = load_config(ROOT / "config.example.json")
        self.assertIn("svc-backup@example.org", config.allow_users)
        self.assertIn("192.0.2.254", config.allow_source_ips)
        self.assertEqual(config.mfa_failures, 4)


if __name__ == "__main__":
    unittest.main()
