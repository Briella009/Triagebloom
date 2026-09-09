from __future__ import annotations

import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from triagebloom.detections import DetectionConfig, run_detections
from triagebloom.models import AnalysisResult
from triagebloom.normalize import load_events
from triagebloom.report import render_html, render_json, result_to_dict, write_html, write_json


ROOT = Path(__file__).resolve().parents[1]


class ReportingTests(unittest.TestCase):
    def _result(self) -> AnalysisResult:
        events = load_events(ROOT / "sample_data" / "demo_events.json")
        return AnalysisResult(
            source_file="demo_events.json",
            generated_at=datetime.now(tz=timezone.utc),
            events_processed=len(events),
            findings=run_detections(events, DetectionConfig()),
            metadata={"triagebloom_version": "0.2.0"},
        )

    def test_redaction_replaces_user_identifiers(self) -> None:
        data = result_to_dict(self._result(), redact=True, salt="fixed-test-salt")
        serialised = str(data)
        self.assertNotIn("finance.admin@example.org", serialised)
        self.assertIn("redacted-", serialised)

    def test_redaction_hides_config_allowlists_and_source_filename(self) -> None:
        result = self._result()
        result.source_file = "client-a-incident.json"
        result.metadata["configuration"] = {
            "allow_users": ["svc-private@example.org"],
            "allow_source_ips": ["10.20.30.40"],
            "allow_devices": ["PRIVATE-JUMP-01"],
            "suppressed_rule_ids": [],
        }
        data = result_to_dict(result, redact=True, salt="fixed-test-salt")
        serialised = str(data)
        self.assertNotIn("client-a-incident.json", serialised)
        self.assertNotIn("svc-private@example.org", serialised)
        self.assertNotIn("10.20.30.40", serialised)
        self.assertNotIn("PRIVATE-JUMP-01", serialised)
        self.assertTrue(data["source_file"].startswith("redacted-source-"))

    def test_render_functions_return_downloadable_strings(self) -> None:
        result = self._result()
        json_text = render_json(result, redact=True, salt="fixed-test-salt")
        html_text = render_html(result, redact=True, salt="fixed-test-salt")
        self.assertIn('"finding_count"', json_text)
        self.assertIn("TriageBloom analysis report", html_text)
        self.assertIn("Triage score", html_text)
        self.assertIn("not calibrated probabilities of compromise", html_text)

    def test_web_report_does_not_claim_local_processing(self) -> None:
        result = self._result()
        result.metadata["processing_mode"] = "streamlit"
        html_text = render_html(result)
        self.assertIn("web interface", html_text)
        self.assertNotIn("Processing occurred locally on the analyst's computer", html_text)

    def test_html_and_json_reports_are_written(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            html_path = write_html(self._result(), root / "report.html")
            json_path = write_json(self._result(), root / "report.json")
            self.assertTrue(html_path.exists())
            self.assertTrue(json_path.exists())
            self.assertIn("TriageBloom analysis report", html_path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
