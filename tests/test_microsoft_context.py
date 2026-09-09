from __future__ import annotations

import unittest
from pathlib import Path

from triagebloom.normalize import load_events, normalise_row


ROOT = Path(__file__).resolve().parents[1]


class MicrosoftContextTests(unittest.TestCase):
    def test_entra_adapter_extracts_security_context(self) -> None:
        event = load_events(ROOT / "sample_data" / "entra_signins.json")[0]
        self.assertEqual(event.source_product, "microsoft_entra")
        self.assertEqual(event.conditional_access_status, "failure")
        self.assertEqual(event.risk_level, "medium")
        self.assertEqual(event.risk_state, "atRisk")
        self.assertEqual(event.authentication_requirement, "multiFactorAuthentication")
        self.assertIn("Microsoft Authenticator", event.authentication_method or "")
        self.assertEqual(event.device, "LAPTOP-DEMO-01")

    def test_defender_process_adapter_extracts_process_context(self) -> None:
        event = load_events(ROOT / "sample_data" / "defender_processes.json")[0]
        self.assertEqual(event.source_product, "microsoft_defender")
        self.assertEqual(event.category, "process")
        self.assertEqual(event.file_name, "powershell.exe")
        self.assertEqual(event.parent_process, "winword.exe")
        self.assertEqual(event.sha256, "d" * 64)

    def test_defender_alert_adapter_is_identified(self) -> None:
        event = load_events(ROOT / "sample_data" / "defender_alerts.json")[0]
        self.assertEqual(event.source_product, "microsoft_defender_alert")
        self.assertEqual(event.category, "alert")
        self.assertEqual(event.alert_severity, "High")
        self.assertEqual(event.event_id, "def-alert-001")

    def test_status_error_code_can_drive_entra_outcome(self) -> None:
        event = normalise_row(
            {
                "createdDateTime": "2026-08-21T09:00:00Z",
                "id": "status-1",
                "activityDisplayName": "User sign-in",
                "userPrincipalName": "user@example.org",
                "conditionalAccessStatus": "failure",
                "authenticationRequirement": "multiFactorAuthentication",
                "status": {"errorCode": 500121},
            },
            1,
        )
        self.assertEqual(event.outcome, "failure")


if __name__ == "__main__":
    unittest.main()
