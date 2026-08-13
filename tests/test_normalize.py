from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from triagebloom.normalize import InputFormatError, load_events, normalise_row


class NormalizeTests(unittest.TestCase):
    def test_normalises_entra_style_fields(self) -> None:
        event = normalise_row(
            {
                "createdDateTime": "2026-08-10T10:00:00Z",
                "id": "abc123",
                "activityDisplayName": "User login",
                "resultType": "0",
                "userPrincipalName": "user@example.org",
                "ipAddress": "192.0.2.5",
            },
            1,
        )
        self.assertEqual(event.event_id, "abc123")
        self.assertEqual(event.outcome, "success")
        self.assertEqual(event.category, "authentication")
        self.assertEqual(event.user, "user@example.org")
        self.assertEqual(event.source_ip, "192.0.2.5")

    def test_loads_json_wrapper(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "events.json"
            path.write_text(
                json.dumps(
                    {
                        "value": [
                            {
                                "timestamp": "2026-08-10T10:00:00Z",
                                "event_type": "SignIn",
                                "outcome": "Success",
                                "user": "user@example.org",
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            events = load_events(path)
            self.assertEqual(len(events), 1)
            self.assertEqual(events[0].outcome, "success")

    def test_rejects_missing_timestamp(self) -> None:
        with self.assertRaises(InputFormatError):
            normalise_row({"user": "user@example.org"}, 1)


if __name__ == "__main__":
    unittest.main()
