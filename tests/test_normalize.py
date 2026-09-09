from __future__ import annotations

import csv
import json
import tempfile
import unittest
from pathlib import Path

from triagebloom.normalize import InputFormatError, load_events, load_events_bytes, normalise_row


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
        self.assertEqual(event.source_product, "microsoft_entra")

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

    def test_loads_csv_and_jsonl(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            csv_path = root / "events.csv"
            with csv_path.open("w", encoding="utf-8", newline="") as handle:
                writer = csv.DictWriter(handle, fieldnames=["timestamp", "event_type", "outcome", "user"])
                writer.writeheader()
                writer.writerow({
                    "timestamp": "2026-08-10T10:00:00Z",
                    "event_type": "SignIn",
                    "outcome": "Success",
                    "user": "csv.user@example.org",
                })
            jsonl_path = root / "events.jsonl"
            jsonl_path.write_text(
                json.dumps({
                    "timestamp": "2026-08-10T11:00:00Z",
                    "event_type": "SignIn",
                    "outcome": "Failure",
                    "user": "jsonl.user@example.org",
                }) + "\n",
                encoding="utf-8",
            )
            self.assertEqual(load_events(csv_path)[0].user, "csv.user@example.org")
            self.assertEqual(load_events(jsonl_path)[0].user, "jsonl.user@example.org")

    def test_epoch_milliseconds_are_supported(self) -> None:
        event = normalise_row(
            {
                "timestamp": 1786356000000,
                "event_type": "SignIn",
                "outcome": "Success",
                "user": "epoch.user@example.org",
            },
            1,
        )
        self.assertEqual(event.timestamp.tzinfo.utcoffset(event.timestamp).total_seconds(), 0)

    def test_status_object_with_pascal_case_is_supported(self) -> None:
        event = normalise_row(
            {
                "createdDateTime": "2026-08-10T10:00:00Z",
                "id": "status-case",
                "activityDisplayName": "Sign-in",
                "Status": {"errorCode": 50126},
                "userPrincipalName": "status.user@example.org",
                "ipAddress": "192.0.2.50",
            },
            1,
        )
        self.assertEqual(event.outcome, "failure")
        self.assertEqual(event.source_product, "microsoft_entra")

    def test_loads_uploaded_bytes_without_disk_write(self) -> None:
        payload = json.dumps({
            "value": [{
                "createdDateTime": "2026-08-10T10:00:00Z",
                "id": "upload-1",
                "activityDisplayName": "Sign-in",
                "resultType": "0",
                "userPrincipalName": "upload.user@example.org",
                "ipAddress": "192.0.2.91",
            }]
        }).encode("utf-8")
        events = load_events_bytes(payload, "entra.json")
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].source_product, "microsoft_entra")
        self.assertEqual(events[0].user, "upload.user@example.org")

    def test_uploaded_bytes_reject_unsupported_extension(self) -> None:
        with self.assertRaises(InputFormatError):
            load_events_bytes(b"timestamp,user\n2026-08-10T10:00:00Z,a", "events.txt")

    def test_rejects_missing_timestamp(self) -> None:
        with self.assertRaises(InputFormatError):
            normalise_row({"user": "user@example.org"}, 1)


if __name__ == "__main__":
    unittest.main()
