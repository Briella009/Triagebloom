from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from triagebloom.cli import main


ROOT = Path(__file__).resolve().parents[1]


class CliTests(unittest.TestCase):
    def test_analyze_writes_both_reports(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            rc = main(
                [
                    "analyze",
                    str(ROOT / "sample_data" / "combined_incident.json"),
                    "--output-dir",
                    str(output),
                    "--profile",
                    "balanced",
                    "--disable-off-hours",
                ]
            )
            self.assertEqual(rc, 0)
            self.assertTrue((output / "combined_incident-triagebloom.html").exists())
            self.assertTrue((output / "combined_incident-triagebloom.json").exists())

    def test_analyze_accepts_config_and_json_only(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            rc = main(
                [
                    "analyze",
                    str(ROOT / "sample_data" / "entra_signins.json"),
                    "--output-dir",
                    str(output),
                    "--format",
                    "json",
                    "--config",
                    str(ROOT / "config.example.json"),
                    "--spray-users",
                    "6",
                    "--mfa-failures",
                    "3",
                    "--correlation-window",
                    "45",
                    "--business-start",
                    "6",
                    "--business-end",
                    "22",
                    "--redact",
                ]
            )
            self.assertEqual(rc, 0)
            self.assertTrue((output / "entra_signins-triagebloom.json").exists())
            self.assertFalse((output / "entra_signins-triagebloom.html").exists())

    def test_missing_file_returns_error_code(self) -> None:
        rc = main(["analyze", "does-not-exist.json"])
        self.assertEqual(rc, 2)

    def test_invalid_threshold_returns_error_code(self) -> None:
        rc = main(
            [
                "analyze",
                str(ROOT / "sample_data" / "demo_events.json"),
                "--spray-users",
                "0",
            ]
        )
        self.assertEqual(rc, 2)


if __name__ == "__main__":
    unittest.main()
