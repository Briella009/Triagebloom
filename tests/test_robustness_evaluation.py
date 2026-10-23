from __future__ import annotations

import json
import re
import unittest
from pathlib import Path

from triagebloom.normalize import InputFormatError, load_events_bytes


ROOT = Path(__file__).resolve().parents[1]


class RobustnessEvaluationTests(unittest.TestCase):
    def test_declared_robustness_cases(self) -> None:
        data = json.loads(
            (ROOT / "evaluation" / "robustness_cases.json").read_text(encoding="utf-8")
        )

        for case in data["cases"]:
            with self.subTest(case_id=case["case_id"]):
                payload = case["payload"].encode("utf-8")
                if case["expected"] == "error":
                    with self.assertRaisesRegex(
                        InputFormatError, re.escape(case["error_contains"])
                    ):
                        load_events_bytes(payload, case["filename"])
                elif case["expected"] == "event_count":
                    events = load_events_bytes(payload, case["filename"])
                    self.assertEqual(len(events), case["event_count"])
                else:
                    self.fail(f"Unknown expectation {case['expected']!r}")


if __name__ == "__main__":
    unittest.main()
