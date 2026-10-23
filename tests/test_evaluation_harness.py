from __future__ import annotations

import json
import runpy
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class SyntheticEvaluationHarnessTests(unittest.TestCase):
    def test_extended_labelled_cases_match_expected_rules(self) -> None:
        namespace = runpy.run_path(str(ROOT / "scripts" / "evaluate_labelled.py"))
        evaluate = namespace["evaluate"]
        data = json.loads(
            (ROOT / "evaluation" / "labelled_cases.json").read_text(encoding="utf-8")
        )

        result = evaluate(data)
        by_case = {item["case_id"]: item for item in result["cases"]}

        self.assertEqual(result["case_count"], 11)
        self.assertEqual(result["rule_count"], 8)
        self.assertEqual(result["false_positives"], 0)
        self.assertEqual(result["false_negatives"], 0)
        self.assertEqual(
            by_case["off-hours-positive"]["predicted"],
            ["TB-AUTH-004"],
        )
        self.assertEqual(
            by_case["business-hours-boundary-negative"]["predicted"],
            [],
        )
        self.assertEqual(
            by_case["benign-powershell-negative"]["predicted"],
            [],
        )


if __name__ == "__main__":
    unittest.main()
