from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
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


matrix = load_script("research_comiset_matrix")


class ResearchMatrixTests(unittest.TestCase):
    def make_dataset(self, root: Path) -> Path:
        path = root / "mini.jsonl"
        rows = [
            {
                "@timestamp": "2025-01-01T10:00:00Z",
                "CommandLine": "powershell.exe -EncodedCommand AAAA",
                "Process_name": "powershell.exe",
                "Process_guid": "event-malicious",
                "Host_name": "host01",
                "User_account": "user01",
                "Rule_technique_id": "T1059.001",
            },
            {
                "@timestamp": "2025-01-01T10:01:00Z",
                "CommandLine": "notepad.exe notes.txt",
                "Process_name": "notepad.exe",
                "Process_guid": "event-benign",
                "Host_name": "host01",
                "User_account": "user01",
                "Rule_technique_id": "",
            },
        ]
        path.write_text("\n".join(json.dumps(row) for row in rows) + "\n", encoding="utf-8")
        return path

    def test_lab_matrix_runs_all_profiles_in_one_dataset_pass(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = self.make_dataset(Path(directory))
            result = matrix.run_matrix(
                path,
                member=None,
                profiles=["learner", "balanced", "strict"],
                dataset_role="lab",
                batch_events=2,
                max_events=None,
                include_fingerprint=False,
            )
            self.assertEqual(result["events_processed"], 2)
            self.assertEqual(set(result["profiles"]), {"learner", "balanced", "strict"})
            for payload in result["profiles"].values():
                self.assertEqual(payload["supported_scope_binary"]["true_positives"], 1)
                self.assertEqual(payload["supported_scope_binary"]["false_positives"], 0)
                self.assertEqual(payload["supported_scope_technique_micro"]["true_positives"], 1)

    def test_real_environment_mode_omits_accuracy_claims(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = self.make_dataset(Path(directory))
            result = matrix.run_matrix(
                path,
                member=None,
                profiles=["balanced"],
                dataset_role="real",
                batch_events=2,
                max_events=None,
                include_fingerprint=False,
            )
            payload = result["profiles"]["balanced"]
            self.assertIn("findings_per_10000_events", payload)
            self.assertIn("interpretation", payload)
            self.assertNotIn("supported_scope_binary", payload)
            self.assertNotIn("per_technique", payload)

    def test_table_rows_keep_binary_and_exact_metrics_separate(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = self.make_dataset(Path(directory))
            result = matrix.run_matrix(
                path,
                member=None,
                profiles=["balanced"],
                dataset_role="lab",
                batch_events=2,
                max_events=None,
                include_fingerprint=False,
            )
            row = matrix.table_rows(result)[0]
            self.assertEqual(row["binary_f1"], 1.0)
            self.assertEqual(row["exact_micro_f1"], 1.0)
            self.assertEqual(row["findings"], 1)

    def test_invalid_profile_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = self.make_dataset(Path(directory))
            with self.assertRaises(ValueError):
                matrix.run_matrix(
                    path,
                    member=None,
                    profiles=["balanced", "unknown"],
                    dataset_role="lab",
                    batch_events=2,
                    max_events=None,
                    include_fingerprint=False,
                )


if __name__ == "__main__":
    unittest.main()
