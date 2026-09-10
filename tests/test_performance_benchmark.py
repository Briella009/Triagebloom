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


benchmark = load_script("research_performance_benchmark")


class PerformanceBenchmarkTests(unittest.TestCase):
    def make_dataset(self, root: Path, count: int = 8) -> Path:
        path = root / "mini.jsonl"
        rows = []
        for index in range(count):
            rows.append(
                {
                    "@timestamp": f"2026-01-01T10:00:{index:02d}Z",
                    "Process_guid": f"event-{index}",
                    "Process_name": "notepad.exe",
                    "CommandLine": "notepad.exe notes.txt",
                    "Host_name": "host01",
                    "User_account": "user01",
                    "Rule_technique_id": "",
                }
            )
        path.write_text("\n".join(json.dumps(row) for row in rows) + "\n", encoding="utf-8")
        return path

    def test_worker_reports_ingest_detection_and_memory_fields(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = self.make_dataset(Path(directory))
            result = benchmark.run_worker(path, None, 5, "balanced")
            self.assertEqual(result["events"], 5)
            self.assertEqual(result["profile"], "balanced")
            self.assertGreaterEqual(result["ingest_seconds"], 0)
            self.assertGreaterEqual(result["detection_seconds"], 0)
            self.assertGreaterEqual(result["total_seconds"], result["detection_seconds"])
            self.assertIn("peak_rss_bytes", result)

    def test_worker_rejects_short_stream(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = self.make_dataset(Path(directory), count=2)
            with self.assertRaises(ValueError):
                benchmark.run_worker(path, None, 3, "balanced")

    def test_summary_reports_median_and_iqr(self) -> None:
        trials = [
            {
                "events": 100,
                "finding_count": 2,
                "ingest_seconds": 1.0,
                "detection_seconds": 2.0,
                "total_seconds": 3.0,
                "detection_events_per_second": 50.0,
                "end_to_end_events_per_second": 33.333,
                "peak_rss_mib": 100.0,
            },
            {
                "events": 100,
                "finding_count": 2,
                "ingest_seconds": 2.0,
                "detection_seconds": 3.0,
                "total_seconds": 5.0,
                "detection_events_per_second": 33.333,
                "end_to_end_events_per_second": 20.0,
                "peak_rss_mib": 120.0,
            },
            {
                "events": 100,
                "finding_count": 2,
                "ingest_seconds": 3.0,
                "detection_seconds": 4.0,
                "total_seconds": 7.0,
                "detection_events_per_second": 25.0,
                "end_to_end_events_per_second": 14.286,
                "peak_rss_mib": 140.0,
            },
        ]
        result = benchmark.summarize_trials(trials)
        self.assertEqual(result["repetitions"], 3)
        self.assertEqual(result["detection_seconds"]["median"], 3.0)
        self.assertEqual(result["detection_seconds"]["q1"], 2.5)
        self.assertEqual(result["detection_seconds"]["q3"], 3.5)
        self.assertEqual(result["detection_seconds"]["iqr"], 1.0)
        self.assertEqual(result["finding_counts"], [2])

    def test_duplicate_sizes_are_rejected_before_workers_run(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = self.make_dataset(Path(directory))
            with self.assertRaises(ValueError):
                benchmark.benchmark(path, None, [4, 4], "balanced", 0, 1)


if __name__ == "__main__":
    unittest.main()
