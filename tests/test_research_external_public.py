"""Secondary public-data smoke check of the existing PowerShell rule.

This test downloads a SHA256-pinned third-party *derived* CSV of four
independent Splunk Attack Data recordings. It is not a production accuracy
study; only Sysmon process creation rows in its PowerShell recording are
in scope. Labels are the dataset curator's, not independent forensic truth.
"""
import csv
import hashlib
import io
import json
import platform
import sys
import unittest
import urllib.error
import urllib.request

from triagebloom.config import DetectionConfig
from triagebloom.detections import run_detections
from triagebloom.normalize import normalise_rows

URL = "https://raw.githubusercontent.com/Sonnetica/windows-attack-telemetry/main/attack_scenario.csv"
EXPECTED_SHA256 = "721f40a12a486b08ca886471c6524cf535ca706d61d93d8ab26cf1e579d30646"


def as_engine_event(row, index):
    original = row["_time"].strip()
    # Dataset format example: 2021-01-19T13:21:58.635+0000
    if original.endswith("+0000"):
        original = original[:-5] + "+00:00"
    return {
        "timestamp": original,
        "event_id": "ext-" + str(index) + "-" + row.get("source_record_hash", "")[:9],
        "event_type": "ProcessCreated",
        "outcome": "Unknown",
        "user": row.get("user") or None,
        "device": row.get("host") or None,
        "command_line": row.get("command_line", ""),
        "parent_process": row.get("parent_image") or None,
        "file_name": row.get("image") or None,
    }


class PublicTelemetrySubset(unittest.TestCase):
    def test_power_shell_process_subset(self):
        try:
            with urllib.request.urlopen(URL, timeout=30) as response:
                payload = response.read()
        except (OSError, urllib.error.URLError) as exc:
            self.skipTest("Pinned public dataset unavailable: " + str(exc))
        digest = hashlib.sha256(payload).hexdigest()
        self.assertEqual(digest, EXPECTED_SHA256,
                         "External CSV differs from pinned version")
        data = list(csv.DictReader(io.StringIO(payload.decode("utf-8-sig"))))
        self.assertEqual(len(data), 1275)
        filtered = [
            (i, r) for i, r in enumerate(data)
            if r.get("technique_id") == "T1059.001"
            and r.get("event_id") == "1"
            and r.get("command_line", "").strip()
        ]
        self.assertGreater(len(filtered), 0)
        tp = fp = tn = fn = 0
        positive_samples = negative_samples = 0
        matched_examples = []
        for i, row in filtered:
            events = normalise_rows([as_engine_event(row, i)])
            findings = run_detections(
                events, DetectionConfig(enable_off_hours=False)
            )
            predicted = "TB-PROC-001" in {f.rule_id for f in findings}
            label = row.get("ground_truth", "").strip().lower()
            self.assertIn(label, ("true", "false"))
            truth = label == "true"
            positive_samples += int(truth)
            negative_samples += int(not truth)
            if truth and predicted: tp += 1
            elif not truth and predicted: fp += 1
            elif truth and not predicted: fn += 1
            else: tn += 1
            if predicted and len(matched_examples) < 4:
                matched_examples.append({
                    "trace_id": row.get("trace_id", ""),
                    "event_id": str(row.get("event_id", "")),
                    "curator_ground_truth": label,
                })
        result = {
            "study": "Public curated replay subset; not field accuracy",
            "dataset": "Sonnetica/windows-attack-telemetry (derived from Splunk Attack Data)",
            "csv_sha256": digest,
            "source_rows": len(data),
            "scope": "T1059.001 trace + Sysmon EventID 1 + non-empty command_line",
            "evaluated_rows": len(filtered),
            "curator_label_positive": positive_samples,
            "curator_label_negative": negative_samples,
            "TP": tp, "FP": fp, "TN": tn, "FN": fn,
            "rule": "TB-PROC-001",
            "python": sys.version.split()[0],
            "platform": platform.platform(),
            "limitations": [
                "Curator labels are not independently adjudicated maliciousness",
                "Attack-trace enrichment is not comparable with real-world benign base rates",
                "Dataset covers one technique and observable process rows only",
                "No threshold tuning or rule changes were made"
            ],
            "sampled_positive_findings": matched_examples,
        }
        print("EXTERNAL_SMOKE_JSON=" + json.dumps(result, separators=(",", ":")))


if __name__ == "__main__":
    unittest.main()
