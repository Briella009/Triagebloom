from __future__ import annotations

import gzip
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


comiset = load_script("research_comiset_eval")
lanl = load_script("research_lanl_eval")


class ComisetResearchTests(unittest.TestCase):
    def test_attack_id_parser_supports_subtechniques(self) -> None:
        self.assertEqual(comiset.attack_ids("T1059.001 + t1218.011"), {"T1059.001", "T1218.011"})

    def test_adapter_preserves_reference_and_process_context(self) -> None:
        event, labels = comiset.to_record(
            {
                "@timestamp": "2022-11-18T10:20:30Z",
                "Task": "Process Create",
                "CommandLine": "powershell.exe -EncodedCommand AAAA",
                "ParentCommandLine": "cmd.exe /c launcher.cmd",
                "Process_name": "powershell.exe",
                "Process_guid": "{abc}",
                "Host_name": "computer01",
                "User_account": "user01",
                "Rule_technique_id": "T1059.001",
            },
            1,
        )
        self.assertEqual(labels, {"T1059.001"})
        self.assertEqual(event.category, "process")
        self.assertEqual(event.user, "user01")
        self.assertEqual(event.device, "computer01")
        self.assertIn("powershell", event.command_line.lower())

    def test_streams_json_array_and_gzip_jsonl(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            array_path = root / "records.json"
            array_path.write_text(json.dumps([{"a": 1}, {"a": 2}]), encoding="utf-8")
            self.assertEqual(list(comiset.iter_rows(array_path)), [{"a": 1}, {"a": 2}])

            line_path = root / "records.jsonl.gz"
            with gzip.open(line_path, "wt", encoding="utf-8") as handle:
                handle.write('{"a":3}\n{"a":4}\n')
            self.assertEqual(list(comiset.iter_rows(line_path)), [{"a": 3}, {"a": 4}])

    def test_supported_process_event_scores_as_true_positive(self) -> None:
        malicious = comiset.to_record(
            {
                "@timestamp": "2022-11-18T10:20:30Z",
                "CommandLine": "powershell.exe -enc AAAA",
                "Process_name": "powershell.exe",
                "Process_guid": "malicious-1",
                "Host_name": "computer01",
                "User_account": "user01",
                "Rule_technique_id": "T1059.001",
            },
            1,
        )
        benign = comiset.to_record(
            {
                "@timestamp": "2022-11-18T10:21:30Z",
                "CommandLine": "notepad.exe readme.txt",
                "Process_name": "notepad.exe",
                "Process_guid": "benign-1",
                "Host_name": "computer01",
                "User_account": "user01",
                "Rule_technique_id": "",
            },
            2,
        )
        overall, _, _ = comiset.evaluate_batch([malicious, benign], "balanced")
        self.assertEqual(overall["tp"], 1)
        self.assertEqual(overall["fp"], 0)
        self.assertEqual(overall["fn"], 0)
        self.assertEqual(overall["tn"], 1)


class LanlResearchTests(unittest.TestCase):
    def test_redteam_event_matches_authentication_row(self) -> None:
        redteam = {(151648, "U748@DOM1", "C17693", "C728")}
        row = [
            "151648",
            "U748@DOM1",
            "U748@DOM1",
            "C17693",
            "C728",
            "NTLM",
            "Network",
            "LogOn",
            "Success",
        ]
        self.assertTrue(lanl.is_redteam(row, redteam))
        event = lanl.row_to_event(row, 1)
        self.assertEqual(event.user, "U748@DOM1")
        self.assertEqual(event.outcome, "success")
        self.assertEqual(event.source_ip, "C17693")

    def test_interval_merging(self) -> None:
        self.assertEqual(lanl.merged_intervals([100, 130, 500], 60), [(40, 190), (440, 560)])

    def test_extract_keeps_only_redteam_windows(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            auth = root / "auth.txt"
            redteam = root / "redteam.txt"
            output = root / "windows.jsonl"
            auth.write_text(
                "1,U1@DOM1,U1@DOM1,C1,C2,NTLM,Network,LogOn,Success\n"
                "151648,U748@DOM1,U748@DOM1,C17693,C728,NTLM,Network,LogOn,Success\n"
                "400000,U2@DOM1,U2@DOM1,C3,C4,NTLM,Network,LogOn,Success\n",
                encoding="utf-8",
            )
            redteam.write_text("151648,U748@DOM1,C17693,C728\n", encoding="utf-8")
            result = lanl.extract_windows(auth, redteam, output, radius_minutes=1)
            self.assertEqual(result["rows_written"], 1)
            self.assertEqual(result["reference_redteam_rows_written"], 1)
            payload = json.loads(output.read_text(encoding="utf-8").strip())
            self.assertTrue(payload["reference_redteam"])


if __name__ == "__main__":
    unittest.main()
