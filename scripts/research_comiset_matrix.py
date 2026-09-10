from __future__ import annotations

import argparse
import csv
import importlib.util
import json
import subprocess
import sys
import time
from collections import Counter
from pathlib import Path
from typing import Any

from triagebloom.config import get_profile


ROOT = Path(__file__).resolve().parents[1]


def _load_comiset_module():
    path = ROOT / "scripts" / "research_comiset_eval.py"
    spec = importlib.util.spec_from_file_location("triagebloom_research_comiset_eval", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("Could not load research_comiset_eval.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


comiset = _load_comiset_module()


def git_sha() -> str | None:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
        )
        return result.stdout.strip() or None
    except (OSError, subprocess.CalledProcessError):
        return None


def _new_profile_state() -> dict[str, Any]:
    return {
        "binary": Counter(),
        "exact_micro": Counter(),
        "per_technique": {name: Counter() for name in sorted(comiset.SUPPORTED)},
        "finding_count": 0,
        "detection_seconds": 0.0,
    }


def _merge_profile_batch(state: dict[str, Any], records: list[tuple[Any, set[str]]], profile: str) -> None:
    started = time.perf_counter()
    binary, exact, by_technique, findings = comiset.evaluate_batch(records, profile)
    state["detection_seconds"] += time.perf_counter() - started
    state["binary"].update(binary)
    state["exact_micro"].update(exact)
    for technique, counts in by_technique.items():
        state["per_technique"][technique].update(counts)
    state["finding_count"] += findings


def _metric_block(counts: Counter) -> dict[str, Any]:
    return comiset.metrics(counts["tp"], counts["fp"], counts["fn"], counts["tn"])


def _profile_result(
    name: str,
    state: dict[str, Any],
    events_processed: int,
    dataset_role: str,
) -> dict[str, Any]:
    config = get_profile(name)
    config.enable_off_hours = False
    result: dict[str, Any] = {
        "profile": name,
        "configuration": config.public_dict(),
        "process_finding_count": state["finding_count"],
        "findings_per_10000_events": round(state["finding_count"] * 10000 / events_processed, 6)
        if events_processed
        else 0.0,
        "detection_seconds": round(state["detection_seconds"], 6),
        "detection_events_per_second": round(events_processed / state["detection_seconds"], 2)
        if state["detection_seconds"]
        else None,
    }

    if dataset_role == "lab":
        result["supported_scope_binary"] = _metric_block(state["binary"])
        result["supported_scope_technique_micro"] = _metric_block(state["exact_micro"])
        result["per_technique"] = {
            technique: _metric_block(counts)
            for technique, counts in state["per_technique"].items()
        }
    else:
        result["interpretation"] = (
            "Real-environment rows are used for alert-density comparison only. Unlabelled rows are not treated as proven benign, "
            "so precision, recall and false-positive rate are intentionally omitted."
        )
    return result


def run_matrix(
    path: Path,
    member: str | None,
    profiles: list[str],
    dataset_role: str,
    batch_events: int,
    max_events: int | None,
    include_fingerprint: bool,
) -> dict[str, Any]:
    if not profiles:
        raise ValueError("At least one profile is required")
    invalid = [name for name in profiles if name not in {"learner", "balanced", "strict"}]
    if invalid:
        raise ValueError(f"Unknown profile(s): {', '.join(invalid)}")
    if batch_events < 1:
        raise ValueError("--batch-events must be at least 1")
    if max_events is not None and max_events < 1:
        raise ValueError("--max-events must be at least 1")

    states = {profile: _new_profile_state() for profile in profiles}
    total = 0
    batch: list[tuple[Any, set[str]]] = []
    started = time.perf_counter()

    for index, raw in enumerate(comiset.iter_rows(path, member), start=1):
        if max_events is not None and index > max_events:
            break
        batch.append(comiset.to_record(raw, index))
        if len(batch) < batch_events:
            continue
        for profile in profiles:
            _merge_profile_batch(states[profile], batch, profile)
        total += len(batch)
        batch.clear()

    if batch:
        for profile in profiles:
            _merge_profile_batch(states[profile], batch, profile)
        total += len(batch)

    elapsed = time.perf_counter() - started
    result: dict[str, Any] = {
        "study": "TriageBloom AISCN 2027 external evaluation",
        "evaluation": "COMISET profile sensitivity matrix",
        "dataset": str(path),
        "archive_member": member,
        "dataset_role": dataset_role,
        "events_processed": total,
        "supported_techniques": sorted(comiset.SUPPORTED),
        "profiles": {
            profile: _profile_result(profile, states[profile], total, dataset_role)
            for profile in profiles
        },
        "wall_clock_seconds": round(elapsed, 6),
        "git_commit": git_sha(),
        "limitations": [
            "COMISET ATT&CK annotations are reference labels, not perfect forensic ground truth.",
            "Lab metrics are restricted to TriageBloom's implemented process-technique overlap.",
            "Real-environment runs report alert density rather than treating every unlabelled event as a true negative.",
            "Profile comparisons use the same event stream and frozen code/configuration in one execution.",
        ],
    }
    if include_fingerprint:
        result["dataset_fingerprint"] = comiset.fingerprint(path)
    return result


def table_rows(result: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    role = result["dataset_role"]
    for profile, payload in result["profiles"].items():
        base = {
            "profile": profile,
            "events": result["events_processed"],
            "findings": payload["process_finding_count"],
            "findings_per_10000": payload["findings_per_10000_events"],
            "detection_seconds": payload["detection_seconds"],
            "detection_events_per_second": payload["detection_events_per_second"],
        }
        if role == "lab":
            binary = payload["supported_scope_binary"]
            exact = payload["supported_scope_technique_micro"]
            base.update(
                {
                    "binary_precision": binary["precision"],
                    "binary_recall": binary["recall"],
                    "binary_f1": binary["f1_score"],
                    "exact_micro_precision": exact["precision"],
                    "exact_micro_recall": exact["recall"],
                    "exact_micro_f1": exact["f1_score"],
                }
            )
        rows.append(base)
    return rows


def write_csv(rows: list[dict[str, Any]], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    fieldnames = list(rows[0])
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run learner/balanced/strict COMISET evaluation in one streaming pass"
    )
    parser.add_argument("input", type=Path)
    parser.add_argument("--member", help="Data-file member inside a ZIP archive")
    parser.add_argument(
        "--profiles",
        nargs="+",
        default=["learner", "balanced", "strict"],
        choices=("learner", "balanced", "strict"),
    )
    parser.add_argument("--dataset-role", choices=("lab", "real"), default="lab")
    parser.add_argument("--batch-events", type=int, default=100000)
    parser.add_argument("--max-events", type=int)
    parser.add_argument("--skip-fingerprint", action="store_true")
    parser.add_argument("--output", type=Path, default=Path("evaluation/external/comiset-profile-matrix.json"))
    parser.add_argument("--csv-output", type=Path, default=Path("evaluation/external/comiset-profile-matrix.csv"))
    args = parser.parse_args(argv)

    try:
        result = run_matrix(
            args.input,
            args.member,
            args.profiles,
            args.dataset_role,
            args.batch_events,
            args.max_events,
            not args.skip_fingerprint,
        )
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(result, indent=2, sort_keys=True), encoding="utf-8")
        write_csv(table_rows(result), args.csv_output)
        print(f"events={result['events_processed']}")
        print(f"json={args.output}")
        print(f"csv={args.csv_output}")
        for profile, payload in result["profiles"].items():
            print(
                f"{profile}: findings={payload['process_finding_count']} "
                f"per_10000={payload['findings_per_10000_events']}"
            )
        return 0
    except (FileNotFoundError, ValueError, comiset.InputFormatError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
