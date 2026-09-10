from __future__ import annotations

import argparse
import ctypes
import importlib.util
import json
import os
import platform
import statistics
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from triagebloom.config import get_profile
from triagebloom.detections import run_detections


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = Path(__file__).resolve()


def _load_comiset_module():
    path = ROOT / "scripts" / "research_comiset_eval.py"
    spec = importlib.util.spec_from_file_location("triagebloom_research_comiset_eval_perf", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("Could not load research_comiset_eval.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


comiset = _load_comiset_module()


def git_sha() -> str | None:
    try:
        completed = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
        )
        return completed.stdout.strip() or None
    except (OSError, subprocess.CalledProcessError):
        return None


def peak_rss_bytes() -> int | None:
    """Return peak resident/working-set size for the current process."""

    if os.name == "nt":
        try:
            class PROCESS_MEMORY_COUNTERS(ctypes.Structure):
                _fields_ = [
                    ("cb", ctypes.c_ulong),
                    ("PageFaultCount", ctypes.c_ulong),
                    ("PeakWorkingSetSize", ctypes.c_size_t),
                    ("WorkingSetSize", ctypes.c_size_t),
                    ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                    ("PagefileUsage", ctypes.c_size_t),
                    ("PeakPagefileUsage", ctypes.c_size_t),
                ]

            counters = PROCESS_MEMORY_COUNTERS()
            counters.cb = ctypes.sizeof(counters)
            handle = ctypes.windll.kernel32.GetCurrentProcess()
            ok = ctypes.windll.psapi.GetProcessMemoryInfo(
                handle, ctypes.byref(counters), counters.cb
            )
            return int(counters.PeakWorkingSetSize) if ok else None
        except (AttributeError, OSError, ValueError):
            return None

    try:
        import resource

        value = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        if sys.platform == "darwin":
            return int(value)
        return int(value * 1024)
    except (ImportError, ValueError, OSError):
        return None


def environment_record() -> dict[str, Any]:
    return {
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "system": platform.system(),
        "release": platform.release(),
        "machine": platform.machine(),
        "processor": platform.processor() or None,
        "cpu_count_logical": os.cpu_count(),
    }


def run_worker(
    input_path: Path,
    member: str | None,
    events_requested: int,
    profile: str,
) -> dict[str, Any]:
    if events_requested < 1:
        raise ValueError("events_requested must be at least 1")

    config = get_profile(profile)
    started_total = time.perf_counter()
    started_ingest = started_total
    events = []
    for index, raw in enumerate(comiset.iter_rows(input_path, member), start=1):
        if index > events_requested:
            break
        event, _ = comiset.to_record(raw, index)
        events.append(event)
    ingest_seconds = time.perf_counter() - started_ingest

    if len(events) != events_requested:
        raise ValueError(
            f"Requested {events_requested} events but the selected data stream provided only {len(events)}"
        )

    started_detection = time.perf_counter()
    findings = run_detections(events, config)
    detection_seconds = time.perf_counter() - started_detection
    total_seconds = time.perf_counter() - started_total
    peak = peak_rss_bytes()

    return {
        "events": len(events),
        "profile": profile,
        "finding_count": len(findings),
        "ingest_seconds": round(ingest_seconds, 9),
        "detection_seconds": round(detection_seconds, 9),
        "total_seconds": round(total_seconds, 9),
        "detection_events_per_second": round(len(events) / detection_seconds, 3)
        if detection_seconds
        else None,
        "end_to_end_events_per_second": round(len(events) / total_seconds, 3)
        if total_seconds
        else None,
        "peak_rss_bytes": peak,
        "peak_rss_mib": round(peak / (1024 * 1024), 3) if peak is not None else None,
    }


def percentile(values: list[float], probability: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0]
    position = (len(ordered) - 1) * probability
    lower = int(position)
    upper = min(lower + 1, len(ordered) - 1)
    fraction = position - lower
    return ordered[lower] + (ordered[upper] - ordered[lower]) * fraction


def summarize_trials(trials: list[dict[str, Any]]) -> dict[str, Any]:
    if not trials:
        raise ValueError("At least one measured trial is required")

    def numbers(field: str) -> list[float]:
        return [float(item[field]) for item in trials if item.get(field) is not None]

    summary: dict[str, Any] = {
        "repetitions": len(trials),
        "events": trials[0]["events"],
        "finding_counts": sorted({int(item["finding_count"]) for item in trials}),
    }
    for field in (
        "ingest_seconds",
        "detection_seconds",
        "total_seconds",
        "detection_events_per_second",
        "end_to_end_events_per_second",
        "peak_rss_mib",
    ):
        values = numbers(field)
        if not values:
            summary[field] = None
            continue
        q1 = percentile(values, 0.25)
        q3 = percentile(values, 0.75)
        summary[field] = {
            "median": round(statistics.median(values), 6),
            "q1": round(q1, 6) if q1 is not None else None,
            "q3": round(q3, 6) if q3 is not None else None,
            "iqr": round(q3 - q1, 6) if q1 is not None and q3 is not None else None,
            "min": round(min(values), 6),
            "max": round(max(values), 6),
        }
    return summary


def worker_command(
    input_path: Path,
    member: str | None,
    events: int,
    profile: str,
) -> list[str]:
    command = [
        sys.executable,
        str(SCRIPT),
        "_worker",
        str(input_path.resolve()),
        "--events",
        str(events),
        "--profile",
        profile,
    ]
    if member:
        command.extend(["--member", member])
    return command


def invoke_worker(
    input_path: Path,
    member: str | None,
    events: int,
    profile: str,
) -> dict[str, Any]:
    completed = subprocess.run(
        worker_command(input_path, member, events, profile),
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        error = completed.stderr.strip() or completed.stdout.strip() or "worker failed"
        raise RuntimeError(error)
    try:
        payload = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError("Benchmark worker did not return valid JSON") from exc
    if not isinstance(payload, dict):
        raise RuntimeError("Benchmark worker returned an unexpected payload")
    return payload


def benchmark(
    input_path: Path,
    member: str | None,
    sizes: list[int],
    profile: str,
    warmups: int,
    repetitions: int,
) -> dict[str, Any]:
    if warmups < 0:
        raise ValueError("--warmups cannot be negative")
    if repetitions < 1:
        raise ValueError("--repetitions must be at least 1")
    if not sizes or any(size < 1 for size in sizes):
        raise ValueError("--sizes must contain positive event counts")
    if len(set(sizes)) != len(sizes):
        raise ValueError("--sizes must not contain duplicates")

    results: dict[str, Any] = {}
    for size in sizes:
        warmup_results = [
            invoke_worker(input_path, member, size, profile) for _ in range(warmups)
        ]
        measured = [
            invoke_worker(input_path, member, size, profile) for _ in range(repetitions)
        ]
        results[str(size)] = {
            "warmup_runs_excluded": len(warmup_results),
            "summary": summarize_trials(measured),
            "trials": measured,
        }

    return {
        "evaluation_type": "TriageBloom runtime and memory benchmark",
        "dataset": str(input_path),
        "archive_member": member,
        "profile": profile,
        "sizes": sizes,
        "warmups_per_size": warmups,
        "measured_repetitions_per_size": repetitions,
        "git_commit": git_sha(),
        "controller_environment": environment_record(),
        "results": results,
        "measurement_notes": [
            "Each measured repetition runs in a fresh child process so peak RSS is not contaminated by an earlier size.",
            "Peak RSS uses Windows PeakWorkingSetSize on Windows and getrusage(RUSAGE_SELF).ru_maxrss on Unix-like systems.",
            "Ingest time includes streaming, decompression where applicable, field adaptation and normalization for the requested prefix.",
            "Detection time covers TriageBloom rule execution over the already normalized in-memory event list.",
            "End-to-end time includes both ingest and detection but excludes child-process startup measured by the controller.",
            "Warm-up runs are executed but excluded from reported medians and IQRs.",
        ],
    }


def add_worker_parser(subparsers: Any) -> None:
    worker = subparsers.add_parser("_worker", help=argparse.SUPPRESS)
    worker.add_argument("input", type=Path)
    worker.add_argument("--member")
    worker.add_argument("--events", type=int, required=True)
    worker.add_argument("--profile", choices=("learner", "balanced", "strict"), default="balanced")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Benchmark TriageBloom on fixed event counts")
    subparsers = parser.add_subparsers(dest="command", required=True)
    run = subparsers.add_parser("benchmark")
    run.add_argument("input", type=Path)
    run.add_argument("--member")
    run.add_argument("--sizes", type=int, nargs="+", default=[10000, 100000, 1000000])
    run.add_argument("--profile", choices=("learner", "balanced", "strict"), default="balanced")
    run.add_argument("--warmups", type=int, default=1)
    run.add_argument("--repetitions", type=int, default=5)
    run.add_argument("--output", type=Path, default=Path("evaluation/external/performance-benchmark.json"))
    add_worker_parser(subparsers)
    args = parser.parse_args(argv)

    try:
        if args.command == "_worker":
            print(json.dumps(run_worker(args.input, args.member, args.events, args.profile)))
            return 0

        result = benchmark(
            args.input,
            args.member,
            args.sizes,
            args.profile,
            args.warmups,
            args.repetitions,
        )
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(result, indent=2, sort_keys=True), encoding="utf-8")
        print(f"result={args.output}")
        for size in args.sizes:
            summary = result["results"][str(size)]["summary"]
            detection = summary["detection_seconds"]
            throughput = summary["detection_events_per_second"]
            memory = summary["peak_rss_mib"]
            print(
                f"events={size} detection_median_s={detection['median']} "
                f"eps_median={throughput['median']} peak_rss_mib_median={memory['median'] if memory else 'n/a'}"
            )
        return 0
    except (FileNotFoundError, ValueError, RuntimeError, comiset.InputFormatError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
