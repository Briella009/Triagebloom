from __future__ import annotations

import argparse
import json
import tempfile
import time
from pathlib import Path

from generate_synthetic import build_dataset
from triagebloom.detections import DetectionConfig, run_detections
from triagebloom.normalize import load_events


def main() -> int:
    parser = argparse.ArgumentParser(description="Benchmark TriageBloom with deterministic synthetic events")
    parser.add_argument("--events", type=int, default=10_000, help="Total number of events")
    parser.add_argument("--repeat", type=int, default=3, help="Number of timed runs")
    parser.add_argument("--seed", type=int, default=42, help="Random seed")
    args = parser.parse_args()

    if args.repeat < 1:
        parser.error("--repeat must be at least 1")

    dataset = build_dataset(args.events, args.seed)
    timings: list[float] = []
    finding_count = 0

    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "events.json"
        path.write_text(json.dumps(dataset), encoding="utf-8")
        for _ in range(args.repeat):
            started = time.perf_counter()
            events = load_events(path)
            findings = run_detections(events, DetectionConfig(enable_off_hours=False))
            timings.append(time.perf_counter() - started)
            finding_count = len(findings)

    best = min(timings)
    median = sorted(timings)[len(timings) // 2]
    throughput = args.events / best if best else 0

    print(f"events={args.events}")
    print(f"repeat={args.repeat}")
    print(f"findings={finding_count}")
    print(f"best_seconds={best:.6f}")
    print(f"median_seconds={median:.6f}")
    print(f"best_events_per_second={throughput:.2f}")
    print("Note: publish the machine specification and exact commit with any benchmark result.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
