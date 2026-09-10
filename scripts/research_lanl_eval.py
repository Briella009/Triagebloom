from __future__ import annotations

import argparse
import bz2
import csv
import gzip
import json
import sys
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterator, TextIO

from triagebloom.config import get_profile
from triagebloom.detections import run_detections
from triagebloom.normalize import InputFormatError, normalise_row


LANL_EPOCH = datetime(2015, 1, 1, tzinfo=timezone.utc)
AUTH_RULES = {"TB-AUTH-001", "TB-AUTH-002", "TB-AUTH-003", "TB-AUTH-005"}


@contextmanager
def open_text(path: Path) -> Iterator[TextIO]:
    if path.suffix.lower() == ".gz":
        handle = gzip.open(path, "rt", encoding="utf-8-sig", newline="")
    elif path.suffix.lower() == ".bz2":
        handle = bz2.open(path, "rt", encoding="utf-8-sig", newline="")
    else:
        handle = path.open("r", encoding="utf-8-sig", newline="")
    try:
        yield handle
    finally:
        handle.close()


def read_redteam(path: Path) -> set[tuple[int, str, str, str]]:
    result: set[tuple[int, str, str, str]] = set()
    with open_text(path) as handle:
        for line_no, row in enumerate(csv.reader(handle), start=1):
            if not row:
                continue
            if len(row) != 4:
                raise InputFormatError(f"LANL red-team row {line_no} must contain 4 columns")
            try:
                second = int(row[0])
            except ValueError as exc:
                raise InputFormatError(f"Invalid LANL red-team time on row {line_no}") from exc
            result.add((second, row[1], row[2], row[3]))
    return result


def merged_intervals(points: list[int], radius_seconds: int) -> list[tuple[int, int]]:
    spans = sorted((max(0, p - radius_seconds), p + radius_seconds) for p in points)
    result: list[tuple[int, int]] = []
    for start, end in spans:
        if not result or start > result[-1][1] + 1:
            result.append((start, end))
        else:
            result[-1] = (result[-1][0], max(result[-1][1], end))
    return result


def row_to_event(row: list[str], index: int) -> Any:
    if len(row) != 9:
        raise InputFormatError(f"LANL auth row {index} must contain 9 columns")
    try:
        seconds = int(row[0])
    except ValueError as exc:
        raise InputFormatError(f"Invalid LANL auth time on row {index}") from exc
    source_user, destination_user = row[1], row[2]
    user = destination_user if destination_user != "?" else source_user
    outcome = "success" if row[8].strip().lower() == "success" else "failure"
    return normalise_row(
        {
            "timestamp": (LANL_EPOCH + timedelta(seconds=seconds)).isoformat(),
            "event_id": f"lanl-auth-{index}",
            "event_type": f"{row[7]} {row[5]} authentication",
            "outcome": outcome,
            "user": user,
            "source_ip": row[3],
            "device": row[4],
            "source_product": "lanl_auth",
        },
        index,
    )


def is_redteam(row: list[str], redteam: set[tuple[int, str, str, str]]) -> bool:
    if len(row) != 9:
        return False
    seconds = int(row[0])
    return (
        (seconds, row[1], row[3], row[4]) in redteam
        or (seconds, row[2], row[3], row[4]) in redteam
    )


def extract_windows(auth: Path, redteam_path: Path, output: Path, radius_minutes: int) -> dict[str, Any]:
    redteam = read_redteam(redteam_path)
    intervals = merged_intervals([item[0] for item in redteam], radius_minutes * 60)
    interval_index = 0
    scanned = written = labelled = 0
    output.parent.mkdir(parents=True, exist_ok=True)

    with open_text(auth) as handle, output.open("w", encoding="utf-8") as target:
        for index, row in enumerate(csv.reader(handle), start=1):
            if not row:
                continue
            scanned += 1
            if len(row) != 9:
                raise InputFormatError(f"LANL auth row {index} must contain 9 columns")
            try:
                seconds = int(row[0])
            except ValueError as exc:
                raise InputFormatError(f"Invalid LANL auth time on row {index}") from exc

            while interval_index < len(intervals) and seconds > intervals[interval_index][1]:
                interval_index += 1
            if interval_index >= len(intervals):
                break
            if seconds < intervals[interval_index][0]:
                continue

            event = row_to_event(row, index)
            payload = event.to_dict()
            payload["reference_redteam"] = is_redteam(row, redteam)
            target.write(json.dumps(payload, sort_keys=True) + "\n")
            written += 1
            labelled += int(payload["reference_redteam"])

    return {
        "auth_source": str(auth),
        "redteam_source": str(redteam_path),
        "output": str(output),
        "radius_minutes": radius_minutes,
        "merged_intervals": len(intervals),
        "rows_scanned": scanned,
        "rows_written": written,
        "reference_redteam_rows_written": labelled,
    }


def read_extract(path: Path) -> list[tuple[Any, bool]]:
    result: list[tuple[Any, bool]] = []
    with path.open("r", encoding="utf-8-sig") as handle:
        for index, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            row = json.loads(line)
            reference = bool(row.pop("reference_redteam", False))
            result.append((normalise_row(row, index), reference))
    return result


def metrics(reference: set[str], predicted: set[str], universe: set[str]) -> dict[str, Any]:
    tp = len(reference & predicted)
    fp = len(predicted - reference)
    fn = len(reference - predicted)
    tn = len(universe - reference - predicted)
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {
        "true_positives": tp,
        "false_positives": fp,
        "false_negatives": fn,
        "true_negatives": tn,
        "precision": round(precision, 6),
        "recall": round(recall, 6),
        "f1_score": round(f1, 6),
        "false_positive_rate": round(fp / (fp + tn), 6) if fp + tn else 0.0,
    }


def evaluate(path: Path, profile: str) -> dict[str, Any]:
    records = read_extract(path)
    events = [event for event, _ in records]
    config = get_profile(profile)
    config.enable_off_hours = False
    findings = [finding for finding in run_detections(events, config) if finding.rule_id in AUTH_RULES]
    predicted: set[str] = set()
    for finding in findings:
        predicted.update(finding.evidence_event_ids)
    reference = {event.event_id for event, flagged in records if flagged}
    universe = {event.event_id for event, _ in records}
    return {
        "evaluation_type": "LANL red-team-window authentication sanity check",
        "dataset": str(path),
        "profile": profile,
        "events_processed": len(events),
        "reference_redteam_events": len(reference),
        "auth_finding_count": len(findings),
        "metrics": metrics(reference, predicted, universe),
        "limitations": [
            "LANL red-team events are successful stolen-credential authentications; TriageBloom does not claim to detect every stolen-credential login.",
            "The LANL source-computer identifier is placed in TriageBloom's generic source entity slot because the dataset does not provide source IP addresses.",
            "This is a secondary stress/sanity check, not a primary accuracy benchmark.",
            "The LANL process data uses de-identified process names, so it cannot directly validate TriageBloom's command-line or cross-authentication-to-suspicious-process logic.",
        ],
    }


def write(result: dict[str, Any], output: Path | None) -> None:
    text = json.dumps(result, indent=2, sort_keys=True)
    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(text, encoding="utf-8")
        print(f"result={output}")
    else:
        print(text)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Prepare and evaluate LANL authentication windows for TriageBloom research")
    sub = parser.add_subparsers(dest="command", required=True)
    extract = sub.add_parser("extract")
    extract.add_argument("auth", type=Path)
    extract.add_argument("redteam", type=Path)
    extract.add_argument("output", type=Path)
    extract.add_argument("--radius-minutes", type=int, default=30)
    extract.add_argument("--summary-output", type=Path)
    run = sub.add_parser("evaluate")
    run.add_argument("input", type=Path)
    run.add_argument("--profile", choices=("learner", "balanced", "strict"), default="balanced")
    run.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    try:
        if args.command == "extract":
            if args.radius_minutes < 1:
                raise ValueError("--radius-minutes must be at least 1")
            write(extract_windows(args.auth, args.redteam, args.output, args.radius_minutes), args.summary_output)
        else:
            write(evaluate(args.input, args.profile), args.output)
        return 0
    except (FileNotFoundError, InputFormatError, ValueError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
