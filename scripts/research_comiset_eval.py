from __future__ import annotations

import argparse
import bz2
import csv
import gzip
import json
import platform
import re
import sys
import time
from collections import Counter
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator, TextIO

from triagebloom.config import get_profile
from triagebloom.detections import run_detections
from triagebloom.normalize import InputFormatError, normalise_row


ATTACK_RE = re.compile(r"T\d{4}(?:\.\d{3})?", re.IGNORECASE)
SUPPORTED = {"T1059.001", "T1105", "T1197", "T1218.005", "T1218.010", "T1218.011"}
PROCESS_RULES = {"TB-PROC-001", "TB-PROC-002"}


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


def key(value: str) -> str:
    return re.sub(r"[^a-z0-9@]+", "", value.lower())


def flatten(record: dict[str, Any]) -> dict[str, Any]:
    merged = dict(record)
    for wrapper in ("_source", "fields"):
        value = record.get(wrapper)
        if isinstance(value, dict):
            for name, item in value.items():
                if isinstance(item, list) and len(item) == 1:
                    item = item[0]
                merged.setdefault(name, item)
    return merged


def get(record: dict[str, Any], *names: str) -> Any:
    indexed = {key(str(name)): value for name, value in record.items()}
    for name in names:
        value = indexed.get(key(name))
        if isinstance(value, list) and len(value) == 1:
            value = value[0]
        if value not in (None, "", [], {}):
            return value
    return None


def attack_ids(value: Any) -> set[str]:
    if value in (None, "", [], {}):
        return set()
    text = " ".join(map(str, value)) if isinstance(value, (list, tuple, set)) else str(value)
    return {match.upper() for match in ATTACK_RE.findall(text)}


def iter_json_array(handle: TextIO, chunk_size: int = 1_048_576) -> Iterator[dict[str, Any]]:
    decoder = json.JSONDecoder()
    buffer = ""
    pos = 0
    started = False
    closed = False
    eof = False
    while not closed:
        if not eof:
            chunk = handle.read(chunk_size)
            if chunk:
                buffer += chunk
            else:
                eof = True
        while True:
            while pos < len(buffer) and buffer[pos].isspace():
                pos += 1
            if not started:
                if pos >= len(buffer):
                    break
                if buffer[pos] != "[":
                    raise InputFormatError("Expected a top-level JSON array")
                started = True
                pos += 1
                continue
            while pos < len(buffer) and (buffer[pos].isspace() or buffer[pos] == ","):
                pos += 1
            if pos < len(buffer) and buffer[pos] == "]":
                closed = True
                break
            if pos >= len(buffer):
                break
            try:
                value, next_pos = decoder.raw_decode(buffer, pos)
            except json.JSONDecodeError:
                if eof:
                    raise InputFormatError("Incomplete or invalid JSON array")
                break
            if not isinstance(value, dict):
                raise InputFormatError("JSON array must contain objects")
            yield value
            pos = next_pos
        if pos > chunk_size:
            buffer = buffer[pos:]
            pos = 0
        if eof and not closed:
            if not started and not buffer.strip():
                return
            if pos >= len(buffer):
                raise InputFormatError("JSON array ended before closing bracket")
    if not started:
        raise InputFormatError("Empty JSON input")


def iter_rows(path: Path) -> Iterator[dict[str, Any]]:
    inner = path.with_suffix("").suffix.lower() if path.suffix.lower() in {".gz", ".bz2"} else path.suffix.lower()
    with open_text(path) as handle:
        if inner == ".csv":
            yield from csv.DictReader(handle)
            return
        if inner in {".jsonl", ".ndjson"}:
            for line_no, line in enumerate(handle, start=1):
                if not line.strip():
                    continue
                try:
                    value = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise InputFormatError(f"Invalid JSON on line {line_no}: {exc}") from exc
                if not isinstance(value, dict):
                    raise InputFormatError(f"JSON line {line_no} is not an object")
                yield value
            return
        if inner != ".json":
            raise InputFormatError("Input must be CSV, JSON, JSONL, or NDJSON, optionally .gz/.bz2")
        first = ""
        while True:
            char = handle.read(1)
            if not char:
                return
            if not char.isspace():
                first = char
                break
        handle.seek(0)
        if first == "[":
            yield from iter_json_array(handle)
        else:
            for line_no, line in enumerate(handle, start=1):
                if not line.strip():
                    continue
                try:
                    value = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise InputFormatError(f"Invalid JSON on line {line_no}: {exc}") from exc
                if not isinstance(value, dict):
                    raise InputFormatError(f"JSON line {line_no} is not an object")
                yield value


def to_record(raw: dict[str, Any], index: int) -> tuple[Any, set[str]]:
    source = flatten(raw)
    timestamp = get(source, "@timestamp", "Event_original_time", "Event_recorded_time", "timestamp")
    if timestamp is None:
        raise InputFormatError("COMISET record has no supported timestamp")
    techniques = attack_ids(get(source, "Rule_technique_id", "rule.technique.id", "technique_id"))
    event_id = get(source, "Process_guid", "EventRecordID", "event_id", "_id") or f"comiset-{index}"
    mapped = {
        "timestamp": timestamp,
        "event_id": str(event_id),
        "event_type": get(source, "Task", "Description", "EventID") or "comiset_event",
        "user": get(source, "User_account", "User", "user.name"),
        "device": get(source, "Host_name", "Computer", "host.name"),
        "command_line": get(source, "CommandLine", "ProcessCommandLine", "process.command_line"),
        "parent_process": get(source, "ParentCommandLine", "process_parent_name", "ParentImage"),
        "file_name": get(source, "Process_name", "OriginalFileName", "Image", "process.name"),
        "source_product": "comiset",
    }
    return normalise_row(mapped, index), techniques


def metrics(tp: int, fp: int, fn: int, tn: int) -> dict[str, Any]:
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


def evaluate_batch(records: list[tuple[Any, set[str]]], profile: str) -> tuple[Counter, dict[str, Counter], int]:
    config = get_profile(profile)
    config.enable_off_hours = False
    events = [event for event, _ in records]
    findings = [finding for finding in run_detections(events, config) if finding.rule_id in PROCESS_RULES]
    predicted: dict[str, set[str]] = {}
    for finding in findings:
        labels = attack_ids(finding.mitre_technique) & SUPPORTED
        for event_id in finding.evidence_event_ids:
            predicted.setdefault(event_id, set()).update(labels)

    overall: Counter = Counter()
    per_technique = {name: Counter() for name in sorted(SUPPORTED)}
    for event, labels in records:
        expected = labels & SUPPORTED
        observed = predicted.get(event.event_id, set()) & SUPPORTED
        overall["tp" if expected and observed else "fp" if observed else "fn" if expected else "tn"] += 1
        for technique, counts in per_technique.items():
            exp = technique in expected
            obs = technique in observed
            counts["tp" if exp and obs else "fp" if obs else "fn" if exp else "tn"] += 1
    return overall, per_technique, len(findings)


def summarize(path: Path, max_events: int | None) -> dict[str, Any]:
    total = labelled = 0
    counts: Counter[str] = Counter()
    for index, raw in enumerate(iter_rows(path), start=1):
        if max_events and index > max_events:
            break
        _, labels = to_record(raw, index)
        total += 1
        labelled += bool(labels)
        counts.update(labels)
    return {"events_scanned": total, "events_with_attack_reference": labelled, "technique_counts": dict(counts.most_common())}


def evaluate(path: Path, profile: str, batch_events: int, max_events: int | None) -> dict[str, Any]:
    overall: Counter = Counter()
    technique_counts = {name: Counter() for name in sorted(SUPPORTED)}
    batch: list[tuple[Any, set[str]]] = []
    total = finding_count = 0
    started = time.perf_counter()
    for index, raw in enumerate(iter_rows(path), start=1):
        if max_events and index > max_events:
            break
        batch.append(to_record(raw, index))
        if len(batch) < batch_events:
            continue
        block, by_technique, found = evaluate_batch(batch, profile)
        overall.update(block)
        for name, counts in by_technique.items():
            technique_counts[name].update(counts)
        total += len(batch)
        finding_count += found
        batch.clear()
    if batch:
        block, by_technique, found = evaluate_batch(batch, profile)
        overall.update(block)
        for name, counts in by_technique.items():
            technique_counts[name].update(counts)
        total += len(batch)
        finding_count += found
    elapsed = time.perf_counter() - started
    return {
        "evaluation_type": "COMISET reference-label evaluation",
        "dataset": str(path),
        "profile": profile,
        "events_processed": total,
        "process_finding_count": finding_count,
        "supported_techniques": sorted(SUPPORTED),
        "supported_scope": metrics(overall["tp"], overall["fp"], overall["fn"], overall["tn"]),
        "per_technique": {
            name: metrics(c["tp"], c["fp"], c["fn"], c["tn"])
            for name, c in technique_counts.items()
        },
        "runtime_seconds": round(elapsed, 6),
        "events_per_second": round(total / elapsed, 2) if elapsed else None,
        "environment": {"python": sys.version.split()[0], "platform": platform.platform()},
        "limitations": [
            "COMISET ATT&CK labels are reference labels created by its own event-labelling pipeline, not perfect forensic ground truth.",
            "Scoring is restricted to ATT&CK techniques overlapping TriageBloom's implemented process-rule scope.",
            "This adapter does not claim to validate TriageBloom's authentication-to-process correlation rule.",
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
    parser = argparse.ArgumentParser(description="Stream and evaluate COMISET data with TriageBloom")
    sub = parser.add_subparsers(dest="command", required=True)
    summary = sub.add_parser("summary")
    summary.add_argument("input", type=Path)
    summary.add_argument("--max-events", type=int)
    summary.add_argument("--output", type=Path)
    run = sub.add_parser("evaluate")
    run.add_argument("input", type=Path)
    run.add_argument("--profile", choices=("learner", "balanced", "strict"), default="balanced")
    run.add_argument("--batch-events", type=int, default=100_000)
    run.add_argument("--max-events", type=int)
    run.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    try:
        if args.command == "summary":
            write(summarize(args.input, args.max_events), args.output)
        else:
            if args.batch_events < 1:
                raise ValueError("--batch-events must be at least 1")
            write(evaluate(args.input, args.profile, args.batch_events, args.max_events), args.output)
        return 0
    except (FileNotFoundError, InputFormatError, ValueError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
