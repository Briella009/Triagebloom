from __future__ import annotations

import argparse
import bz2
import csv
import gzip
import hashlib
import io
import json
import platform
import re
import sys
import time
import zipfile
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
ELIGIBLE_SUFFIXES = {".csv", ".json", ".jsonl", ".ndjson"}
OFFICIAL_COMISET_MD5 = {
    "Comiset23_Lab_Environment_Dataset.zip": "e838308bfa31fba1e273d500d588aba6",
    "Comiset23_Real_Environment_Dataset.zip": "1718e161dc50b8c49e00020b596974d3",
}


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


def _eligible_zip_members(archive: zipfile.ZipFile) -> list[str]:
    members: list[str] = []
    for info in archive.infolist():
        if info.is_dir():
            continue
        if Path(info.filename).suffix.lower() in ELIGIBLE_SUFFIXES:
            members.append(info.filename)
    return sorted(members)


def select_zip_member(archive: zipfile.ZipFile, requested: str | None) -> str:
    eligible = _eligible_zip_members(archive)
    if requested:
        if requested not in archive.namelist():
            raise InputFormatError(f"ZIP member not found: {requested}")
        if Path(requested).suffix.lower() not in ELIGIBLE_SUFFIXES:
            raise InputFormatError("Selected ZIP member must be CSV, JSON, JSONL, or NDJSON")
        return requested
    if len(eligible) == 1:
        return eligible[0]
    if not eligible:
        raise InputFormatError("ZIP archive contains no CSV, JSON, JSONL, or NDJSON member")
    preview = ", ".join(eligible[:10])
    suffix = " ..." if len(eligible) > 10 else ""
    raise InputFormatError(
        f"ZIP archive contains {len(eligible)} candidate data files; choose one with --member. Candidates: {preview}{suffix}"
    )


@contextmanager
def open_text(path: Path, member: str | None = None) -> Iterator[tuple[TextIO, str]]:
    suffix = path.suffix.lower()
    if suffix == ".zip":
        archive = zipfile.ZipFile(path)
        raw = None
        handle = None
        try:
            chosen = select_zip_member(archive, member)
            raw = archive.open(chosen, "r")
            handle = io.TextIOWrapper(raw, encoding="utf-8-sig", newline="")
            yield handle, chosen
        finally:
            if handle is not None:
                handle.close()
            elif raw is not None:
                raw.close()
            archive.close()
        return

    if member:
        raise InputFormatError("--member is only valid when the input is a ZIP archive")
    if suffix == ".gz":
        handle = gzip.open(path, "rt", encoding="utf-8-sig", newline="")
        logical_name = path.with_suffix("").name
    elif suffix == ".bz2":
        handle = bz2.open(path, "rt", encoding="utf-8-sig", newline="")
        logical_name = path.with_suffix("").name
    else:
        handle = path.open("r", encoding="utf-8-sig", newline="")
        logical_name = path.name
    try:
        yield handle, logical_name
    finally:
        handle.close()


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


def iter_rows(path: Path, member: str | None = None) -> Iterator[dict[str, Any]]:
    with open_text(path, member) as (handle, logical_name):
        inner = Path(logical_name).suffix.lower()
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
            raise InputFormatError("Input must be CSV, JSON, JSONL, or NDJSON, optionally .gz/.bz2 or inside .zip")
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


def evaluate_batch(
    records: list[tuple[Any, set[str]]], profile: str
) -> tuple[Counter, Counter, dict[str, Counter], int]:
    config = get_profile(profile)
    config.enable_off_hours = False
    events = [event for event, _ in records]
    findings = [finding for finding in run_detections(events, config) if finding.rule_id in PROCESS_RULES]
    predicted: dict[str, set[str]] = {}
    for finding in findings:
        labels = attack_ids(finding.mitre_technique) & SUPPORTED
        for event_id in finding.evidence_event_ids:
            predicted.setdefault(event_id, set()).update(labels)

    binary: Counter = Counter()
    exact_micro: Counter = Counter()
    per_technique = {name: Counter() for name in sorted(SUPPORTED)}
    for event, labels in records:
        expected = labels & SUPPORTED
        observed = predicted.get(event.event_id, set()) & SUPPORTED
        binary["tp" if expected and observed else "fp" if observed else "fn" if expected else "tn"] += 1
        for technique, counts in per_technique.items():
            exp = technique in expected
            obs = technique in observed
            outcome = "tp" if exp and obs else "fp" if obs else "fn" if exp else "tn"
            counts[outcome] += 1
            exact_micro[outcome] += 1
    return binary, exact_micro, per_technique, len(findings)


def _field_presence(source: dict[str, Any]) -> dict[str, bool]:
    return {
        "timestamp": get(source, "@timestamp", "Event_original_time", "Event_recorded_time", "timestamp") is not None,
        "command_line": get(source, "CommandLine", "ProcessCommandLine", "process.command_line") is not None,
        "process_name": get(source, "Process_name", "OriginalFileName", "Image", "process.name") is not None,
        "parent_process": get(source, "ParentCommandLine", "process_parent_name", "ParentImage", "Process_parent_id", "Process_parent_guid") is not None,
        "user": get(source, "User_account", "User", "user.name") is not None,
        "host": get(source, "Host_name", "Computer", "host.name") is not None,
        "attack_reference": get(source, "Rule_technique_id", "rule.technique.id", "technique_id") is not None,
    }


def audit(path: Path, member: str | None, max_events: int | None) -> dict[str, Any]:
    total = parseable = labelled = supported_labelled = 0
    technique_counts: Counter[str] = Counter()
    supported_counts: Counter[str] = Counter()
    fields: Counter[str] = Counter()
    errors: Counter[str] = Counter()
    for index, raw in enumerate(iter_rows(path, member), start=1):
        if max_events and index > max_events:
            break
        total += 1
        source = flatten(raw)
        for name, present in _field_presence(source).items():
            if present:
                fields[name] += 1
        labels = attack_ids(get(source, "Rule_technique_id", "rule.technique.id", "technique_id"))
        if labels:
            labelled += 1
            technique_counts.update(labels)
        overlap = labels & SUPPORTED
        if overlap:
            supported_labelled += 1
            supported_counts.update(overlap)
        try:
            to_record(raw, index)
            parseable += 1
        except InputFormatError as exc:
            errors[str(exc)] += 1

    coverage = {
        name: {
            "rows_present": count,
            "coverage": round(count / total, 6) if total else 0.0,
        }
        for name, count in sorted(fields.items())
    }
    return {
        "audit_type": "COMISET schema and supported-scope audit",
        "dataset": str(path),
        "archive_member": member,
        "events_scanned": total,
        "parseable_events": parseable,
        "events_with_any_attack_reference": labelled,
        "events_with_supported_attack_reference": supported_labelled,
        "field_coverage": coverage,
        "supported_techniques": sorted(SUPPORTED),
        "supported_technique_counts": dict(supported_counts.most_common()),
        "top_reference_techniques": dict(technique_counts.most_common(30)),
        "parse_errors": dict(errors.most_common(10)),
        "note": "Audit results describe the scanned portion only when --max-events is used; they are not model-performance results.",
    }


def summarize(path: Path, member: str | None, max_events: int | None) -> dict[str, Any]:
    result = audit(path, member, max_events)
    return {
        "events_scanned": result["events_scanned"],
        "events_with_attack_reference": result["events_with_any_attack_reference"],
        "events_with_supported_attack_reference": result["events_with_supported_attack_reference"],
        "supported_technique_counts": result["supported_technique_counts"],
        "technique_counts": result["top_reference_techniques"],
    }


def evaluate(
    path: Path,
    member: str | None,
    profile: str,
    batch_events: int,
    max_events: int | None,
) -> dict[str, Any]:
    binary: Counter = Counter()
    exact_micro: Counter = Counter()
    technique_counts = {name: Counter() for name in sorted(SUPPORTED)}
    batch: list[tuple[Any, set[str]]] = []
    total = finding_count = 0
    started = time.perf_counter()
    for index, raw in enumerate(iter_rows(path, member), start=1):
        if max_events and index > max_events:
            break
        batch.append(to_record(raw, index))
        if len(batch) < batch_events:
            continue
        binary_block, exact_block, by_technique, found = evaluate_batch(batch, profile)
        binary.update(binary_block)
        exact_micro.update(exact_block)
        for name, counts in by_technique.items():
            technique_counts[name].update(counts)
        total += len(batch)
        finding_count += found
        batch.clear()
    if batch:
        binary_block, exact_block, by_technique, found = evaluate_batch(batch, profile)
        binary.update(binary_block)
        exact_micro.update(exact_block)
        for name, counts in by_technique.items():
            technique_counts[name].update(counts)
        total += len(batch)
        finding_count += found
    elapsed = time.perf_counter() - started
    return {
        "evaluation_type": "COMISET reference-label evaluation",
        "dataset": str(path),
        "archive_member": member,
        "profile": profile,
        "events_processed": total,
        "process_finding_count": finding_count,
        "findings_per_10000_events": round(finding_count * 10000 / total, 6) if total else 0.0,
        "supported_techniques": sorted(SUPPORTED),
        "supported_scope_binary": metrics(binary["tp"], binary["fp"], binary["fn"], binary["tn"]),
        "supported_scope_technique_micro": metrics(
            exact_micro["tp"], exact_micro["fp"], exact_micro["fn"], exact_micro["tn"]
        ),
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
            "Binary supported-scope metrics test whether any supported behaviour was surfaced; exact-technique micro and per-technique metrics test label agreement.",
            "This adapter does not claim to validate TriageBloom's authentication-to-process correlation rule.",
        ],
    }


def fingerprint(path: Path, expected_md5: str | None = None) -> dict[str, Any]:
    md5 = hashlib.md5(usedforsecurity=False)
    sha256 = hashlib.sha256()
    size = 0
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(8 * 1024 * 1024), b""):
            size += len(chunk)
            md5.update(chunk)
            sha256.update(chunk)
    observed_md5 = md5.hexdigest()
    official = OFFICIAL_COMISET_MD5.get(path.name)
    expected = (expected_md5 or official or "").lower() or None
    return {
        "file": str(path),
        "bytes": size,
        "md5": observed_md5,
        "sha256": sha256.hexdigest(),
        "expected_md5": expected,
        "md5_matches_expected": observed_md5 == expected if expected else None,
        "expected_md5_source": "COMISET Zenodo record 15375146" if official and not expected_md5 else "user-supplied" if expected_md5 else None,
    }


def write(result: dict[str, Any], output: Path | None) -> None:
    text = json.dumps(result, indent=2, sort_keys=True)
    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(text, encoding="utf-8")
        print(f"result={output}")
    else:
        print(text)


def add_input_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("input", type=Path)
    parser.add_argument("--member", help="Data-file member inside a ZIP archive; required if the archive has multiple candidates")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Stream and evaluate COMISET data with TriageBloom")
    sub = parser.add_subparsers(dest="command", required=True)

    summary = sub.add_parser("summary", help="Count ATT&CK reference labels in a dataset or archive")
    add_input_args(summary)
    summary.add_argument("--max-events", type=int)
    summary.add_argument("--output", type=Path)

    inspect = sub.add_parser("audit", help="Inspect schema coverage and TriageBloom-supported ATT&CK overlap before scoring")
    add_input_args(inspect)
    inspect.add_argument("--max-events", type=int, default=100000)
    inspect.add_argument("--output", type=Path)

    run = sub.add_parser("evaluate", help="Score the supported process-rule scope")
    add_input_args(run)
    run.add_argument("--profile", choices=("learner", "balanced", "strict"), default="balanced")
    run.add_argument("--batch-events", type=int, default=100_000)
    run.add_argument("--max-events", type=int)
    run.add_argument("--output", type=Path)

    verify = sub.add_parser("fingerprint", help="Stream the downloaded archive and record integrity hashes")
    verify.add_argument("input", type=Path)
    verify.add_argument("--expected-md5")
    verify.add_argument("--output", type=Path)

    args = parser.parse_args(argv)
    try:
        if args.command == "summary":
            write(summarize(args.input, args.member, args.max_events), args.output)
        elif args.command == "audit":
            if args.max_events is not None and args.max_events < 1:
                raise ValueError("--max-events must be at least 1")
            write(audit(args.input, args.member, args.max_events), args.output)
        elif args.command == "fingerprint":
            write(fingerprint(args.input, args.expected_md5), args.output)
        else:
            if args.batch_events < 1:
                raise ValueError("--batch-events must be at least 1")
            if args.max_events is not None and args.max_events < 1:
                raise ValueError("--max-events must be at least 1")
            write(evaluate(args.input, args.member, args.profile, args.batch_events, args.max_events), args.output)
        return 0
    except (FileNotFoundError, InputFormatError, ValueError, json.JSONDecodeError, zipfile.BadZipFile) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
