from __future__ import annotations

import csv
import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Iterable

from .models import NormalizedEvent


ALIASES: dict[str, tuple[str, ...]] = {
    "timestamp": (
        "timestamp",
        "timegenerated",
        "createddatetime",
        "event_time",
        "eventtime",
        "datetime",
        "time",
        "@timestamp",
    ),
    "event_id": ("event_id", "eventid", "id", "recordid", "systemalertid"),
    "event_type": (
        "event_type",
        "eventtype",
        "operationname",
        "activitydisplayname",
        "actiontype",
        "category",
        "type",
    ),
    "outcome": (
        "outcome",
        "result",
        "status",
        "resulttype",
        "action",
        "resultstatus",
    ),
    "user": (
        "user",
        "username",
        "userprincipalname",
        "account",
        "accountname",
        "targetuser",
        "identity",
        "initiatedby",
    ),
    "source_ip": (
        "source_ip",
        "sourceip",
        "src_ip",
        "srcip",
        "ip",
        "ipaddress",
        "clientip",
        "calleripaddress",
    ),
    "device": (
        "device",
        "devicename",
        "hostname",
        "computer",
        "host",
        "machinename",
    ),
    "command_line": (
        "command_line",
        "commandline",
        "processcommandline",
        "cmdline",
        "process_command_line",
    ),
}


class InputFormatError(ValueError):
    pass


def _canonical_key(value: str) -> str:
    return value.strip().lower().replace(" ", "").replace("-", "").replace("_", "")


def _normalise_keys(row: dict[str, Any]) -> dict[str, Any]:
    return {_canonical_key(str(key)): value for key, value in row.items()}


def _first(row: dict[str, Any], field: str) -> Any:
    for alias in ALIASES[field]:
        value = row.get(_canonical_key(alias))
        if value not in (None, ""):
            return value
    return None


def _parse_timestamp(value: Any) -> datetime:
    if value in (None, ""):
        raise InputFormatError("A timestamp field is required for every event")

    if isinstance(value, (int, float)):
        # Support epoch seconds and epoch milliseconds.
        seconds = float(value)
        if seconds > 10_000_000_000:
            seconds /= 1000
        return datetime.fromtimestamp(seconds, tz=UTC)

    text = str(value).strip()
    if text.isdigit():
        return _parse_timestamp(int(text))

    if text.endswith("Z"):
        text = f"{text[:-1]}+00:00"

    candidates = (
        text,
        text.replace(" ", "T", 1),
    )
    for candidate in candidates:
        try:
            parsed = datetime.fromisoformat(candidate)
            return parsed.replace(tzinfo=UTC) if parsed.tzinfo is None else parsed.astimezone(UTC)
        except ValueError:
            continue

    for pattern in ("%Y-%m-%d %H:%M:%S", "%Y/%m/%d %H:%M:%S", "%d/%m/%Y %H:%M:%S"):
        try:
            return datetime.strptime(text, pattern).replace(tzinfo=UTC)
        except ValueError:
            continue

    raise InputFormatError(f"Unsupported timestamp format: {value!r}")


def _normalise_outcome(value: Any, event_type: str) -> str:
    text = str(value or "").strip().lower()
    event_text = event_type.lower()

    if text in {"0", "success", "succeeded", "successful", "allowed", "allow", "true", "ok"}:
        return "success"
    if text in {"failure", "failed", "denied", "deny", "blocked", "false", "error"}:
        return "failure"

    # Microsoft Entra ID resultType uses 0 for success and non-zero codes for failure.
    if text.isdigit():
        return "success" if int(text) == 0 else "failure"

    if any(token in event_text for token in ("failed", "failure", "denied", "blocked")):
        return "failure"
    if any(token in event_text for token in ("success", "succeeded", "allowed", "login")):
        return "success"
    return "unknown"


def _infer_category(event_type: str, command_line: str | None, user: str | None, outcome: str) -> str:
    lowered = event_type.lower()
    if command_line or any(token in lowered for token in ("process", "powershell", "command")):
        return "process"
    if user and (outcome != "unknown" or any(token in lowered for token in ("signin", "login", "auth", "mfa"))):
        return "authentication"
    return "unknown"


def _derive_event_id(row: dict[str, Any], index: int) -> str:
    supplied = _first(row, "event_id")
    if supplied not in (None, ""):
        return str(supplied)
    stable = json.dumps(row, sort_keys=True, default=str).encode("utf-8")
    digest = hashlib.sha256(stable).hexdigest()[:10]
    return f"evt-{index:05d}-{digest}"


def normalise_row(raw_row: dict[str, Any], index: int) -> NormalizedEvent:
    row = _normalise_keys(raw_row)
    event_type = str(_first(row, "event_type") or "unknown")
    command_line_value = _first(row, "command_line")
    command_line = str(command_line_value) if command_line_value not in (None, "") else None
    user_value = _first(row, "user")
    user = str(user_value) if user_value not in (None, "") else None
    outcome = _normalise_outcome(_first(row, "outcome"), event_type)

    return NormalizedEvent(
        event_id=_derive_event_id(row, index),
        timestamp=_parse_timestamp(_first(row, "timestamp")),
        category=_infer_category(event_type, command_line, user, outcome),
        event_type=event_type,
        outcome=outcome,
        user=user,
        source_ip=str(_first(row, "source_ip")) if _first(row, "source_ip") not in (None, "") else None,
        device=str(_first(row, "device")) if _first(row, "device") not in (None, "") else None,
        command_line=command_line,
        raw=raw_row,
    )


def _read_json(path: Path) -> list[dict[str, Any]]:
    text = path.read_text(encoding="utf-8-sig").strip()
    if not text:
        return []

    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        rows: list[dict[str, Any]] = []
        for line_number, line in enumerate(text.splitlines(), start=1):
            if not line.strip():
                continue
            try:
                value = json.loads(line)
            except json.JSONDecodeError as exc:
                raise InputFormatError(f"Invalid JSON on line {line_number}: {exc}") from exc
            if not isinstance(value, dict):
                raise InputFormatError("JSON Lines input must contain one object per line")
            rows.append(value)
        return rows

    if isinstance(parsed, list) and all(isinstance(item, dict) for item in parsed):
        return parsed
    if isinstance(parsed, dict):
        for key in ("events", "records", "value", "data"):
            value = parsed.get(key)
            if isinstance(value, list) and all(isinstance(item, dict) for item in value):
                return value
        return [parsed]
    raise InputFormatError("JSON input must be an object, an array of objects, or JSON Lines")


def _read_csv(path: Path) -> list[dict[str, Any]]:
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        return [dict(row) for row in csv.DictReader(handle)]


def load_events(path: str | Path) -> list[NormalizedEvent]:
    input_path = Path(path)
    if not input_path.exists():
        raise FileNotFoundError(f"Input file not found: {input_path}")
    if not input_path.is_file():
        raise InputFormatError(f"Input path is not a file: {input_path}")

    suffix = input_path.suffix.lower()
    if suffix == ".csv":
        rows = _read_csv(input_path)
    elif suffix in {".json", ".jsonl", ".ndjson"}:
        rows = _read_json(input_path)
    else:
        raise InputFormatError("Supported input formats are CSV, JSON, JSONL, and NDJSON")

    events: list[NormalizedEvent] = []
    errors: list[str] = []
    for index, row in enumerate(rows, start=1):
        try:
            events.append(normalise_row(row, index))
        except InputFormatError as exc:
            errors.append(f"row {index}: {exc}")

    if errors:
        preview = "; ".join(errors[:5])
        remaining = len(errors) - 5
        if remaining > 0:
            preview += f"; and {remaining} more"
        raise InputFormatError(f"Could not normalise input: {preview}")

    return sorted(events, key=lambda event: event.timestamp)


def iter_identifiers(events: Iterable[NormalizedEvent]) -> Iterable[str]:
    for event in events:
        for value in (event.user, event.source_ip, event.device):
            if value:
                yield value
