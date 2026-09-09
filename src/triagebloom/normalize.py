from __future__ import annotations

import csv
import hashlib
import io
import json
from datetime import datetime, timezone
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
    "event_id": (
        "event_id",
        "eventid",
        "id",
        "recordid",
        "systemalertid",
        "alertid",
        "reportid",
    ),
    "event_type": (
        "event_type",
        "eventtype",
        "operationname",
        "activitydisplayname",
        "actiontype",
        "category",
        "type",
        "title",
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
        "remoteip",
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
    "parent_process": (
        "parent_process",
        "parentprocess",
        "parentprocessname",
        "initiatingprocessfilename",
        "initiatingprocesscommandline",
    ),
    "file_name": (
        "filename",
        "file_name",
        "processname",
        "imagefilename",
    ),
    "sha256": ("sha256", "filesha256", "processsha256"),
    "conditional_access_status": (
        "conditionalaccessstatus",
        "conditional_access_status",
    ),
    "risk_level": (
        "risklevelduringsignin",
        "risklevelaggregated",
        "risklevel",
        "risk_level",
    ),
    "risk_state": ("riskstate", "risk_state"),
    "authentication_requirement": (
        "authenticationrequirement",
        "authentication_requirement",
    ),
    "alert_severity": ("severity", "alertseverity", "alert_severity"),
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
        seconds = float(value)
        if seconds > 10_000_000_000:
            seconds /= 1000
        return datetime.fromtimestamp(seconds, tz=timezone.utc)

    text = str(value).strip()
    if text.isdigit():
        return _parse_timestamp(int(text))

    if text.endswith("Z"):
        text = f"{text[:-1]}+00:00"

    for candidate in (text, text.replace(" ", "T", 1)):
        try:
            parsed = datetime.fromisoformat(candidate)
            return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed.astimezone(timezone.utc)
        except ValueError:
            continue

    for pattern in ("%Y-%m-%d %H:%M:%S", "%Y/%m/%d %H:%M:%S", "%d/%m/%Y %H:%M:%S"):
        try:
            return datetime.strptime(text, pattern).replace(tzinfo=timezone.utc)
        except ValueError:
            continue

    raise InputFormatError(f"Unsupported timestamp format: {value!r}")


def _normalise_outcome(value: Any, event_type: str, raw_row: dict[str, Any]) -> str:
    text = str(value or "").strip().lower()
    event_text = event_type.lower()

    if text in {"0", "success", "succeeded", "successful", "allowed", "allow", "true", "ok"}:
        return "success"
    if text in {"failure", "failed", "denied", "deny", "blocked", "false", "error", "interrupted"}:
        return "failure"

    if text.isdigit():
        return "success" if int(text) == 0 else "failure"

    status = raw_row.get("status") or raw_row.get("Status")
    if isinstance(status, dict):
        error_code = status.get("errorCode")
        if error_code is not None:
            try:
                return "success" if int(error_code) == 0 else "failure"
            except (TypeError, ValueError):
                pass

    if any(token in event_text for token in ("failed", "failure", "denied", "blocked")):
        return "failure"
    if any(token in event_text for token in ("success", "succeeded", "allowed")):
        return "success"
    return "unknown"


def _infer_source_product(raw_row: dict[str, Any], row: dict[str, Any]) -> str:
    keys = set(row)
    if {
        _canonical_key("createdDateTime"),
        _canonical_key("userPrincipalName"),
    }.issubset(keys) and (
        _canonical_key("ipAddress") in keys
        or _canonical_key("resultType") in keys
        or _canonical_key("conditionalAccessStatus") in keys
        or _canonical_key("authenticationRequirement") in keys
        or _canonical_key("riskLevelDuringSignIn") in keys
    ):
        return "microsoft_entra"

    if _canonical_key("AlertId") in keys or (
        _canonical_key("Title") in keys and _canonical_key("Severity") in keys and _canonical_key("ServiceSource") in keys
    ):
        return "microsoft_defender_alert"

    if (
        _canonical_key("DeviceName") in keys
        and (
            _canonical_key("ProcessCommandLine") in keys
            or _canonical_key("InitiatingProcessFileName") in keys
            or _canonical_key("ActionType") in keys
        )
    ):
        return "microsoft_defender"

    explicit = raw_row.get("source_product") or raw_row.get("sourceProduct") or raw_row.get("product")
    return str(explicit).strip().lower().replace(" ", "_") if explicit else "generic"


def _authentication_method(raw_row: dict[str, Any]) -> str | None:
    details = raw_row.get("authenticationDetails") or raw_row.get("AuthenticationDetails")
    if isinstance(details, list):
        parts: list[str] = []
        for item in details:
            if not isinstance(item, dict):
                continue
            for key in (
                "authenticationMethod",
                "authenticationStepRequirement",
                "authenticationStepResultDetail",
            ):
                value = item.get(key)
                if value not in (None, ""):
                    parts.append(str(value))
        if parts:
            return " | ".join(dict.fromkeys(parts))

    for key in ("authenticationMethod", "AuthenticationMethod", "mfaDetail", "MfaDetail"):
        value = raw_row.get(key)
        if value not in (None, ""):
            return str(value)
    return None


def _device_from_nested(raw_row: dict[str, Any]) -> str | None:
    detail = raw_row.get("deviceDetail") or raw_row.get("DeviceDetail")
    if isinstance(detail, dict):
        for key in ("displayName", "deviceId", "operatingSystem"):
            value = detail.get(key)
            if value not in (None, ""):
                return str(value)
    return None


def _context(raw_row: dict[str, Any]) -> dict[str, Any]:
    context: dict[str, Any] = {}
    for source_key, destination_key in (
        ("appDisplayName", "app"),
        ("resourceDisplayName", "resource"),
        ("clientAppUsed", "client_app"),
        ("location", "location"),
        ("ServiceSource", "service_source"),
        ("DetectionSource", "detection_source"),
        ("Category", "alert_category"),
        ("FolderPath", "folder_path"),
        ("ProcessId", "process_id"),
        ("InitiatingProcessAccountName", "initiating_account"),
        ("InitiatingProcessCommandLine", "initiating_process_command_line"),
    ):
        value = raw_row.get(source_key)
        if value not in (None, "", [], {}):
            context[destination_key] = value
    return context


def _infer_category(
    event_type: str,
    command_line: str | None,
    user: str | None,
    outcome: str,
    source_product: str,
) -> str:
    lowered = event_type.lower()
    if source_product == "microsoft_defender_alert":
        return "alert"
    if command_line or any(token in lowered for token in ("process", "powershell", "command")):
        return "process"
    if user and (
        outcome != "unknown"
        or any(token in lowered for token in ("signin", "sign-in", "login", "auth", "mfa"))
        or source_product == "microsoft_entra"
    ):
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
    source_product = _infer_source_product(raw_row, row)
    outcome = _normalise_outcome(_first(row, "outcome"), event_type, raw_row)

    device_value = _first(row, "device")
    device = str(device_value) if device_value not in (None, "") else _device_from_nested(raw_row)

    def optional(field: str) -> str | None:
        value = _first(row, field)
        return str(value) if value not in (None, "") else None

    return NormalizedEvent(
        event_id=_derive_event_id(row, index),
        timestamp=_parse_timestamp(_first(row, "timestamp")),
        category=_infer_category(event_type, command_line, user, outcome, source_product),
        event_type=event_type,
        outcome=outcome,
        user=user,
        source_ip=optional("source_ip"),
        device=device,
        command_line=command_line,
        parent_process=optional("parent_process"),
        file_name=optional("file_name"),
        sha256=optional("sha256"),
        source_product=source_product,
        conditional_access_status=optional("conditional_access_status"),
        risk_level=optional("risk_level"),
        risk_state=optional("risk_state"),
        authentication_requirement=optional("authentication_requirement"),
        authentication_method=_authentication_method(raw_row),
        alert_severity=optional("alert_severity"),
        context=_context(raw_row),
        raw=raw_row,
    )


def normalise_rows(rows: Iterable[dict[str, Any]]) -> list[NormalizedEvent]:
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


def _read_json_text(text: str) -> list[dict[str, Any]]:
    text = text.lstrip("\ufeff").strip()
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


def _read_csv_text(text: str) -> list[dict[str, Any]]:
    handle = io.StringIO(text.lstrip("\ufeff"), newline="")
    reader = csv.DictReader(handle)
    if not reader.fieldnames:
        return []
    return [dict(row) for row in reader]


def _rows_from_text(text: str, suffix: str) -> list[dict[str, Any]]:
    suffix = suffix.lower()
    if suffix == ".csv":
        return _read_csv_text(text)
    if suffix in {".json", ".jsonl", ".ndjson"}:
        return _read_json_text(text)
    raise InputFormatError("Supported input formats are CSV, JSON, JSONL, and NDJSON")


def load_events_bytes(content: bytes, filename: str) -> list[NormalizedEvent]:
    """Load an uploaded security-event export without writing it to disk."""
    suffix = Path(filename).suffix.lower()
    try:
        text = content.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise InputFormatError("Input must be UTF-8 encoded text") from exc
    return normalise_rows(_rows_from_text(text, suffix))


def load_events(path: str | Path) -> list[NormalizedEvent]:
    input_path = Path(path)
    if not input_path.exists():
        raise FileNotFoundError(f"Input file not found: {input_path}")
    if not input_path.is_file():
        raise InputFormatError(f"Input path is not a file: {input_path}")

    try:
        text = input_path.read_text(encoding="utf-8-sig")
    except UnicodeDecodeError as exc:
        raise InputFormatError("Input must be UTF-8 encoded text") from exc
    return normalise_rows(_rows_from_text(text, input_path.suffix))


def iter_identifiers(events: Iterable[NormalizedEvent]) -> Iterable[str]:
    for event in events:
        for value in (event.user, event.source_ip, event.device):
            if value:
                yield value
