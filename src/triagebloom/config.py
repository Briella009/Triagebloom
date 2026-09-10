from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field, replace
from pathlib import Path
from typing import Any


@dataclass(slots=True)
class DetectionConfig:
    spray_users: int = 5
    spray_window_minutes: int = 10
    brute_force_failures: int = 8
    brute_force_window_minutes: int = 10
    success_after_failures: int = 5
    success_window_minutes: int = 15
    mfa_failures: int = 4
    mfa_window_minutes: int = 15
    correlation_window_minutes: int = 30
    business_start_hour: int = 7
    business_end_hour: int = 20
    enable_off_hours: bool = True
    allow_users: set[str] = field(default_factory=set)
    allow_source_ips: set[str] = field(default_factory=set)
    allow_devices: set[str] = field(default_factory=set)
    suppressed_rule_ids: set[str] = field(default_factory=set)

    def public_dict(self) -> dict[str, Any]:
        data = asdict(self)
        for key in ("allow_users", "allow_source_ips", "allow_devices", "suppressed_rule_ids"):
            data[key] = sorted(data[key])
        return data


PROFILES: dict[str, DetectionConfig] = {
    "learner": DetectionConfig(
        spray_users=4,
        spray_window_minutes=15,
        brute_force_failures=6,
        brute_force_window_minutes=15,
        success_after_failures=4,
        success_window_minutes=20,
        mfa_failures=3,
        mfa_window_minutes=20,
        correlation_window_minutes=45,
        business_start_hour=7,
        business_end_hour=20,
        enable_off_hours=True,
    ),
    "balanced": DetectionConfig(),
    "strict": DetectionConfig(
        spray_users=8,
        spray_window_minutes=10,
        brute_force_failures=12,
        brute_force_window_minutes=10,
        success_after_failures=7,
        success_window_minutes=15,
        mfa_failures=5,
        mfa_window_minutes=15,
        correlation_window_minutes=20,
        business_start_hour=7,
        business_end_hour=20,
        enable_off_hours=False,
    ),
}


_MUTABLE_SET_FIELDS = (
    "allow_users",
    "allow_source_ips",
    "allow_devices",
    "suppressed_rule_ids",
)


def clone_config(config: DetectionConfig) -> DetectionConfig:
    """Return an independent config copy, including mutable set fields."""

    return replace(
        config,
        allow_users=set(config.allow_users),
        allow_source_ips=set(config.allow_source_ips),
        allow_devices=set(config.allow_devices),
        suppressed_rule_ids=set(config.suppressed_rule_ids),
    )


def get_profile(name: str) -> DetectionConfig:
    if name not in PROFILES:
        raise ValueError(f"Unknown profile {name!r}; choose from {', '.join(sorted(PROFILES))}")
    return clone_config(PROFILES[name])


def _as_set(value: Any, field_name: str) -> set[str]:
    if value is None:
        return set()
    if not isinstance(value, list):
        raise ValueError(f"{field_name} must be a JSON array")
    return {str(item) for item in value if str(item).strip()}


def load_config(path: str | Path, base: DetectionConfig | None = None) -> DetectionConfig:
    config = clone_config(base or DetectionConfig())
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("Configuration file must contain a JSON object")

    numeric_fields = (
        "spray_users",
        "spray_window_minutes",
        "brute_force_failures",
        "brute_force_window_minutes",
        "success_after_failures",
        "success_window_minutes",
        "mfa_failures",
        "mfa_window_minutes",
        "correlation_window_minutes",
        "business_start_hour",
        "business_end_hour",
    )
    for field_name in numeric_fields:
        if field_name in raw:
            try:
                setattr(config, field_name, int(raw[field_name]))
            except (TypeError, ValueError) as exc:
                raise ValueError(f"{field_name} must be an integer") from exc

    if "enable_off_hours" in raw:
        if not isinstance(raw["enable_off_hours"], bool):
            raise ValueError("enable_off_hours must be true or false")
        config.enable_off_hours = raw["enable_off_hours"]

    for field_name in _MUTABLE_SET_FIELDS:
        if field_name in raw:
            setattr(config, field_name, _as_set(raw[field_name], field_name))

    validate_config(config)
    return config


def validate_config(config: DetectionConfig) -> None:
    positive_fields = (
        "spray_users",
        "spray_window_minutes",
        "brute_force_failures",
        "brute_force_window_minutes",
        "success_after_failures",
        "success_window_minutes",
        "mfa_failures",
        "mfa_window_minutes",
        "correlation_window_minutes",
    )
    for field_name in positive_fields:
        if getattr(config, field_name) < 1:
            raise ValueError(f"{field_name} must be at least 1")

    if not 0 <= config.business_start_hour <= 23 or not 1 <= config.business_end_hour <= 24:
        raise ValueError("Business hours must be within 00:00-24:00 UTC")
    if config.business_start_hour >= config.business_end_hour:
        raise ValueError("business_start_hour must be earlier than business_end_hour")
