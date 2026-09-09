from __future__ import annotations

import argparse
import json
import os
import secrets
import sys
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from .config import DetectionConfig, get_profile, load_config, validate_config
from .detections import run_detections
from .models import AnalysisResult
from .normalize import InputFormatError, load_events
from .report import write_html, write_json


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="triagebloom",
        description="Explainable, local-first triage for exported security logs.",
    )
    parser.add_argument("--version", action="version", version=f"TriageBloom {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    analyze = subparsers.add_parser("analyze", help="Analyze a CSV, JSON, JSONL, or NDJSON event export")
    analyze.add_argument("input", type=Path, help="Path to the event export")
    analyze.add_argument("--output-dir", type=Path, default=Path("reports"), help="Directory for generated reports")
    analyze.add_argument(
        "--format",
        choices=("html", "json", "both"),
        default="both",
        help="Report format (default: both)",
    )
    analyze.add_argument("--redact", action="store_true", help="Pseudonymise user, IP, and device identifiers in reports")
    analyze.add_argument(
        "--profile",
        choices=("learner", "balanced", "strict"),
        default="balanced",
        help="Rule-threshold profile (default: balanced)",
    )
    analyze.add_argument("--config", type=Path, help="Optional JSON file with thresholds, allow-lists, and suppressions")
    analyze.add_argument("--spray-users", type=int, default=None, help="Override unique users required for password spray")
    analyze.add_argument("--spray-window", type=int, default=None, help="Override password-spray window in minutes")
    analyze.add_argument("--bruteforce-failures", type=int, default=None, help="Override brute-force failure threshold")
    analyze.add_argument("--bruteforce-window", type=int, default=None, help="Override brute-force window in minutes")
    analyze.add_argument("--success-after-failures", type=int, default=None, help="Override failure-to-success threshold")
    analyze.add_argument("--success-window", type=int, default=None, help="Override failure-to-success window in minutes")
    analyze.add_argument("--mfa-failures", type=int, default=None, help="Override MFA-fatigue failure threshold")
    analyze.add_argument("--mfa-window", type=int, default=None, help="Override MFA-fatigue window in minutes")
    analyze.add_argument("--correlation-window", type=int, default=None, help="Override incident-correlation window in minutes")
    analyze.add_argument("--business-start", type=int, default=None, help="Override business-day start hour in UTC")
    analyze.add_argument("--business-end", type=int, default=None, help="Override business-day end hour in UTC")
    analyze.add_argument("--disable-off-hours", action="store_true", help="Disable low-severity off-hours sign-in findings")
    return parser


def _apply_cli_overrides(config: DetectionConfig, args: argparse.Namespace) -> DetectionConfig:
    mapping = {
        "spray_users": "spray_users",
        "spray_window": "spray_window_minutes",
        "bruteforce_failures": "brute_force_failures",
        "bruteforce_window": "brute_force_window_minutes",
        "success_after_failures": "success_after_failures",
        "success_window": "success_window_minutes",
        "mfa_failures": "mfa_failures",
        "mfa_window": "mfa_window_minutes",
        "correlation_window": "correlation_window_minutes",
        "business_start": "business_start_hour",
        "business_end": "business_end_hour",
    }
    for arg_name, field_name in mapping.items():
        value = getattr(args, arg_name)
        if value is not None:
            setattr(config, field_name, value)
    if args.disable_off_hours:
        config.enable_off_hours = False
    validate_config(config)
    return config


def _build_config(args: argparse.Namespace) -> DetectionConfig:
    config = get_profile(args.profile)
    if args.config:
        config = load_config(args.config, config)
    return _apply_cli_overrides(config, args)


def analyze(args: argparse.Namespace) -> int:
    config = _build_config(args)
    events = load_events(args.input)
    findings = run_detections(events, config)
    source_products = sorted({event.source_product for event in events})
    result = AnalysisResult(
        source_file=args.input.name,
        generated_at=datetime.now(tz=timezone.utc),
        events_processed=len(events),
        findings=findings,
        metadata={
            "triagebloom_version": __version__,
            "processing_mode": "local",
            "profile": args.profile,
            "source_products": source_products,
            "triggered_rules": sorted({finding.rule_id for finding in findings}),
            "configuration": config.public_dict(),
        },
    )

    args.output_dir.mkdir(parents=True, exist_ok=True)
    stem = args.input.stem
    salt = (os.getenv("TRIAGEBLOOM_REDACTION_SALT") or secrets.token_hex(16)) if args.redact else None
    outputs: list[Path] = []
    if args.format in {"html", "both"}:
        outputs.append(write_html(result, args.output_dir / f"{stem}-triagebloom.html", args.redact, salt))
    if args.format in {"json", "both"}:
        outputs.append(write_json(result, args.output_dir / f"{stem}-triagebloom.json", args.redact, salt))

    print(f"Processed {len(events)} events and generated {len(findings)} findings.")
    print(f"Source products: {', '.join(source_products)}")
    for output in outputs:
        print(f"Report: {output.resolve()}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "analyze":
            return analyze(args)
    except (FileNotFoundError, InputFormatError, ValueError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    parser.error("Unknown command")
    return 2
