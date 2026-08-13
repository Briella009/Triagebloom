from __future__ import annotations

import argparse
import os
import secrets
import sys
from datetime import UTC, datetime
from pathlib import Path

from . import __version__
from .detections import DetectionConfig, run_detections
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
    analyze.add_argument("--spray-users", type=int, default=5, help="Unique users required for password-spray detection")
    analyze.add_argument("--spray-window", type=int, default=10, help="Password-spray time window in minutes")
    analyze.add_argument("--bruteforce-failures", type=int, default=8, help="Failures required for brute-force detection")
    analyze.add_argument("--bruteforce-window", type=int, default=10, help="Brute-force time window in minutes")
    analyze.add_argument("--success-after-failures", type=int, default=5, help="Failures before a success is escalated")
    analyze.add_argument("--success-window", type=int, default=15, help="Failure-to-success time window in minutes")
    analyze.add_argument("--business-start", type=int, default=7, help="Business-day start hour in UTC")
    analyze.add_argument("--business-end", type=int, default=20, help="Business-day end hour in UTC")
    analyze.add_argument("--disable-off-hours", action="store_true", help="Disable low-severity off-hours sign-in findings")
    return parser


def _validate_args(args: argparse.Namespace) -> None:
    positive_fields = (
        "spray_users",
        "spray_window",
        "bruteforce_failures",
        "bruteforce_window",
        "success_after_failures",
        "success_window",
    )
    for field in positive_fields:
        if getattr(args, field) < 1:
            raise ValueError(f"--{field.replace('_', '-')} must be at least 1")
    if not 0 <= args.business_start <= 23 or not 1 <= args.business_end <= 24:
        raise ValueError("Business hours must be within 00:00-24:00 UTC")
    if args.business_start >= args.business_end:
        raise ValueError("--business-start must be earlier than --business-end")


def analyze(args: argparse.Namespace) -> int:
    _validate_args(args)
    events = load_events(args.input)
    config = DetectionConfig(
        spray_users=args.spray_users,
        spray_window_minutes=args.spray_window,
        brute_force_failures=args.bruteforce_failures,
        brute_force_window_minutes=args.bruteforce_window,
        success_after_failures=args.success_after_failures,
        success_window_minutes=args.success_window,
        business_start_hour=args.business_start,
        business_end_hour=args.business_end,
        enable_off_hours=not args.disable_off_hours,
    )
    findings = run_detections(events, config)
    result = AnalysisResult(
        source_file=args.input.name,
        generated_at=datetime.now(tz=UTC),
        events_processed=len(events),
        findings=findings,
        metadata={
            "triagebloom_version": __version__,
            "processing_mode": "local",
            "triggered_rules": sorted({finding.rule_id for finding in findings}),
            "configuration": {
                "spray_users": config.spray_users,
                "spray_window_minutes": config.spray_window_minutes,
                "brute_force_failures": config.brute_force_failures,
                "brute_force_window_minutes": config.brute_force_window_minutes,
                "success_after_failures": config.success_after_failures,
                "success_window_minutes": config.success_window_minutes,
                "business_start_hour_utc": config.business_start_hour,
                "business_end_hour_utc": config.business_end_hour,
                "off_hours_enabled": config.enable_off_hours,
            },
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
    for output in outputs:
        print(f"Report: {output.resolve()}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "analyze":
            return analyze(args)
    except (FileNotFoundError, InputFormatError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    parser.error("Unknown command")
    return 2
