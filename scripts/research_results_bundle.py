from __future__ import annotations

import argparse
import json
import math
import sys
from pathlib import Path
from typing import Any


PROFILES = ("learner", "balanced", "strict")


def read_json(path: Path | None) -> dict[str, Any] | None:
    if path is None:
        return None
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"Expected JSON object in {path}")
    return payload


def fmt(value: Any, digits: int = 4) -> str:
    if value is None:
        return "NR"
    if isinstance(value, bool):
        return "yes" if value else "no"
    if isinstance(value, int):
        return f"{value:,}"
    if isinstance(value, float):
        if math.isnan(value) or math.isinf(value):
            return "NR"
        return f"{value:.{digits}f}"
    return str(value)


def markdown_table(headers: list[str], rows: list[list[Any]]) -> str:
    if not rows:
        return "_No result rows supplied._"
    lines = [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join(["---"] * len(headers)) + " |",
    ]
    for row in rows:
        lines.append("| " + " | ".join(fmt(value) for value in row) + " |")
    return "\n".join(lines)


def comiset_lab_section(data: dict[str, Any]) -> str:
    profiles = data.get("profiles", {})
    rows: list[list[Any]] = []
    for profile in PROFILES:
        payload = profiles.get(profile)
        if not isinstance(payload, dict):
            continue
        binary = payload.get("supported_scope_binary", {})
        exact = payload.get("supported_scope_technique_micro", {})
        rows.append(
            [
                profile,
                data.get("events_processed"),
                payload.get("process_finding_count"),
                payload.get("findings_per_10000_events"),
                binary.get("precision"),
                binary.get("recall"),
                binary.get("f1_score"),
                exact.get("precision"),
                exact.get("recall"),
                exact.get("f1_score"),
            ]
        )
    table = markdown_table(
        [
            "Profile",
            "Events",
            "Findings",
            "Findings/10k",
            "Binary P",
            "Binary R",
            "Binary F1",
            "Exact P",
            "Exact R",
            "Exact F1",
        ],
        rows,
    )

    technique_rows: list[list[Any]] = []
    supported = data.get("supported_techniques", [])
    for technique in supported:
        for profile in PROFILES:
            payload = profiles.get(profile)
            if not isinstance(payload, dict):
                continue
            metrics = payload.get("per_technique", {}).get(technique, {})
            technique_rows.append(
                [
                    technique,
                    profile,
                    metrics.get("true_positives"),
                    metrics.get("false_positives"),
                    metrics.get("false_negatives"),
                    metrics.get("precision"),
                    metrics.get("recall"),
                    metrics.get("f1_score"),
                ]
            )
    per_technique = markdown_table(
        ["Technique", "Profile", "TP", "FP", "FN", "Precision", "Recall", "F1"],
        technique_rows,
    )
    return (
        "## COMISET laboratory evaluation\n\n"
        + table
        + "\n\n### Per-technique results\n\n"
        + per_technique
        + "\n\n**Interpretation boundary:** binary supported-scope detection and exact ATT&CK-technique agreement are reported separately."
    )


def comiset_real_section(data: dict[str, Any]) -> str:
    profiles = data.get("profiles", {})
    rows: list[list[Any]] = []
    for profile in PROFILES:
        payload = profiles.get(profile)
        if not isinstance(payload, dict):
            continue
        rows.append(
            [
                profile,
                data.get("events_processed"),
                payload.get("process_finding_count"),
                payload.get("findings_per_10000_events"),
                payload.get("detection_events_per_second"),
            ]
        )
    return (
        "## COMISET real-environment behaviour\n\n"
        + markdown_table(
            ["Profile", "Events", "Findings", "Findings/10k", "Detection events/s"],
            rows,
        )
        + "\n\n**Interpretation boundary:** these rows characterize finding density. Unlabelled real-environment events are not automatically classified as proven false positives."
    )


def performance_section(data: dict[str, Any]) -> str:
    rows: list[list[Any]] = []
    for size in data.get("sizes", []):
        item = data.get("results", {}).get(str(size), {})
        summary = item.get("summary", {})
        def median(name: str) -> Any:
            value = summary.get(name)
            return value.get("median") if isinstance(value, dict) else None
        def iqr(name: str) -> Any:
            value = summary.get(name)
            return value.get("iqr") if isinstance(value, dict) else None
        rows.append(
            [
                size,
                summary.get("repetitions"),
                median("ingest_seconds"),
                iqr("ingest_seconds"),
                median("detection_seconds"),
                iqr("detection_seconds"),
                median("detection_events_per_second"),
                median("peak_rss_mib"),
            ]
        )
    return (
        "## Runtime and memory\n\n"
        + markdown_table(
            [
                "Events",
                "Runs",
                "Ingest median s",
                "Ingest IQR",
                "Detect median s",
                "Detect IQR",
                "Detect events/s",
                "Peak RSS MiB",
            ],
            rows,
        )
        + "\n\n**Interpretation boundary:** performance is a characterization of the documented test machine, not a production scalability guarantee."
    )


def correlation_section(data: dict[str, Any]) -> str:
    metrics = data.get("scenario_level_detection", {})
    summary_rows = [[
        data.get("scenario_count"),
        metrics.get("precision"),
        metrics.get("recall"),
        metrics.get("f1_score"),
        data.get("median_expected_event_coverage"),
        data.get("median_expected_stage_coverage"),
        data.get("median_top_risk_uplift"),
        data.get("median_correlation_rank"),
    ]]
    scenario_rows: list[list[Any]] = []
    for item in data.get("scenarios", []):
        scenario_rows.append(
            [
                item.get("scenario_id"),
                item.get("expected_correlation"),
                item.get("correlation_detected"),
                item.get("baseline_finding_count"),
                item.get("full_finding_count"),
                item.get("top_risk_uplift"),
                item.get("correlation_rank"),
                item.get("expected_event_coverage"),
                item.get("expected_stage_coverage"),
            ]
        )
    return (
        "## Sequence-correlation ablation\n\n"
        + markdown_table(
            ["Scenarios", "Precision", "Recall", "F1", "Event coverage", "Stage coverage", "Risk uplift", "Correlation rank"],
            summary_rows,
        )
        + "\n\n### Scenario detail\n\n"
        + markdown_table(
            ["Scenario", "Expected", "Detected", "Baseline findings", "Full findings", "Risk uplift", "Rank", "Event coverage", "Stage coverage"],
            scenario_rows,
        )
        + "\n\n**Interpretation boundary:** the current correlation rule adds an evidence-consolidating finding; it does not suppress component findings, so no alert-reduction claim is made."
    )


def lanl_section(data: dict[str, Any]) -> str:
    metrics = data.get("metrics", {})
    rows = [[
        data.get("profile"),
        data.get("events_processed"),
        data.get("reference_redteam_events"),
        data.get("auth_finding_count"),
        metrics.get("precision"),
        metrics.get("recall"),
        metrics.get("f1_score"),
    ]]
    return (
        "## LANL authentication sanity check\n\n"
        + markdown_table(
            ["Profile", "Events", "Red-team refs", "Auth findings", "Precision", "Recall", "F1"],
            rows,
        )
        + "\n\n**Interpretation boundary:** LANL is a secondary stress/sanity check for specific authentication sequences, not the primary accuracy benchmark."
    )


def readiness(comiset_lab: dict[str, Any] | None, performance: dict[str, Any] | None) -> list[str]:
    checks: list[str] = []
    if comiset_lab is None:
        checks.append("MISSING: COMISET laboratory profile matrix")
    else:
        if not comiset_lab.get("git_commit"):
            checks.append("MISSING: COMISET matrix git commit")
        fingerprint = comiset_lab.get("dataset_fingerprint")
        if not isinstance(fingerprint, dict) or not fingerprint.get("sha256"):
            checks.append("MISSING: COMISET dataset SHA-256 fingerprint")
        if not comiset_lab.get("events_processed"):
            checks.append("MISSING: COMISET processed event count")
    if performance is None:
        checks.append("MISSING: runtime/memory benchmark")
    elif not performance.get("git_commit"):
        checks.append("MISSING: performance benchmark git commit")
    return checks


def build_bundle(
    comiset_lab: dict[str, Any] | None,
    comiset_real: dict[str, Any] | None,
    performance: dict[str, Any] | None,
    correlation: dict[str, Any] | None,
    lanl: dict[str, Any] | None,
) -> str:
    sections = [
        "# TriageBloom AISCN 2027 — measured results bundle",
        "",
        "This file is generated from experiment JSON outputs. `NR` means not recorded. Values should be transferred into the manuscript only after the corresponding experiment is accepted as final under the frozen protocol.",
    ]
    missing = readiness(comiset_lab, performance)
    sections.extend(["", "## Manuscript-readiness checks", ""])
    if missing:
        sections.extend([f"- {item}" for item in missing])
    else:
        sections.append("- Core COMISET and performance provenance fields are present.")

    for data, builder in (
        (comiset_lab, comiset_lab_section),
        (comiset_real, comiset_real_section),
        (performance, performance_section),
        (correlation, correlation_section),
        (lanl, lanl_section),
    ):
        if data is not None:
            sections.extend(["", builder(data)])

    sections.extend(
        [
            "",
            "## Claim controls",
            "",
            "- Do not convert synthetic regression results into external-validation claims.",
            "- Do not describe COMISET reference labels as perfect forensic ground truth.",
            "- Do not call every unlabelled real-environment finding a false positive.",
            "- Do not claim alert-count reduction from TB-CORR-001; it currently adds a correlated finding.",
            "- Do not claim analyst productivity improvement without a separate human study.",
            "- Do not claim superiority to another platform or model without a fair direct comparison.",
        ]
    )
    return "\n".join(sections) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Compile TriageBloom research outputs into manuscript-ready Markdown tables")
    parser.add_argument("--comiset-lab", type=Path)
    parser.add_argument("--comiset-real", type=Path)
    parser.add_argument("--performance", type=Path)
    parser.add_argument("--correlation", type=Path)
    parser.add_argument("--lanl", type=Path)
    parser.add_argument("--output", type=Path, default=Path("evaluation/external/aiscn-results-bundle.md"))
    args = parser.parse_args(argv)

    try:
        bundle = build_bundle(
            read_json(args.comiset_lab),
            read_json(args.comiset_real),
            read_json(args.performance),
            read_json(args.correlation),
            read_json(args.lanl),
        )
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(bundle, encoding="utf-8")
        print(f"result={args.output}")
        return 0
    except (FileNotFoundError, ValueError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
