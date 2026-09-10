from __future__ import annotations

import argparse
import html
import json
import math
import sys
from pathlib import Path
from typing import Any


WIDTH = 960
HEIGHT = 540
MARGIN = 70
PROFILES = ("learner", "balanced", "strict")


def esc(value: Any) -> str:
    return html.escape(str(value), quote=True)


def svg_document(body: str, width: int = WIDTH, height: int = HEIGHT) -> str:
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
        f'viewBox="0 0 {width} {height}" role="img">\n'
        '<style>text{font-family:Arial,Helvetica,sans-serif;fill:#111} .title{font-size:24px;font-weight:700} '
        '.label{font-size:16px} .small{font-size:13px} .box{fill:#fff;stroke:#111;stroke-width:2} '
        '.axis{stroke:#111;stroke-width:1.5} .grid{stroke:#bbb;stroke-width:1;stroke-dasharray:4 4} '
        '.bar{fill:#ddd;stroke:#111;stroke-width:1.2} .line{fill:none;stroke:#111;stroke-width:2.5} '
        '.point{fill:#fff;stroke:#111;stroke-width:2}</style>\n'
        f'{body}\n</svg>\n'
    )


def write_svg(path: Path, body: str, width: int = WIDTH, height: int = HEIGHT) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(svg_document(body, width, height), encoding="utf-8")


def architecture_svg(path: Path) -> None:
    labels = [
        ("Raw security exports", "CSV / JSON / JSONL"),
        ("Vendor-neutral normalisation", "Identity + endpoint context"),
        ("Deterministic detections", "Explicit thresholds and rules"),
        ("Sequence correlation", "TB-CORR-001"),
        ("Prioritised finding", "Evidence + ATT&CK + next steps"),
    ]
    x0, y, w, h, gap = 35, 210, 158, 105, 27
    parts = ['<text x="480" y="55" text-anchor="middle" class="title">TriageBloom research architecture</text>']
    for index, (title, subtitle) in enumerate(labels):
        x = x0 + index * (w + gap)
        parts.append(f'<rect class="box" x="{x}" y="{y}" width="{w}" height="{h}" rx="10"/>')
        parts.append(f'<text x="{x + w/2}" y="{y + 40}" text-anchor="middle" class="label">{esc(title)}</text>')
        parts.append(f'<text x="{x + w/2}" y="{y + 68}" text-anchor="middle" class="small">{esc(subtitle)}</text>')
        if index < len(labels) - 1:
            x1 = x + w + 5
            x2 = x + w + gap - 5
            mid = y + h / 2
            parts.append(f'<line class="axis" x1="{x1}" y1="{mid}" x2="{x2}" y2="{mid}"/>')
            parts.append(f'<polygon points="{x2},{mid} {x2-9},{mid-5} {x2-9},{mid+5}"/>')
    parts.append('<text x="480" y="390" text-anchor="middle" class="small">Core analysis is deterministic; the current research evaluation does not require model training or an external inference API.</text>')
    write_svg(path, "\n".join(parts))


def sequence_svg(path: Path) -> None:
    labels = [
        ("Repeated failures", "same user"),
        ("Successful sign-in", "within auth window"),
        ("Suspicious process", "after success"),
        ("TB-CORR-001", "correlated finding"),
    ]
    x0, y, w, h, gap = 85, 205, 165, 100, 45
    parts = ['<text x="480" y="55" text-anchor="middle" class="title">TriageBloom correlation sequence</text>']
    for index, (title, subtitle) in enumerate(labels):
        x = x0 + index * (w + gap)
        parts.append(f'<rect class="box" x="{x}" y="{y}" width="{w}" height="{h}" rx="10"/>')
        parts.append(f'<text x="{x + w/2}" y="{y + 40}" text-anchor="middle" class="label">{esc(title)}</text>')
        parts.append(f'<text x="{x + w/2}" y="{y + 68}" text-anchor="middle" class="small">{esc(subtitle)}</text>')
        if index < len(labels) - 1:
            x1 = x + w + 5
            x2 = x + w + gap - 5
            mid = y + h / 2
            parts.append(f'<line class="axis" x1="{x1}" y1="{mid}" x2="{x2}" y2="{mid}"/>')
            parts.append(f'<polygon points="{x2},{mid} {x2-9},{mid-5} {x2-9},{mid+5}"/>')
    parts.append('<text x="480" y="380" text-anchor="middle" class="small">Identity, timing and compatible device context are required when the relevant fields are available.</text>')
    parts.append('<text x="480" y="410" text-anchor="middle" class="small">The correlated finding is additive; component findings are not suppressed.</text>')
    write_svg(path, "\n".join(parts))


def read_json(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"Expected a JSON object in {path}")
    return payload


def _metric(profile: dict[str, Any], key: str) -> float | None:
    metrics = profile.get("supported_scope_binary", {})
    value = metrics.get(key) if isinstance(metrics, dict) else None
    if isinstance(value, (int, float)) and math.isfinite(float(value)):
        return float(value)
    return None


def profile_svg(data: dict[str, Any], path: Path) -> None:
    profiles = data.get("profiles", {})
    if not isinstance(profiles, dict):
        raise ValueError("COMISET matrix does not contain a profiles object")
    series = []
    for name in PROFILES:
        profile = profiles.get(name)
        if not isinstance(profile, dict):
            continue
        values = [_metric(profile, key) for key in ("precision", "recall", "f1_score")]
        if any(value is None for value in values):
            continue
        series.append((name, [float(v) for v in values if v is not None]))
    if not series:
        raise ValueError("No measured binary precision/recall/F1 values found")

    plot_left, plot_top, plot_w, plot_h = 95, 105, 785, 335
    parts = ['<text x="480" y="48" text-anchor="middle" class="title">COMISET supported-scope profile comparison</text>']
    for tick in range(0, 6):
        value = tick / 5
        y = plot_top + plot_h - value * plot_h
        parts.append(f'<line class="grid" x1="{plot_left}" y1="{y}" x2="{plot_left+plot_w}" y2="{y}"/>')
        parts.append(f'<text x="{plot_left-12}" y="{y+5}" text-anchor="end" class="small">{value:.1f}</text>')
    parts.append(f'<line class="axis" x1="{plot_left}" y1="{plot_top}" x2="{plot_left}" y2="{plot_top+plot_h}"/>')
    parts.append(f'<line class="axis" x1="{plot_left}" y1="{plot_top+plot_h}" x2="{plot_left+plot_w}" y2="{plot_top+plot_h}"/>')

    metrics = ("Precision", "Recall", "F1")
    group_w = plot_w / len(metrics)
    bar_w = 46
    for m_index, metric in enumerate(metrics):
        gx = plot_left + m_index * group_w
        parts.append(f'<text x="{gx + group_w/2}" y="{plot_top+plot_h+34}" text-anchor="middle" class="label">{metric}</text>')
        total_bars = len(series)
        start = gx + group_w/2 - total_bars * bar_w/2
        for p_index, (name, values) in enumerate(series):
            value = values[m_index]
            height = value * plot_h
            x = start + p_index * bar_w
            y = plot_top + plot_h - height
            parts.append(f'<rect class="bar" x="{x}" y="{y}" width="{bar_w-7}" height="{height}"/>')
            parts.append(f'<text x="{x+(bar_w-7)/2}" y="{max(plot_top+14, y-7)}" text-anchor="middle" class="small">{value:.3f}</text>')
            parts.append(f'<text x="{x+(bar_w-7)/2}" y="{plot_top+plot_h+58}" text-anchor="middle" class="small">{esc(name)}</text>')
    write_svg(path, "\n".join(parts))


def _median(summary: dict[str, Any], key: str) -> float | None:
    value = summary.get(key)
    if isinstance(value, dict):
        value = value.get("median")
    if isinstance(value, (int, float)) and math.isfinite(float(value)):
        return float(value)
    return None


def performance_svg(data: dict[str, Any], path: Path) -> None:
    points: list[tuple[int, float]] = []
    for size in data.get("sizes", []):
        summary = data.get("results", {}).get(str(size), {}).get("summary", {})
        if not isinstance(summary, dict):
            continue
        throughput = _median(summary, "detection_events_per_second")
        if throughput is not None:
            points.append((int(size), throughput))
    if len(points) < 2:
        raise ValueError("At least two measured performance sizes are required")
    points.sort()
    max_y = max(v for _, v in points) * 1.1 or 1
    min_x, max_x = points[0][0], points[-1][0]
    plot_left, plot_top, plot_w, plot_h = 100, 105, 760, 330
    parts = ['<text x="480" y="48" text-anchor="middle" class="title">TriageBloom detection throughput scaling</text>']
    parts.append(f'<line class="axis" x1="{plot_left}" y1="{plot_top}" x2="{plot_left}" y2="{plot_top+plot_h}"/>')
    parts.append(f'<line class="axis" x1="{plot_left}" y1="{plot_top+plot_h}" x2="{plot_left+plot_w}" y2="{plot_top+plot_h}"/>')
    coords = []
    for i in range(6):
        value = max_y * i / 5
        y = plot_top + plot_h - (value/max_y)*plot_h
        parts.append(f'<line class="grid" x1="{plot_left}" y1="{y}" x2="{plot_left+plot_w}" y2="{y}"/>')
        parts.append(f'<text x="{plot_left-12}" y="{y+5}" text-anchor="end" class="small">{value:,.0f}</text>')
    for size, value in points:
        x = plot_left if max_x == min_x else plot_left + (size-min_x)/(max_x-min_x)*plot_w
        y = plot_top + plot_h - value/max_y*plot_h
        coords.append((x, y, size, value))
    poly = " ".join(f"{x:.1f},{y:.1f}" for x, y, _, _ in coords)
    parts.append(f'<polyline class="line" points="{poly}"/>')
    for x, y, size, value in coords:
        parts.append(f'<circle class="point" cx="{x}" cy="{y}" r="6"/>')
        parts.append(f'<text x="{x}" y="{plot_top+plot_h+32}" text-anchor="middle" class="small">{size:,}</text>')
        parts.append(f'<text x="{x}" y="{max(plot_top+14, y-12)}" text-anchor="middle" class="small">{value:,.0f}</text>')
    parts.append('<text x="480" y="505" text-anchor="middle" class="small">Events processed</text>')
    parts.append('<text x="25" y="275" transform="rotate(-90 25 275)" text-anchor="middle" class="small">Detection events/second</text>')
    write_svg(path, "\n".join(parts))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate dependency-free SVG figures for the TriageBloom AISCN study")
    parser.add_argument("--output-dir", type=Path, default=Path("evaluation/external/figures"))
    parser.add_argument("--comiset-matrix", type=Path)
    parser.add_argument("--performance", type=Path)
    args = parser.parse_args(argv)
    try:
        architecture_svg(args.output_dir / "figure1-architecture.svg")
        sequence_svg(args.output_dir / "figure2-correlation-sequence.svg")
        if args.comiset_matrix:
            profile_svg(read_json(args.comiset_matrix), args.output_dir / "figure3-profile-comparison.svg")
        if args.performance:
            performance_svg(read_json(args.performance), args.output_dir / "figure4-throughput-scaling.svg")
        print(f"figures={args.output_dir}")
        return 0
    except (FileNotFoundError, ValueError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
