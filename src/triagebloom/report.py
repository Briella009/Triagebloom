from __future__ import annotations

import hashlib
import html
import json
import secrets
from collections import Counter
from pathlib import Path
from typing import Any

from .models import AnalysisResult


SENSITIVE_ENTITY_KEYS = {"users", "source_ips", "devices"}


def _pseudonym(value: str, salt: str) -> str:
    digest = hashlib.sha256(f"{salt}:{value}".encode("utf-8")).hexdigest()[:10]
    return f"redacted-{digest}"


def _redacted_result(result: AnalysisResult, salt: str) -> dict[str, Any]:
    data = result.to_dict()
    global_mapping: dict[str, str] = {}

    for finding in data["findings"]:
        entities = finding.get("entities", {})
        for key, values in entities.items():
            if key not in SENSITIVE_ENTITY_KEYS:
                continue
            redacted_values = []
            for value in values:
                original = str(value)
                replacement = global_mapping.setdefault(original, _pseudonym(original, salt))
                redacted_values.append(replacement)
            entities[key] = redacted_values

    metadata = data.get("metadata", {})
    configuration = metadata.get("configuration")
    if isinstance(configuration, dict):
        for key in ("allow_users", "allow_source_ips", "allow_devices"):
            values = configuration.get(key)
            if not isinstance(values, list):
                continue
            redacted_values = []
            for value in values:
                original = str(value)
                replacement = global_mapping.setdefault(original, _pseudonym(original, salt))
                redacted_values.append(replacement)
            configuration[key] = redacted_values

    for finding in data["findings"]:
        for original, replacement in global_mapping.items():
            finding["summary"] = finding["summary"].replace(original, replacement)
            finding["why_it_triggered"] = [item.replace(original, replacement) for item in finding["why_it_triggered"]]

    source_file = str(data.get("source_file", ""))
    if source_file:
        data["source_file"] = f"redacted-source-{hashlib.sha256(f'{salt}:{source_file}'.encode('utf-8')).hexdigest()[:10]}"
    data["metadata"] = {**metadata, "identifiers_redacted": True}
    return data


def result_to_dict(result: AnalysisResult, redact: bool = False, salt: str | None = None) -> dict[str, Any]:
    if not redact:
        return result.to_dict()
    return _redacted_result(result, salt or secrets.token_hex(16))


def render_json(result: AnalysisResult, redact: bool = False, salt: str | None = None) -> str:
    return json.dumps(result_to_dict(result, redact=redact, salt=salt), indent=2, ensure_ascii=False)


def write_json(result: AnalysisResult, destination: Path, redact: bool = False, salt: str | None = None) -> Path:
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(render_json(result, redact=redact, salt=salt), encoding="utf-8")
    return destination


def _pill(severity: str) -> str:
    return f'<span class="pill {html.escape(severity)}">{html.escape(severity.upper())}</span>'


def render_html(result: AnalysisResult, redact: bool = False, salt: str | None = None) -> str:
    data = result_to_dict(result, redact=redact, salt=salt)

    severity_counts = Counter(item["severity"] for item in data["findings"])
    finding_rows: list[str] = []
    detail_sections: list[str] = []

    for index, finding in enumerate(data["findings"], start=1):
        anchor = f"finding-{index}"
        finding_rows.append(
            "<tr>"
            f'<td><a href="#{anchor}">{html.escape(finding["rule_id"])}</a></td>'
            f'<td>{html.escape(finding["title"])}</td>'
            f'<td>{_pill(finding["severity"])}</td>'
            f'<td>{finding["risk_score"]}/100</td>'
            f'<td>{html.escape(finding["mitre_technique"])}</td>'
            f'<td>{html.escape(finding["first_seen"])}</td>'
            "</tr>"
        )

        entity_items = "".join(
            f"<li><strong>{html.escape(key.replace('_', ' ').title())}:</strong> "
            f"{html.escape(', '.join(str(value) for value in values))}</li>"
            for key, values in finding.get("entities", {}).items()
        ) or "<li>No identifiers were present in the source event.</li>"
        why_items = "".join(f"<li>{html.escape(item)}</li>" for item in finding["why_it_triggered"])
        next_items = "".join(f"<li>{html.escape(item)}</li>" for item in finding["next_steps"])
        evidence_items = "".join(f"<code>{html.escape(event_id)}</code> " for event_id in finding["evidence_event_ids"])

        detail_sections.append(
            f'<section class="finding" id="{anchor}">'
            f'<div class="finding-heading"><h3>{html.escape(finding["title"])}</h3>{_pill(finding["severity"])}</div>'
            f'<p class="rule">{html.escape(finding["rule_id"])} | Risk {finding["risk_score"]}/100 | '
            f'Confidence {finding["confidence"]}% | {html.escape(finding["mitre_technique"])} '
            f'({html.escape(finding["mitre_tactic"])})</p>'
            f'<p>{html.escape(finding["summary"])}</p>'
            "<h4>Why it triggered</h4>"
            f"<ul>{why_items}</ul>"
            "<h4>Entities</h4>"
            f"<ul>{entity_items}</ul>"
            "<h4>Recommended investigation</h4>"
            f"<ol>{next_items}</ol>"
            "<h4>Evidence event IDs</h4>"
            f'<p class="evidence">{evidence_items}</p>'
            "</section>"
        )

    table_body = "".join(finding_rows) or '<tr><td colspan="6">No findings were generated.</td></tr>'
    details = "".join(detail_sections) or "<p>No suspicious patterns matched the enabled rules.</p>"
    redaction_note = "Identifiers were pseudonymised in this report." if redact else "Identifiers are shown as present in the source data."
    metadata = data.get("metadata", {})
    processing_mode = str(metadata.get("processing_mode", "local"))
    if processing_mode == "local":
        processing_note = "Processing occurred locally on the analyst's computer."
    else:
        processing_note = (
            "This report was generated through the TriageBloom web interface. If the interface is hosted, uploaded "
            "content is processed by that hosting environment; do not upload confidential employer, client, or "
            "production logs to a public deployment."
        )
    profile = str(metadata.get("profile", "not specified"))
    source_products = ", ".join(str(item) for item in metadata.get("source_products", [])) or "not identified"
    triggered_rules = ", ".join(str(item) for item in metadata.get("triggered_rules", [])) or "none"

    document = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>TriageBloom analysis report</title>
<style>
:root {{ color-scheme: light; --ink:#172033; --muted:#657089; --line:#dbe1ea; --surface:#f6f8fb; }}
* {{ box-sizing:border-box; }}
body {{ margin:0; font-family:Inter,Segoe UI,Arial,sans-serif; color:var(--ink); background:white; line-height:1.55; }}
header {{ padding:48px max(24px,8vw); background:#111a2e; color:white; }}
header h1 {{ margin:0 0 8px; font-size:2.2rem; }}
header p {{ margin:4px 0; color:#d8dfed; }}
main {{ width:min(1180px,92vw); margin:32px auto 64px; }}
.cards {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(160px,1fr)); gap:14px; margin:24px 0; }}
.card {{ padding:18px; border:1px solid var(--line); border-radius:14px; background:var(--surface); }}
.card strong {{ display:block; font-size:1.7rem; }}
table {{ width:100%; border-collapse:collapse; font-size:.92rem; }}
th,td {{ text-align:left; padding:12px 10px; border-bottom:1px solid var(--line); vertical-align:top; }}
th {{ background:var(--surface); position:sticky; top:0; }}
a {{ color:#2457c5; }}
.pill {{ display:inline-block; padding:3px 9px; border-radius:999px; font-size:.72rem; font-weight:700; letter-spacing:.04em; background:#e8edf5; }}
.pill.low {{ background:#e7f1ff; }} .pill.medium {{ background:#fff1c7; }} .pill.high {{ background:#ffe1cd; }} .pill.critical {{ background:#ffd9df; }}
.finding {{ margin:26px 0; padding:24px; border:1px solid var(--line); border-radius:16px; }}
.finding-heading {{ display:flex; justify-content:space-between; gap:16px; align-items:flex-start; }}
.finding h3 {{ margin:0; }} .finding h4 {{ margin-bottom:4px; }}
.rule {{ color:var(--muted); font-size:.88rem; }}
.evidence {{ line-height:2; }} code {{ background:#eef2f7; padding:3px 6px; border-radius:5px; }}
.notice {{ padding:16px 18px; border-left:4px solid #6b7b9c; background:var(--surface); margin:22px 0; }}
footer {{ color:var(--muted); font-size:.86rem; margin-top:38px; }}
@media print {{ header {{ padding:28px; }} main {{ width:94%; }} .finding {{ break-inside:avoid; }} }}
</style>
</head>
<body>
<header>
  <h1>TriageBloom analysis report</h1>
  <p>Explainable, local-first security log triage</p>
  <p>Generated {html.escape(data["generated_at"])} from {html.escape(data["source_file"])}</p>
</header>
<main>
  <div class="notice"><strong>Privacy:</strong> {html.escape(processing_note)} {html.escape(redaction_note)}</div>
  <div class="notice"><strong>Analysis context:</strong> profile {html.escape(profile)} | source products {html.escape(source_products)} | triggered rules {html.escape(triggered_rules)}</div>
  <div class="cards">
    <div class="card"><span>Events processed</span><strong>{data["events_processed"]}</strong></div>
    <div class="card"><span>Total findings</span><strong>{data["finding_count"]}</strong></div>
    <div class="card"><span>Critical</span><strong>{severity_counts.get("critical", 0)}</strong></div>
    <div class="card"><span>High</span><strong>{severity_counts.get("high", 0)}</strong></div>
    <div class="card"><span>Medium</span><strong>{severity_counts.get("medium", 0)}</strong></div>
  </div>
  <h2>Finding summary</h2>
  <div style="overflow-x:auto">
  <table>
    <thead><tr><th>Rule</th><th>Finding</th><th>Severity</th><th>Risk</th><th>MITRE</th><th>First seen</th></tr></thead>
    <tbody>{table_body}</tbody>
  </table>
  </div>
  <h2>Analyst detail</h2>
  {details}
  <footer>
    TriageBloom is an analyst-assistance tool, not a substitute for investigation or incident-response judgement.
    Validate all findings against authoritative telemetry and organisational context.
  </footer>
</main>
</body>
</html>
"""
    return document


def write_html(result: AnalysisResult, destination: Path, redact: bool = False, salt: str | None = None) -> Path:
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(render_html(result, redact=redact, salt=salt), encoding="utf-8")
    return destination
