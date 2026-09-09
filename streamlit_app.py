from __future__ import annotations

import secrets
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import streamlit as st

from triagebloom import __version__
from triagebloom.config import get_profile, validate_config
from triagebloom.detections import run_detections
from triagebloom.models import AnalysisResult
from triagebloom.normalize import InputFormatError, load_events, load_events_bytes
from triagebloom.report import render_html, render_json

ROOT = Path(__file__).resolve().parent
MAX_UPLOAD_BYTES = 25 * 1024 * 1024
DEMO_FILES = {
    "Combined incident chain": ROOT / "sample_data" / "combined_incident.json",
    "Microsoft Entra sign-ins": ROOT / "sample_data" / "entra_signins.json",
    "Microsoft Defender processes": ROOT / "sample_data" / "defender_processes.json",
    "Microsoft Defender alerts": ROOT / "sample_data" / "defender_alerts.json",
}

st.set_page_config(page_title="TriageBloom", page_icon="🔎", layout="wide")
st.markdown(
    """
    <style>
    .block-container {padding-top: 2rem; padding-bottom: 4rem; max-width: 1280px;}
    .tb-hero {padding: 1.2rem 0 0.8rem 0;}
    .tb-kicker {font-size: .82rem; letter-spacing: .12em; text-transform: uppercase; opacity: .68;}
    .tb-hero h1 {font-size: 2.8rem; margin: .15rem 0 .35rem 0;}
    .tb-sub {font-size: 1.05rem; opacity: .82; max-width: 850px;}
    .tb-note {border: 1px solid rgba(128,128,128,.25); border-radius: 12px; padding: .9rem 1rem; margin: .7rem 0 1rem 0;}
    </style>
    """,
    unsafe_allow_html=True,
)

st.markdown(
    f"""
    <div class="tb-hero">
      <div class="tb-kicker">Explainable security log triage · v{__version__}</div>
      <h1>TriageBloom</h1>
      <div class="tb-sub">Analyse exported security events, correlate suspicious activity, preserve Microsoft security context, and generate evidence-linked analyst reports.</div>
    </div>
    """,
    unsafe_allow_html=True,
)

st.markdown(
    """
    <div class="tb-note"><strong>Hosted privacy boundary:</strong> the public web interface is for synthetic, redacted, or explicitly authorised non-confidential data. Do not upload employer, client, production, regulated, or sensitive security logs to a public deployment. For sensitive investigations, run the CLI or Streamlit app locally.</div>
    """,
    unsafe_allow_html=True,
)

with st.sidebar:
    st.header("Analysis settings")
    profile_name = st.selectbox(
        "Detection profile",
        ("balanced", "learner", "strict"),
        help="Balanced is the default. Learner lowers thresholds for demonstrations; strict reduces noise.",
    )
    redact = st.toggle("Pseudonymise identifiers in downloads", value=True)
    enable_off_hours = st.toggle("Review off-hours sign-ins", value=True)

    with st.expander("Advanced thresholds"):
        base = get_profile(profile_name)
        spray_users = st.number_input("Password-spray unique users", 2, 100, base.spray_users)
        brute_force = st.number_input("Brute-force failures", 2, 200, base.brute_force_failures)
        success_after = st.number_input("Failures before success", 2, 100, base.success_after_failures)
        mfa_failures = st.number_input("MFA failures", 2, 100, base.mfa_failures)
        correlation_window = st.number_input("Correlation window (minutes)", 5, 240, base.correlation_window_minutes)

    st.caption("TriageBloom is analyst assistance, not an autonomous incident-response system.")

left, right = st.columns([1, 1])
with left:
    source_mode = st.radio("Data source", ("Demo data", "Upload file"), horizontal=True)
with right:
    if source_mode == "Demo data":
        demo_name = st.selectbox("Synthetic demo", tuple(DEMO_FILES))
        uploaded = None
    else:
        uploaded = st.file_uploader(
            "Security-event export",
            type=["csv", "json", "jsonl", "ndjson"],
            help="Maximum 25 MB. UTF-8 text only.",
        )
        demo_name = None

confirmed = True
if source_mode == "Upload file":
    confirmed = st.checkbox(
        "I confirm this file is synthetic, redacted, or authorised and safe for processing in this web deployment.",
        value=False,
    )

analyze_clicked = st.button("Run analysis", type="primary", use_container_width=True)

if analyze_clicked:
    if source_mode == "Upload file" and uploaded is None:
        st.error("Choose a CSV, JSON, JSONL, or NDJSON file first.")
        st.stop()
    if source_mode == "Upload file" and not confirmed:
        st.error("Confirm that the upload is safe and authorised before analysis.")
        st.stop()
    if uploaded is not None and uploaded.size > MAX_UPLOAD_BYTES:
        st.error("The file is larger than the 25 MB hosted-interface limit.")
        st.stop()

    config = get_profile(profile_name)
    config.enable_off_hours = enable_off_hours
    config.spray_users = int(spray_users)
    config.brute_force_failures = int(brute_force)
    config.success_after_failures = int(success_after)
    config.mfa_failures = int(mfa_failures)
    config.correlation_window_minutes = int(correlation_window)

    try:
        validate_config(config)
        if source_mode == "Demo data":
            source_path = DEMO_FILES[demo_name]
            events = load_events(source_path)
            source_name = source_path.name
            processing_mode = "streamlit"
        else:
            events = load_events_bytes(uploaded.getvalue(), uploaded.name)
            source_name = uploaded.name
            processing_mode = "streamlit"
    except (InputFormatError, ValueError, UnicodeDecodeError) as exc:
        st.error(f"Could not analyse this file: {exc}")
        st.stop()

    if not events:
        st.warning("No events were found in the selected input.")
        st.stop()

    findings = run_detections(events, config)
    source_products = sorted({event.source_product for event in events})
    result = AnalysisResult(
        source_file=source_name,
        generated_at=datetime.now(tz=timezone.utc),
        events_processed=len(events),
        findings=findings,
        metadata={
            "triagebloom_version": __version__,
            "processing_mode": processing_mode,
            "profile": profile_name,
            "source_products": source_products,
            "triggered_rules": sorted({finding.rule_id for finding in findings}),
            "configuration": config.public_dict(),
        },
    )

    counts = Counter(finding.severity for finding in findings)
    m1, m2, m3, m4, m5 = st.columns(5)
    m1.metric("Events", len(events))
    m2.metric("Findings", len(findings))
    m3.metric("Critical", counts.get("critical", 0))
    m4.metric("High", counts.get("high", 0))
    m5.metric("Medium", counts.get("medium", 0))

    st.caption("Source products: " + ", ".join(source_products))

    if findings:
        st.subheader("Prioritised findings")
        st.dataframe(
            [
                {
                    "Rule": item.rule_id,
                    "Finding": item.title,
                    "Severity": item.severity.upper(),
                    "Risk": item.risk_score,
                    "Confidence": item.confidence,
                    "MITRE ATT&CK": item.mitre_technique,
                    "First seen": item.first_seen.isoformat(),
                }
                for item in findings
            ],
            use_container_width=True,
            hide_index=True,
        )

        st.subheader("Analyst detail")
        for finding in findings:
            with st.expander(f"{finding.severity.upper()} · {finding.rule_id} · {finding.title}"):
                st.write(finding.summary)
                st.write(f"**Risk:** {finding.risk_score}/100 · **Confidence:** {finding.confidence}%")
                st.write(f"**MITRE ATT&CK:** {finding.mitre_technique} · {finding.mitre_tactic}")
                if finding.entities:
                    st.write("**Entities**")
                    st.json(finding.entities, expanded=False)
                st.write("**Why it triggered**")
                for item in finding.why_it_triggered:
                    st.write(f"- {item}")
                st.write("**Recommended investigation**")
                for index, item in enumerate(finding.next_steps, start=1):
                    st.write(f"{index}. {item}")
                st.caption("Evidence event IDs: " + ", ".join(finding.evidence_event_ids))
    else:
        st.success("No enabled TriageBloom rules matched this dataset.")

    salt = secrets.token_hex(16) if redact else None
    json_report = render_json(result, redact=redact, salt=salt)
    html_report = render_html(result, redact=redact, salt=salt)
    stem = Path(source_name).stem

    st.subheader("Download report")
    d1, d2 = st.columns(2)
    d1.download_button(
        "Download JSON",
        data=json_report,
        file_name=f"{stem}-triagebloom.json",
        mime="application/json",
        use_container_width=True,
    )
    d2.download_button(
        "Download HTML",
        data=html_report,
        file_name=f"{stem}-triagebloom.html",
        mime="text/html",
        use_container_width=True,
    )
