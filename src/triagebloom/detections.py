from __future__ import annotations

from collections import defaultdict, deque
from datetime import timedelta
from typing import Callable, Iterable

from .config import DetectionConfig
from .models import Finding, NormalizedEvent


SEVERITY_BASE = {"low": 30, "medium": 55, "high": 80, "critical": 95}


def _risk(severity: str, confidence: int) -> int:
    base = SEVERITY_BASE[severity]
    return min(100, round(base * 0.75 + confidence * 0.25))


def _entities(events: Iterable[NormalizedEvent]) -> dict[str, list[str]]:
    values: dict[str, set[str]] = {
        "users": set(),
        "source_ips": set(),
        "devices": set(),
        "source_products": set(),
    }
    for event in events:
        if event.user:
            values["users"].add(event.user)
        if event.source_ip:
            values["source_ips"].add(event.source_ip)
        if event.device:
            values["devices"].add(event.device)
        if event.source_product:
            values["source_products"].add(event.source_product)
    return {key: sorted(items) for key, items in values.items() if items}


def _context_lines(event: NormalizedEvent) -> list[str]:
    lines: list[str] = []
    if event.conditional_access_status:
        lines.append(f"Conditional Access: {event.conditional_access_status}")
    if event.risk_level:
        lines.append(f"Sign-in risk level: {event.risk_level}")
    if event.risk_state:
        lines.append(f"Risk state: {event.risk_state}")
    if event.authentication_requirement:
        lines.append(f"Authentication requirement: {event.authentication_requirement}")
    if event.authentication_method:
        lines.append(f"Authentication detail: {event.authentication_method}")
    if event.parent_process:
        lines.append(f"Parent/initiating process: {event.parent_process}")
    if event.file_name:
        lines.append(f"Process/file: {event.file_name}")
    if event.sha256:
        lines.append(f"SHA256: {event.sha256}")
    return lines


def _make_finding(
    *,
    rule_id: str,
    title: str,
    severity: str,
    confidence: int,
    mitre_technique: str,
    mitre_tactic: str,
    summary: str,
    events: list[NormalizedEvent],
    why: list[str],
    next_steps: list[str],
) -> Finding:
    ordered = sorted(events, key=lambda event: event.timestamp)
    return Finding(
        rule_id=rule_id,
        title=title,
        severity=severity,
        confidence=max(0, min(100, confidence)),
        risk_score=_risk(severity, max(0, min(100, confidence))),
        mitre_technique=mitre_technique,
        mitre_tactic=mitre_tactic,
        summary=summary,
        evidence_event_ids=[event.event_id for event in ordered],
        entities=_entities(ordered),
        why_it_triggered=why,
        next_steps=next_steps,
        first_seen=ordered[0].timestamp,
        last_seen=ordered[-1].timestamp,
    )


def _finding_is_suppressed(finding: Finding, config: DetectionConfig) -> bool:
    if finding.rule_id in config.suppressed_rule_ids:
        return True

    entity_sets = {
        "users": config.allow_users,
        "source_ips": config.allow_source_ips,
        "devices": config.allow_devices,
    }
    for key, allow_values in entity_sets.items():
        finding_values = set(finding.entities.get(key, []))
        if finding_values and allow_values and finding_values.issubset(allow_values):
            return True
    return False


def detect_password_spray(events: list[NormalizedEvent], config: DetectionConfig) -> list[Finding]:
    failures = [
        event
        for event in events
        if event.category == "authentication" and event.outcome == "failure" and event.source_ip and event.user
    ]
    grouped: dict[str, list[NormalizedEvent]] = defaultdict(list)
    for event in failures:
        grouped[event.source_ip or ""].append(event)

    findings: list[Finding] = []
    window = timedelta(minutes=config.spray_window_minutes)

    for source_ip, source_events in grouped.items():
        queue: deque[NormalizedEvent] = deque()
        emitted_until = None
        for event in sorted(source_events, key=lambda item: item.timestamp):
            queue.append(event)
            while queue and event.timestamp - queue[0].timestamp > window:
                queue.popleft()

            users = {item.user for item in queue if item.user}
            if len(users) >= config.spray_users:
                if emitted_until is not None and event.timestamp <= emitted_until:
                    continue
                evidence = list(queue)
                findings.append(
                    _make_finding(
                        rule_id="TB-AUTH-001",
                        title="Possible password spray",
                        severity="high",
                        confidence=90,
                        mitre_technique="T1110.003",
                        mitre_tactic="Credential Access",
                        summary=(
                            f"Source IP {source_ip} generated failed sign-ins for {len(users)} distinct users "
                            f"within {config.spray_window_minutes} minutes."
                        ),
                        events=evidence,
                        why=[
                            f"Unique targeted users: {len(users)} (threshold: {config.spray_users})",
                            f"Observed source IP: {source_ip}",
                            f"Time window: {config.spray_window_minutes} minutes",
                        ],
                        next_steps=[
                            "Check whether the source IP belongs to a trusted VPN, proxy, identity provider, or test range.",
                            "Review Entra sign-in risk, locations, client applications, and Conditional Access results.",
                            "Check whether any targeted account later authenticated successfully from the same source.",
                        ],
                    )
                )
                emitted_until = event.timestamp + window
    return findings


def detect_brute_force(events: list[NormalizedEvent], config: DetectionConfig) -> list[Finding]:
    failures = [
        event
        for event in events
        if event.category == "authentication" and event.outcome == "failure" and event.user
    ]
    grouped: dict[str, list[NormalizedEvent]] = defaultdict(list)
    for event in failures:
        grouped[event.user or ""].append(event)

    findings: list[Finding] = []
    window = timedelta(minutes=config.brute_force_window_minutes)

    for user, user_events in grouped.items():
        queue: deque[NormalizedEvent] = deque()
        emitted_until = None
        for event in sorted(user_events, key=lambda item: item.timestamp):
            queue.append(event)
            while queue and event.timestamp - queue[0].timestamp > window:
                queue.popleft()
            if len(queue) >= config.brute_force_failures:
                if emitted_until is not None and event.timestamp <= emitted_until:
                    continue
                evidence = list(queue)
                source_ips = {item.source_ip for item in evidence if item.source_ip}
                findings.append(
                    _make_finding(
                        rule_id="TB-AUTH-002",
                        title="Possible account brute force",
                        severity="high",
                        confidence=85,
                        mitre_technique="T1110.001",
                        mitre_tactic="Credential Access",
                        summary=(
                            f"User {user} had {len(evidence)} failed sign-ins within "
                            f"{config.brute_force_window_minutes} minutes."
                        ),
                        events=evidence,
                        why=[
                            f"Failed sign-ins: {len(evidence)} (threshold: {config.brute_force_failures})",
                            f"Distinct source IPs: {len(source_ips)}",
                            f"Time window: {config.brute_force_window_minutes} minutes",
                        ],
                        next_steps=[
                            "Confirm whether the failures were caused by a stale password, service account, or automated task.",
                            "Review source IPs, devices, sign-in risk, and authentication methods.",
                            "Consider password reset and session revocation if the activity is unexplained.",
                        ],
                    )
                )
                emitted_until = event.timestamp + window
    return findings


def detect_success_after_failures(events: list[NormalizedEvent], config: DetectionConfig) -> list[Finding]:
    auth_events = [event for event in events if event.category == "authentication" and event.user]
    grouped: dict[str, list[NormalizedEvent]] = defaultdict(list)
    for event in auth_events:
        grouped[event.user or ""].append(event)

    findings: list[Finding] = []
    window = timedelta(minutes=config.success_window_minutes)

    for user, user_events in grouped.items():
        recent_failures: deque[NormalizedEvent] = deque()
        for event in sorted(user_events, key=lambda item: item.timestamp):
            while recent_failures and event.timestamp - recent_failures[0].timestamp > window:
                recent_failures.popleft()
            if event.outcome == "failure":
                recent_failures.append(event)
                continue
            if event.outcome == "success" and len(recent_failures) >= config.success_after_failures:
                evidence = list(recent_failures) + [event]
                confidence = 92
                if str(event.risk_level or "").lower() in {"high", "medium"}:
                    confidence += 4
                why = [
                    f"Preceding failures: {len(recent_failures)} (threshold: {config.success_after_failures})",
                    f"Successful event: {event.event_id}",
                    f"Successful source IP: {event.source_ip or 'not present'}",
                ] + _context_lines(event)
                findings.append(
                    _make_finding(
                        rule_id="TB-AUTH-003",
                        title="Successful sign-in after repeated failures",
                        severity="critical",
                        confidence=confidence,
                        mitre_technique="T1078",
                        mitre_tactic="Defense Evasion, Persistence, Privilege Escalation, Initial Access",
                        summary=(
                            f"User {user} successfully authenticated after {len(recent_failures)} failures "
                            f"within {config.success_window_minutes} minutes."
                        ),
                        events=evidence,
                        why=why,
                        next_steps=[
                            "Validate the successful sign-in with the user and compare its device, IP, and location with normal activity.",
                            "Review Conditional Access, risk state, authentication details, and actions performed after sign-in.",
                            "Revoke active sessions and reset credentials if compromise cannot be ruled out.",
                        ],
                    )
                )
                recent_failures.clear()
    return findings


def _looks_like_mfa(event: NormalizedEvent) -> bool:
    combined = " ".join(
        str(value or "")
        for value in (
            event.event_type,
            event.authentication_requirement,
            event.authentication_method,
        )
    ).lower()
    return "mfa" in combined or "multifactor" in combined or "multi-factor" in combined


def detect_mfa_fatigue(events: list[NormalizedEvent], config: DetectionConfig) -> list[Finding]:
    auth_events = [event for event in events if event.category == "authentication" and event.user and _looks_like_mfa(event)]
    grouped: dict[str, list[NormalizedEvent]] = defaultdict(list)
    for event in auth_events:
        grouped[event.user or ""].append(event)

    findings: list[Finding] = []
    window = timedelta(minutes=config.mfa_window_minutes)

    for user, user_events in grouped.items():
        failures: deque[NormalizedEvent] = deque()
        for event in sorted(user_events, key=lambda item: item.timestamp):
            while failures and event.timestamp - failures[0].timestamp > window:
                failures.popleft()
            if event.outcome == "failure":
                failures.append(event)
                continue
            if event.outcome == "success" and len(failures) >= config.mfa_failures:
                evidence = list(failures) + [event]
                findings.append(
                    _make_finding(
                        rule_id="TB-AUTH-005",
                        title="Possible MFA fatigue followed by successful authentication",
                        severity="critical",
                        confidence=94,
                        mitre_technique="T1621",
                        mitre_tactic="Credential Access",
                        summary=(
                            f"User {user} had {len(failures)} MFA-related failures followed by a success "
                            f"within {config.mfa_window_minutes} minutes."
                        ),
                        events=evidence,
                        why=[
                            f"MFA-related failures: {len(failures)} (threshold: {config.mfa_failures})",
                            f"Successful event: {event.event_id}",
                            f"Time window: {config.mfa_window_minutes} minutes",
                        ] + _context_lines(event),
                        next_steps=[
                            "Contact the user to confirm whether repeated MFA prompts were expected.",
                            "Review authentication methods, device details, sign-in risk, and source IP changes.",
                            "Revoke sessions and reset credentials if the user denies approving the successful prompt.",
                        ],
                    )
                )
                failures.clear()
    return findings


POWERSHELL_PATTERNS: tuple[tuple[str, str], ...] = (
    ("-enc", "encoded command switch"),
    ("-encodedcommand", "encoded command switch"),
    ("frombase64string", "Base64 decoding"),
    ("downloadstring", "remote content download"),
    ("invoke-expression", "dynamic expression execution"),
    ("iex ", "Invoke-Expression alias"),
    ("-windowstyle hidden", "hidden PowerShell window"),
    ("-w hidden", "hidden PowerShell window"),
)

LOLBIN_PATTERNS: tuple[tuple[str, str, str], ...] = (
    ("certutil", "T1105", "Ingress Tool Transfer"),
    ("mshta", "T1218.005", "Signed Binary Proxy Execution"),
    ("regsvr32", "T1218.010", "Signed Binary Proxy Execution"),
    ("rundll32", "T1218.011", "Signed Binary Proxy Execution"),
    ("bitsadmin", "T1197", "BITS Jobs"),
)


def detect_suspicious_commands(events: list[NormalizedEvent], config: DetectionConfig) -> list[Finding]:
    del config
    findings: list[Finding] = []
    for event in events:
        if not event.command_line:
            continue
        command = event.command_line.lower()
        matched = sorted({description for pattern, description in POWERSHELL_PATTERNS if pattern in command})
        if matched and ("powershell" in command or "pwsh" in command):
            findings.append(
                _make_finding(
                    rule_id="TB-PROC-001",
                    title="Suspicious PowerShell execution",
                    severity="high",
                    confidence=min(98, 78 + 5 * len(matched)),
                    mitre_technique="T1059.001",
                    mitre_tactic="Execution",
                    summary=f"PowerShell command contained {', '.join(matched)}.",
                    events=[event],
                    why=[f"Matched behaviour: {description}" for description in matched] + _context_lines(event),
                    next_steps=[
                        "Retrieve the full process tree, parent process, user context, and file hashes.",
                        "Decode Base64 content only in an isolated analysis environment and inspect referenced URLs or files.",
                        "Search for the same command-line fragments across other endpoints.",
                    ],
                )
            )

        for binary, technique, technique_name in LOLBIN_PATTERNS:
            if binary in command:
                findings.append(
                    _make_finding(
                        rule_id="TB-PROC-002",
                        title=f"Potential living-off-the-land binary use: {binary}",
                        severity="medium",
                        confidence=74,
                        mitre_technique=technique,
                        mitre_tactic="Defense Evasion, Execution, Command and Control",
                        summary=(
                            f"Command line used {binary}, a legitimate Windows utility that can be abused. "
                            f"Mapped behaviour: {technique_name}."
                        ),
                        events=[event],
                        why=[f"The command line contained the executable name '{binary}'."] + _context_lines(event),
                        next_steps=[
                            "Validate whether the command is expected for the user, device, and software deployment process.",
                            "Inspect parent and child processes, network connections, and files created by the command.",
                            "Search for repeated use of the same binary and arguments across the environment.",
                        ],
                    )
                )
                break
    return findings


def detect_off_hours_success(events: list[NormalizedEvent], config: DetectionConfig) -> list[Finding]:
    if not config.enable_off_hours:
        return []
    findings: list[Finding] = []
    for event in events:
        if event.category != "authentication" or event.outcome != "success" or not event.user:
            continue
        hour = event.timestamp.hour
        if config.business_start_hour <= hour < config.business_end_hour:
            continue
        findings.append(
            _make_finding(
                rule_id="TB-AUTH-004",
                title="Successful sign-in outside configured business hours",
                severity="low",
                confidence=55,
                mitre_technique="T1078",
                mitre_tactic="Initial Access, Persistence, Privilege Escalation, Defense Evasion",
                summary=(
                    f"User {event.user} successfully authenticated at {event.timestamp.isoformat()}, outside the configured "
                    f"{config.business_start_hour:02d}:00-{config.business_end_hour:02d}:00 UTC window."
                ),
                events=[event],
                why=[
                    f"Observed UTC hour: {hour:02d}:00",
                    f"Configured business window: {config.business_start_hour:02d}:00-{config.business_end_hour:02d}:00 UTC",
                ] + _context_lines(event),
                next_steps=[
                    "Check the user's expected work pattern, travel, time zone, and on-call responsibilities.",
                    "Compare IP address, device, risk state, and authentication method with normal activity.",
                ],
            )
        )
    return findings


def _is_suspicious_process(event: NormalizedEvent) -> bool:
    command = (event.command_line or "").lower()
    if not command:
        return False
    if ("powershell" in command or "pwsh" in command) and any(pattern in command for pattern, _ in POWERSHELL_PATTERNS):
        return True
    return any(binary in command for binary, _, _ in LOLBIN_PATTERNS)


def detect_incident_chain(events: list[NormalizedEvent], config: DetectionConfig) -> list[Finding]:
    """Correlate failed authentication, a success, and suspicious endpoint execution."""

    by_user: dict[str, list[NormalizedEvent]] = defaultdict(list)
    for event in events:
        if event.user:
            by_user[event.user].append(event)

    findings: list[Finding] = []
    window = timedelta(minutes=config.correlation_window_minutes)

    for user, user_events in by_user.items():
        ordered = sorted(user_events, key=lambda item: item.timestamp)
        for success in [item for item in ordered if item.category == "authentication" and item.outcome == "success"]:
            failures = [
                item
                for item in ordered
                if item.category == "authentication"
                and item.outcome == "failure"
                and success.timestamp - window <= item.timestamp < success.timestamp
            ]
            if len(failures) < config.success_after_failures:
                continue

            processes = [
                item
                for item in ordered
                if item.category == "process"
                and success.timestamp <= item.timestamp <= success.timestamp + window
                and _is_suspicious_process(item)
                and (not success.device or not item.device or success.device == item.device)
            ]
            if not processes:
                continue

            evidence = failures[-config.success_after_failures :] + [success, processes[0]]
            findings.append(
                _make_finding(
                    rule_id="TB-CORR-001",
                    title="Correlated authentication-to-endpoint compromise chain",
                    severity="critical",
                    confidence=97,
                    mitre_technique="T1078 + T1059.001",
                    mitre_tactic="Initial Access, Credential Access, Execution",
                    summary=(
                        f"User {user} had repeated failed authentication, then a successful sign-in, "
                        "followed by suspicious endpoint execution within the configured correlation window."
                    ),
                    events=evidence,
                    why=[
                        f"Authentication failures before success: {len(failures)}",
                        f"Successful authentication event: {success.event_id}",
                        f"Suspicious process event: {processes[0].event_id}",
                        f"Correlation window: {config.correlation_window_minutes} minutes",
                    ] + _context_lines(success) + _context_lines(processes[0]),
                    next_steps=[
                        "Treat the sequence as a single investigation rather than separate alerts.",
                        "Validate the successful sign-in and isolate the endpoint if malicious execution is confirmed.",
                        "Review subsequent processes, network connections, cloud activity, and persistence attempts.",
                    ],
                )
            )
            break
    return findings


DETECTORS: tuple[Callable[[list[NormalizedEvent], DetectionConfig], list[Finding]], ...] = (
    detect_password_spray,
    detect_brute_force,
    detect_success_after_failures,
    detect_mfa_fatigue,
    detect_suspicious_commands,
    detect_off_hours_success,
    detect_incident_chain,
)


def run_detections(events: list[NormalizedEvent], config: DetectionConfig | None = None) -> list[Finding]:
    effective_config = config or DetectionConfig()
    findings: list[Finding] = []
    for detector in DETECTORS:
        findings.extend(detector(events, effective_config))
    findings = [finding for finding in findings if not _finding_is_suppressed(finding, effective_config)]
    return sorted(findings, key=lambda item: (-item.risk_score, item.first_seen, item.rule_id))
