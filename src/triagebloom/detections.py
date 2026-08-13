from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import timedelta
from typing import Callable, Iterable

from .models import Finding, NormalizedEvent


SEVERITY_BASE = {"low": 30, "medium": 55, "high": 80, "critical": 95}


@dataclass(slots=True)
class DetectionConfig:
    spray_users: int = 5
    spray_window_minutes: int = 10
    brute_force_failures: int = 8
    brute_force_window_minutes: int = 10
    success_after_failures: int = 5
    success_window_minutes: int = 15
    business_start_hour: int = 7
    business_end_hour: int = 20
    enable_off_hours: bool = True


def _risk(severity: str, confidence: int) -> int:
    base = SEVERITY_BASE[severity]
    return min(100, round(base * 0.75 + confidence * 0.25))


def _entities(events: Iterable[NormalizedEvent]) -> dict[str, list[str]]:
    values: dict[str, set[str]] = {"users": set(), "source_ips": set(), "devices": set()}
    for event in events:
        if event.user:
            values["users"].add(event.user)
        if event.source_ip:
            values["source_ips"].add(event.source_ip)
        if event.device:
            values["devices"].add(event.device)
    return {key: sorted(items) for key, items in values.items() if items}


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
        confidence=confidence,
        risk_score=_risk(severity, confidence),
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
                            "Check whether the source IP belongs to a trusted VPN, proxy, or identity provider.",
                            "Review sign-in risk, user agents, locations, and conditional access results for the affected users.",
                            "Reset or protect any account that later authenticated successfully from the same source.",
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
                            "Review the source IPs and devices for known infrastructure or hostile reputation.",
                            "Consider a password reset and session revocation if the activity is unexplained.",
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
                findings.append(
                    _make_finding(
                        rule_id="TB-AUTH-003",
                        title="Successful sign-in after repeated failures",
                        severity="critical",
                        confidence=92,
                        mitre_technique="T1078",
                        mitre_tactic="Defense Evasion, Persistence, Privilege Escalation, Initial Access",
                        summary=(
                            f"User {user} successfully authenticated after {len(recent_failures)} failures "
                            f"within {config.success_window_minutes} minutes."
                        ),
                        events=evidence,
                        why=[
                            f"Preceding failures: {len(recent_failures)} (threshold: {config.success_after_failures})",
                            f"Successful event: {event.event_id}",
                            f"Successful source IP: {event.source_ip or 'not present'}",
                        ],
                        next_steps=[
                            "Validate the successful sign-in with the user and compare its device, IP, and location with normal activity.",
                            "Review actions performed after authentication, including mailbox, cloud, and endpoint activity.",
                            "Revoke active sessions and reset credentials immediately if compromise cannot be ruled out.",
                        ],
                    )
                )
                recent_failures.clear()
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
                    why=[f"Matched behaviour: {description}" for description in matched],
                    next_steps=[
                        "Retrieve the full process tree, parent process, user context, and file hashes.",
                        "Decode any Base64 content in an isolated analysis environment and inspect referenced URLs or files.",
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
                        why=[f"The command line contained the executable name '{binary}'."],
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
                ],
                next_steps=[
                    "Check the user's expected work pattern, travel, time zone, and on-call responsibilities.",
                    "Compare the IP address, device, and authentication method with the user's normal activity.",
                ],
            )
        )
    return findings


DETECTORS: tuple[Callable[[list[NormalizedEvent], DetectionConfig], list[Finding]], ...] = (
    detect_password_spray,
    detect_brute_force,
    detect_success_after_failures,
    detect_suspicious_commands,
    detect_off_hours_success,
)


def run_detections(events: list[NormalizedEvent], config: DetectionConfig | None = None) -> list[Finding]:
    effective_config = config or DetectionConfig()
    findings: list[Finding] = []
    for detector in DETECTORS:
        findings.extend(detector(events, effective_config))
    return sorted(findings, key=lambda item: (-item.risk_score, item.first_seen, item.rule_id))
