from __future__ import annotations


ATTACK_TACTICS: dict[str, tuple[str, ...]] = {
    "T1110.001": ("Credential Access",),
    "T1110.003": ("Credential Access",),
    "T1078": ("Stealth", "Persistence", "Privilege Escalation", "Initial Access"),
    "T1621": ("Credential Access",),
    "T1059.001": ("Execution",),
    "T1105": ("Command and Control",),
    "T1218.005": ("Stealth",),
    "T1218.010": ("Stealth",),
    "T1218.011": ("Stealth",),
    "T1197": ("Stealth", "Persistence", "Execution"),
}


def canonical_tactics(technique: str, fallback: str) -> str:
    """Return current ATT&CK tactic labels for a supported technique expression."""

    technique_ids = [part.strip() for part in technique.split("+") if part.strip()]
    if not technique_ids or any(technique_id not in ATTACK_TACTICS for technique_id in technique_ids):
        return fallback

    ordered: list[str] = []
    seen: set[str] = set()
    for technique_id in technique_ids:
        for tactic in ATTACK_TACTICS[technique_id]:
            if tactic not in seen:
                seen.add(tactic)
                ordered.append(tactic)
    return ", ".join(ordered)
