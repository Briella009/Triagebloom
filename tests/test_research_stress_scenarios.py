"""Researcher-authored semantic stress tests for TriageBloom.

This deliberately small collection is NOT independent validation, a field
study, or a measurement of production precision and recall. Case labels mean
"warrants analyst review", not confirmed malicious activity. Findings from
the stress suite must be reported including all false alerts and misses.
"""
import json
import platform
import sys
import time
import unittest
from datetime import datetime, timedelta, timezone

from triagebloom.config import get_profile
from triagebloom.detections import run_detections
from triagebloom.normalize import normalise_rows

BASE = datetime(2026, 10, 1, 10, 0, tzinfo=timezone.utc)


def when(minute=0):
    return (BASE + timedelta(minutes=minute)).isoformat().replace("+00:00", "Z")


def auth(event_id, user="user@example.org", ip="198.51.100.7",
         outcome="Failure", minute=0, device="LAB-A", event_type="SignIn"):
    return {
        "timestamp": when(minute), "event_id": event_id,
        "event_type": event_type, "outcome": outcome,
        "user": user, "source_ip": ip, "device": device,
    }


def proc(event_id, command, user="user@example.org", minute=0, device="LAB-A"):
    return {
        "Timestamp": when(minute), "ReportId": event_id,
        "DeviceName": device, "ActionType": "ProcessCreated",
        "AccountName": user, "ProcessCommandLine": command,
        "FileName": command.split()[0],
    }


def case(case_id, review, category, rationale, events):
    return dict(id=case_id, review_warranted=review, category=category,
                rationale=rationale, events=events)


def make_cases():
    cases = []
    cases.append(case("B01", False, "benign", "Normal successful workday sign-ins",
        [auth("b01-1", outcome="Success"),
         auth("b01-2", user="u2@example.org", outcome="Success", minute=3)]))
    cases.append(case("B02", False, "benign_lookalike",
        "Authorised certificate hash verification using a dual-use executable",
        [proc("b02-1", r"certutil.exe -hashfile C:\Temp\baseline.txt SHA256")]))
    cases.append(case("B03", False, "benign_lookalike",
        "Administrative PowerShell -EncryptVolume, not -EncodedCommand",
        [proc("b03-1", "powershell.exe -EncryptVolume -MountPoint C:")]))
    cases.append(case("B04", False, "benign",
        "Three mistyped sign-ins in three minutes",
        [auth(f"b04-{i}", minute=i) for i in range(3)]))
    cases.append(case("B05", False, "benign_lookalike",
        "Authorised account testing with eight failed attempts",
        [auth(f"b05-{i}", user="labtest@example.org", minute=i) for i in range(8)]))
    cases.append(case("B06", False, "boundary",
        "Four failed users from corporate egress below spray threshold",
        [auth(f"b06-{i}", user=f"co{i}@example.org",
              ip="203.0.113.17", minute=i) for i in range(4)]))
    cases.append(case("A07", True, "spray",
        "Six targeted accounts from one IP in five minutes",
        [auth(f"a07-{i}", user=f"target{i}@example.org",
              ip="203.0.113.51", minute=i) for i in range(6)]))
    cases.append(case("A08", True, "low_and_slow",
        "Six targeted accounts spaced five minutes apart",
        [auth(f"a08-{i}", user=f"slow{i}@example.org",
              ip="203.0.113.52", minute=i * 5) for i in range(6)]))
    cases.append(case("A09", True, "success_after_failure",
        "Five failures followed by success for one identity and IP",
        [auth(f"a09-{i}", user="stolen@example.org",
              ip="198.51.100.21", minute=i) for i in range(5)]
        + [auth("a09-ok", user="stolen@example.org",
                ip="198.51.100.21", outcome="Success", minute=6)]))
    cases.append(case("A10", True, "time_boundary",
        "Five failures, suspicious success after twenty minutes",
        [auth(f"a10-{i}", user="delayed@example.org",
              ip="198.51.100.22", minute=i) for i in range(5)]
        + [auth("a10-ok", user="delayed@example.org",
                ip="198.51.100.22", outcome="Success", minute=24)]))
    cases.append(case("A11", True, "mfa",
        "Four failed MFA prompts followed by authentication",
        [auth(f"a11-{i}", user="mfa@example.org",
              event_type="MFA challenge", minute=i) for i in range(4)]
        + [auth("a11-ok", user="mfa@example.org",
                event_type="MFA completed", outcome="Success", minute=5)]))
    cases.append(case("A12", True, "powershell",
        "Encoded PowerShell execution",
        [proc("a12-1", "powershell.exe -EncodedCommand UwB5AG4AdABoAGUAdABpAGMA")]))
    cases.append(case("B13", False, "benign",
        "Routine interactive PowerShell Get-Process",
        [proc("b13-1", "powershell.exe Get-Process")]))
    cases.append(case("A14", True, "lolbin",
        "Unusual remote mshta execution",
        [proc("a14-1", "mshta.exe https://example.invalid/demo.hta")]))
    cases.append(case("B15", False, "benign",
        "Informational upstream EDR alert metadata",
        [{"Timestamp": when(), "AlertId": "b15",
          "Title": "Sample detection notice", "Severity": "Informational",
          "Category": "Test", "ServiceSource": "MicrosoftDefenderForEndpoint",
          "DetectionSource": "CustomDetection", "DeviceName": "LAB-A",
          "AccountName": "user@example.org"}]))
    cases.append(case("A16", True, "correlation",
        "Failures, success, suspicious process, same user/device",
        [auth(f"a16-{i}", user="finance@example.org",
              ip="198.51.100.91", minute=i, device="FIN-01") for i in range(5)]
        + [auth("a16-ok", user="finance@example.org",
                ip="198.51.100.91", outcome="Success", minute=6, device="FIN-01"),
           proc("a16-p", "powershell.exe -enc UwB5AG4AdABoAGUAdABpAGMA",
                user="finance@example.org", minute=7, device="FIN-01")]))
    cases.append(case("A17", True, "reordering",
        "Five failures and success, reverse raw input ordering",
        list(reversed(
            [auth(f"a17-{i}", user="reverse@example.org", minute=i)
             for i in range(5)]
            + [auth("a17-ok", user="reverse@example.org",
                    outcome="Success", minute=6)]))))
    cases.append(case("B18", False, "duplicates",
        "One failed sign-in duplicated eight times; not eight independent failures",
        [auth("b18-original", user="sync@example.org") for _ in range(8)]))
    cases.append(case("E19", None, "invalid_input",
        "Missing required timestamp tests ingestion failure",
        [{"event_id": "e19-1", "event_type": "SignInFailure",
          "outcome": "Failure", "user": "bad@example.org",
          "source_ip": "192.0.2.55"}]))
    return cases


def safe_div(num, den):
    return num / den if den else None


def evaluate_profile(cases, profile_name):
    config = get_profile(profile_name)
    config.enable_off_hours = False
    cm = dict(TP=0, FP=0, TN=0, FN=0, INVALID=0)
    detail = []
    for item in cases:
        start = time.perf_counter()
        try:
            normalized = normalise_rows(item["events"])
            findings = run_detections(normalized, config)
            detected = bool(findings)
            error = None
        except Exception as exc:
            detected = None
            findings = []
            error = type(exc).__name__ + ": " + str(exc)
        elapsed = time.perf_counter() - start
        expected = item["review_warranted"]
        if detected is None:
            outcome = "INVALID"
        elif expected is None:
            outcome = "UNLABELLED"
        elif expected:
            outcome = "TP" if detected else "FN"
        else:
            outcome = "FP" if detected else "TN"
        if outcome in cm:
            cm[outcome] += 1
        detail.append(dict(id=item["id"], outcome=outcome,
                           predicted_review=detected,
                           rule_ids=sorted({f.rule_id for f in findings}),
                           finding_count=len(findings),
                           error=error, seconds=round(elapsed, 6)))
    tp, fp, tn, fn = (cm[k] for k in ("TP", "FP", "TN", "FN"))
    p, r = safe_div(tp, tp + fp), safe_div(tp, tp + fn)
    f1 = safe_div(2*p*r, p+r) if p is not None and r is not None else None
    return dict(profile=profile_name, confusion=cm, case_precision=p,
                case_recall=r, case_f1=f1, case_false_positive_rate=safe_div(fp, fp+tn),
                cases=detail)


class ResearchStressEvaluation(unittest.TestCase):
    def test_researcher_authored_stress_matrix(self):
        cases = make_cases()
        self.assertEqual(len(cases), 19)
        self.assertEqual(len([x for x in cases if x["review_warranted"] is True]), 9)
        self.assertEqual(len([x for x in cases if x["review_warranted"] is False]), 9)
        results = [evaluate_profile(cases, name) for name in ("learner", "balanced", "strict")]
        for item in results:
            self.assertEqual(item["confusion"]["INVALID"], 1,
                "Unexpected ingestion error in one of the labelled scenarios")
            self.assertEqual(sum(item["confusion"].values()), 19)
        report = {
            "study_type": "researcher-authored adversarial semantic stress suite",
            "not_independent_or_production_performance": True,
            "scenario_count": 19, "labelled_cases": 18,
            "case_definition": "any TriageBloom finding versus researcher-labelled review warranted",
            "python": sys.version.split()[0], "platform": platform.platform(),
            "results": results,
        }
        print("STRESS_REPORT_JSON=" + json.dumps(report, separators=(",", ":"), sort_keys=True))


if __name__ == "__main__":
    unittest.main()
