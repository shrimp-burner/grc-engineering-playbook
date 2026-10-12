"""Detect log tampering and audit log-protection posture.

Detects the signature attack: StopLogging followed by suspicious activity from the
same identity within a window. Also audits whether log-protection is actually
configured (Object Lock, log file validation, central account, tamper SCPs).
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

SUSPICIOUS = {"RunInstances", "CreateAccessKey", "PutBucketPolicy", "DeleteTrail", "UpdateTrail", "AuthorizeSecurityGroupIngress"}
TAMPER_EVENTS = {"DeleteTrail", "UpdateTrail"}
TAMPER_WINDOW_MIN = 30

POSTURE_REQUIREMENTS = {
    "org_trail": "Organization-wide trail exists",
    "multi_region": "Trail is multi-region",
    "log_file_validation": "Log file validation enabled (detects tampering)",
    "centralized_log_account": "Logs go to a dedicated security account",
    "kms_encrypted": "Logs encrypted with KMS",
    "object_lock_enabled": "S3 Object Lock (WORM) on the log bucket",
    "versioning": "Log bucket versioning enabled",
    "scp_protect_logs_attached": "SCP denying CloudTrail/log tampering is attached",
    "root_mfa_enabled": "Root account MFA enabled",
}


def _parse(t):
    return datetime.fromisoformat(t.replace("Z", "+00:00"))


def run(data_dir: Path, quiet=False):
    events = sorted(json.loads((data_dir / "cloudtrail-events.json").read_text()),
                    key=lambda e: e["time"])
    posture = json.loads((data_dir / "log-posture.json").read_text())
    findings = []

    for key, label in POSTURE_REQUIREMENTS.items():
        if not posture.get(key, False):
            findings.append(("POSTURE", "gap", label + " is MISSING"))

    for i, e in enumerate(events):
        if e["event"] == "StopLogging":
            t0 = _parse(e["time"])
            follow = [x for x in events[i + 1:]
                      if x["identity"] == e["identity"]
                      and (_parse(x["time"]) - t0).total_seconds() / 60 <= TAMPER_WINDOW_MIN
                      and x["event"] in SUSPICIOUS]
            if follow:
                kinds = ", ".join(sorted({x["event"] for x in follow}))
                findings.append(("TAMPER", "critical",
                                 "{0} stopped logging for {1}, then performed {2} within {3} min - LOG TAMPERING".format(
                                     e["identity"], e["resource"], kinds, TAMPER_WINDOW_MIN)))

    for e in events:
        if e["event"] in TAMPER_EVENTS:
            findings.append(("TAMPER", "high" if e["outcome"] == "Allow" else "medium",
                             "{0} {1} on {2} from {3}".format(e["identity"], e["event"], e["resource"], e["source_ip"])))
        if e["event"] == "PutBucketPolicy" and "logs" in e["resource"]:
            findings.append(("TAMPER", "critical", "log bucket policy changed by {0} from {1} - possible tamper".format(e["identity"], e["source_ip"])))

    gaps = [f for f in findings if f[0] == "POSTURE"]
    dets = [f for f in findings if f[0] == "TAMPER"]
    if not quiet:
        print("=" * 74)
        print("SECURITY LOG GUARD  " + datetime.now(timezone.utc).isoformat(timespec="seconds"))
        print("=" * 74)
        print("POSTURE")
        if not gaps:
            print("  [OK] all log-protection controls in place")
        for _, _, msg in gaps:
            print("  [GAP] " + msg)
        print("\nDETECTIONS")
        if not dets:
            print("  none")
        for _, sev, msg in sorted(dets, key=lambda x: x[1] != "critical"):
            print("  [{0:<6}] {1}".format(sev.upper(), msg))
        print("-" * 74)
        print("summary: {0} posture gap(s), {1} detection(s)".format(len(gaps), len(dets)))

    return {"posture_gaps": gaps, "detections": dets}


if __name__ == "__main__":
    from grc_playbook import EXAMPLES
    run(EXAMPLES / "logs")
