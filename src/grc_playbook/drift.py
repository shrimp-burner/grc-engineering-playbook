"""Detect drift between live state and an approved baseline, and attribute it.

Three kinds of drift:
  CHANGED    a field differs from baseline (manual / IaC / config drift)
  UNMANAGED  a resource exists that is not in the baseline (created out of band)
  DELETED    a baseline resource is gone

Drift is classified by blast radius and attributed to the CloudTrail event whose
action maps to the drifted field (naive "latest event" mis-attributes).
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

FIELD_SEVERITY = {
    "ingress": "critical", "public": "critical",
    "encryption": "high", "policy_actions": "high", "mfa_required": "high",
    "versioning": "medium", "logging": "medium",
    "tags": "low", "environment": "low", "owner": "low",
}
SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}
ACTION_FIELD = {
    "AuthorizeSecurityGroupIngress": "ingress", "RevokeSecurityGroupIngress": "ingress",
    "DeleteBucketEncryption": "encryption", "PutBucketEncryption": "encryption",
    "PutRolePolicy": "policy_actions", "UpdateAssumeRolePolicy": "policy_actions",
    "CreateTags": "tags", "DeleteTags": "tags", "PutBucketVersioning": "versioning",
}


def _classify(field):
    return FIELD_SEVERITY.get(field, "medium")


def _attribute(cloudtrail, resource, primary_field=None):
    hits = [e for e in cloudtrail if e.get("resource") == resource]
    if not hits:
        return None
    if primary_field:
        matching = [e for e in hits if ACTION_FIELD.get(e.get("action")) == primary_field]
        if matching:
            return sorted(matching, key=lambda e: e["time"])[-1]
    return sorted(hits, key=lambda e: e["time"])[-1]


def _diff_resource(base, cur):
    drifts = []
    for k in set(base) | set(cur):
        if k == "type":
            continue
        b, c = base.get(k), cur.get(k)
        if b != c:
            drifts.append({"field": k, "from": b, "to": c, "severity": _classify(k)})
    return drifts


def run(data_dir: Path, severity=None, quiet=False):
    baseline = json.loads((data_dir / "baseline.json").read_text())
    current = json.loads((data_dir / "current.json").read_text())
    cloudtrail = json.loads((data_dir / "cloudtrail.json").read_text())
    baseline.pop("_comment", None)
    current.pop("_comment", None)

    events = []
    for rid in sorted(set(baseline) | set(current)):
        if rid in baseline and rid not in current:
            events.append({"resource": rid, "kind": "DELETED", "severity": "high",
                           "changes": ["resource present in baseline but missing now"],
                           "attribution": _attribute(cloudtrail, rid)})
            continue
        if rid not in baseline and rid in current:
            events.append({"resource": rid, "kind": "UNMANAGED", "severity": "high",
                           "changes": ["resource exists but is not in the approved baseline"],
                           "attribution": _attribute(cloudtrail, rid)})
            continue
        drifts = _diff_resource(baseline[rid], current[rid])
        if drifts:
            changes = ["{0}: {1!r} -> {2!r} ({3})".format(d["field"], d["from"], d["to"], d["severity"]) for d in drifts]
            worst = max((d["severity"] for d in drifts), key=lambda s: SEVERITY_RANK[s])
            worst_field = max(drifts, key=lambda d: SEVERITY_RANK[d["severity"]])["field"]
            events.append({"resource": rid, "kind": "CHANGED", "severity": worst,
                           "changes": changes, "attribution": _attribute(cloudtrail, rid, worst_field)})

    if severity:
        floor = SEVERITY_RANK[severity]
        events = [e for e in events if SEVERITY_RANK[e["severity"]] >= floor]

    if not quiet:
        print("=" * 70)
        print("CONTROL DRIFT REPORT  " + datetime.now(timezone.utc).isoformat(timespec="seconds"))
        print("=" * 70)
        if not events:
            print("no drift detected (above the given severity floor)")
        for e in sorted(events, key=lambda x: -SEVERITY_RANK[x["severity"]]):
            print("[{0:<8}] {1:<20} {2}".format(e["severity"].upper(), e["resource"], e["kind"]))
            for ch in e["changes"]:
                print("           - " + ch)
            a = e["attribution"]
            if a:
                print("           attributed to: {0} via {1} at {2} ({3})".format(a["identity"], a["source"], a["time"], a["action"]))
                print("           detail: " + a["detail"])
            else:
                print("           attributed to: (no CloudTrail event found)")
            print("           action: " + ("OPEN TICKET" if e["severity"] in ("critical", "high") else "AUTO-REVERT (cosmetic) + notify"))
        print("-" * 70)

    return {"generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"), "events": events}


if __name__ == "__main__":
    from grc_playbook import EXAMPLES
    run(EXAMPLES / "drift")
