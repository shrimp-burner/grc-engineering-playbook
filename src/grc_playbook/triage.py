"""Turn a noisy scanner dump into an owned, prioritized queue.

Pipeline: dedupe (across scanners) -> score (exploitability, not scanner default)
-> route (owner tag; untagged is itself a finding) -> SLA/escalation.
"""
from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path

SEV_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}
ESCALATE_TYPES = {"S3.2", "s3_bucket_public_access", "EC2.13", "ec2_sg_open_ssh", "sharing_external", "admin_no_mfa"}
REGULATED_RESOURCES = {"rds-prod-orders", "acme-prod-data"}
SLA_DAYS = 30

# Map the same underlying issue as reported by different scanners onto one class,
# so dedupe merges aliases but keeps genuinely distinct findings apart.
CANONICAL = {
    "S3.2": "s3_public", "s3_bucket_public_access": "s3_public",
    "EC2.13": "sg_open_ssh", "ec2_sg_open_ssh": "sg_open_ssh",
    "RDS.3": "rds_unencrypted", "rds_encryption": "rds_unencrypted",
    "S3.9": "s3_no_logging", "s3_access_logging": "s3_no_logging",
}


def _class(f):
    return CANONICAL.get(f["type"], f["type"].lower())


def _dedupe(findings):
    groups = defaultdict(list)
    for f in findings:
        groups[(f["resource"], _class(f))].append(f)
    merged = []
    for items in groups.values():
        best = max(items, key=lambda x: SEV_RANK[x["severity"]])
        best = dict(best)
        best["sources"] = sorted({i["source"] for i in items})
        best["duplicate_count"] = len(items)
        merged.append(best)
    return merged


def _score(f):
    sev = SEV_RANK[f["severity"]]
    if f["type"] in ESCALATE_TYPES:
        sev = min(4, sev + 1)
    if f["resource"] in REGULATED_RESOURCES and sev < 4:
        sev = min(4, sev + 1)
    rank_to_sev = {v: k for k, v in SEV_RANK.items()}
    f = dict(f)
    f["scored_severity"] = rank_to_sev[sev]
    return f


def _route(f, owners=None):
    f = dict(f)
    f["assignee"] = f.get("owner") or "UNASSIGNED"
    f["escalate"] = f["age_days"] > SLA_DAYS
    f["escalate_to"] = (owners or {}).get(f["assignee"], {}).get("manager") if f["escalate"] else None
    return f


def run(data_dir: Path, min_severity="low", quiet=False):
    raw = json.loads((data_dir / "findings.json").read_text())
    owners = {}
    owners_file = data_dir / "owners.json"
    if owners_file.exists():
        owners = json.loads(owners_file.read_text())
    merged = [_route(_score(f), owners) for f in _dedupe(raw)]
    floor = SEV_RANK[min_severity]
    actionable = [f for f in merged if SEV_RANK[f["scored_severity"]] >= floor]
    actionable.sort(key=lambda f: (-SEV_RANK[f["scored_severity"]], -f["age_days"]))

    if not quiet:
        print("=" * 74)
        print("MISCONFIGURATION TRIAGE")
        print("=" * 74)
        print("raw findings: {0} -> after dedupe: {1} -> actionable: {2}".format(len(raw), len(merged), len(actionable)))
        print("untagged / unowned: {0} (a finding in itself)".format(sum(1 for f in merged if f["assignee"] == "UNASSIGNED")))
        print("-" * 74)
        for f in actionable:
            flags = []
            if len(f["sources"]) > 1:
                flags.append("dup x{0}".format(f["duplicate_count"]))
            if f["escalate"]:
                target = " -> " + f["escalate_to"] if f.get("escalate_to") else ""
                flags.append("SLA>{0}d{1}".format(SLA_DAYS, target))
            if f["scored_severity"] != f["severity"]:
                flags.append("escalated {0}=>{1}".format(f["severity"], f["scored_severity"]))
            print("[{0:<8}] {1:<22} {2:<22} owner={3:<12} age={4:<3} {5}".format(
                f["scored_severity"].upper(), f["type"], f["resource"], f["assignee"], f["age_days"],
                ("(" + ", ".join(flags) + ")") if flags else ""))
        print("-" * 74)
        print("by owner:")
        by_owner = defaultdict(int)
        for f in actionable:
            by_owner[f["assignee"]] += 1
        for owner, n in sorted(by_owner.items(), key=lambda x: -x[1]):
            print("   {0:<14} {1}".format(owner, n))

    return {"raw": len(raw), "deduped": len(merged), "actionable": actionable}


if __name__ == "__main__":
    from grc_playbook import EXAMPLES
    run(EXAMPLES / "triage")
