"""Ownership attribution audit.

Unowned risk cannot be fixed, so this reports tag coverage, infers an owner from
the CloudTrail creator for untagged resources, and produces a remediation queue
(propose tags for confident cases, flag uncertain ones for review).
"""
from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path


def run(data_dir: Path, quiet=False):
    assets = json.loads((data_dir / "assets.json").read_text())
    identities = json.loads((data_dir / "identities.json").read_text())
    cloudtrail = json.loads((data_dir / "cloudtrail.json").read_text())

    total = len(assets)
    owned = [a for a in assets if a.get("owner_team")]
    unowned = [a for a in assets if not a.get("owner_team")]
    coverage = round(len(owned) * 100.0 / total, 1) if total else 0.0

    # The creator is the earliest event on a resource, not the latest. Using the
    # latest is recency attribution, which is what D5 warns against.
    creator_by_res = {}
    for c in cloudtrail:
        r = c["resource"]
        if r not in creator_by_res or c["time"] < creator_by_res[r]["time"]:
            creator_by_res[r] = c
    creator_identity = {r: c["identity"] for r, c in creator_by_res.items()}

    proposals = []
    for a in unowned:
        creator = creator_identity.get(a["name"], a.get("created_by", "?"))
        inferred = identities.get(creator)
        proposals.append({"name": a["name"], "propose_team": inferred, "created_by": creator})

    if not quiet:
        print("=" * 74)
        print("OWNERSHIP ATTRIBUTION AUDIT")
        print("=" * 74)
        print("coverage: {0}/{1} resources owned ({2:.1f}%)".format(len(owned), total, coverage))
        print("-" * 74)
        print("COVERAGE BY ACCOUNT")
        by_acct = defaultdict(lambda: [0, 0])
        for a in assets:
            by_acct[a["account"]][0] += 1
            if a.get("owner_team"):
                by_acct[a["account"]][1] += 1
        for acct, (n, o) in sorted(by_acct.items()):
            print("   {0:<16} {1}/{2}".format(acct, o, n))
        print("\nUNOWNED RESOURCES (remediation queue)")
        for p in proposals:
            propose = p["propose_team"] or "UNKNOWN - human review"
            print("   {0:<20} created_by={1:<18} -> propose team={2}".format(p["name"], p["created_by"], propose))
        print("-" * 74)
        print("{0} unowned; {1} could not be inferred and need human review".format(
            len(unowned), sum(1 for p in proposals if not p["propose_team"])))

    return {"coverage_pct": coverage, "unowned": unowned, "proposals": proposals}


if __name__ == "__main__":
    from grc_playbook import EXAMPLES
    run(EXAMPLES / "ownership")
