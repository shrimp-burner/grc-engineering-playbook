"""Check SCP coverage and dangerous IAM allows before a change merges.

IAM policies are checked individually for dangerous wildcards. SCPs are checked
for coverage across the whole set: org guardrails are deliberately spread across
multiple SCPs, so it is the union that must cover every required guardrail.
Exits non-zero when an IAM policy is dangerous or a guardrail is uncovered.
"""
from __future__ import annotations

import fnmatch
import json
from pathlib import Path


def _actions(stmt):
    a = stmt.get("Action", [])
    return a if isinstance(a, list) else [a]


def _resources(stmt):
    r = stmt.get("Resource", [])
    return r if isinstance(r, list) else [r]


def _is_scp(doc):
    # Heuristic: an all-Deny document is treated as an SCP. A legitimate identity
    # policy that happens to be all-Deny would be linted as an SCP instead.
    stmts = doc.get("Statement", [])
    return bool(stmts) and all(s.get("Effect") == "Deny" for s in stmts)


def _denies(doc, actions):
    # Only UNCONDITIONAL denies are credited. A deny scoped by a condition (a
    # specific principal, an org boundary, MFA) does not cover everyone, and this
    # linter does not evaluate conditions, so it errs toward not crediting.
    for s in doc.get("Statement", []):
        if s.get("Effect") != "Deny" or s.get("Condition"):
            continue
        for pattern in _actions(s):
            if not isinstance(pattern, str) or pattern.strip() == "*":
                continue
            p = pattern.lower()
            for want in actions:
                if fnmatch.fnmatch(want.lower(), p):
                    return True
    return False


def _bounds_org(doc):
    # Deny sts:AssumeRole when the caller is NOT in the org (StringNotEquals on
    # aws:PrincipalOrgID). The operator matters: StringEquals would deny inside the
    # org, the opposite intent.
    for s in doc.get("Statement", []):
        if s.get("Effect") != "Deny":
            continue
        cond = json.dumps(s.get("Condition", {}))
        action = json.dumps(s.get("Action", ""))
        if "PrincipalOrgID" in cond and "StringNotEquals" in cond and "sts:AssumeRole" in action:
            return True
    return False


GUARDRAILS = {
    "Protect CloudTrail (StopLogging/DeleteTrail/UpdateTrail)":
        lambda d: _denies(d, ["cloudtrail:StopLogging", "cloudtrail:DeleteTrail", "cloudtrail:UpdateTrail"]),
    "Protect log groups (logs:DeleteLogGroup/DeleteLogStream)":
        lambda d: _denies(d, ["logs:DeleteLogGroup", "logs:DeleteLogStream"]),
    "Bound the org (sts:AssumeRole denied outside aws:PrincipalOrgID)":
        lambda d: _bounds_org(d),
    "Protect KMS keys (no disable/schedule-delete)":
        lambda d: _denies(d, ["kms:ScheduleKeyDeletion", "kms:DisableKey"]),
    "Lock down root without MFA":
        lambda d: any(s.get("Effect") == "Deny"
                      and "MultiFactorAuthPresent" in json.dumps(s.get("Condition", {}))
                      and "BoolIfExists" in json.dumps(s.get("Condition", {}))
                      for s in d.get("Statement", [])),
}


def _iam_findings(doc):
    bad = []
    for s in doc.get("Statement", []):
        if s.get("Effect") != "Allow":
            continue
        acts, res = _actions(s), _resources(s)
        if "*" in acts and "*" in res:
            bad.append('full admin ("*" on "*")')
        elif ("iam:*" in acts or "*" in acts) and "*" in res:
            bad.append("wildcard iam on all resources")
    return bad


def run(data_dir: Path, quiet=False):
    docs = [(f.name, json.loads(f.read_text())) for f in sorted((data_dir / "policies").glob("*.json"))]
    scps = [(n, d) for n, d in docs if _is_scp(d)]
    iams = [(n, d) for n, d in docs if not _is_scp(d)]

    failed = 0
    lines = []
    lines.append("=" * 72)
    lines.append("POLICY LINT  (IAM dangerous-allows + SCP org coverage)")
    lines.append("=" * 72)
    lines.append("")
    lines.append("IAM POLICIES (checked individually)")
    for name, d in iams:
        bad = _iam_findings(d)
        if bad:
            failed += 1
            lines.append("  [FAIL] {0} -> {1}".format(name, "; ".join(bad)))
        else:
            lines.append("  [PASS] " + name)
    lines.append("")
    lines.append("SCP COVERAGE (evaluated across ALL attached SCPs)")
    for guard, fn in GUARDRAILS.items():
        covering = [name for name, d in scps if fn(d)]
        if covering:
            lines.append("  [x] {0}  <- {1}".format(guard, ", ".join(covering)))
        else:
            failed += 1
            lines.append("  [ ] {0}  <- GAP (no SCP covers this)".format(guard))
    lines.append("")
    lines.append("{0} issue(s) found -> CI would BLOCK the merge".format(failed) if failed
                 else "all policies pass and all org guardrails are covered")

    if not quiet:
        print("\n".join(lines))
    return {"ok": failed == 0, "findings": failed}


if __name__ == "__main__":
    from grc_playbook import EXAMPLES
    raise SystemExit(0 if run(EXAMPLES)["ok"] else 1)
