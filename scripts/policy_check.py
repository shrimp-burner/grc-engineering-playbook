#!/usr/bin/env python3
"""CI policy gate. Asserts that the enforcement modules behave the way they claim.

The bundled examples deliberately contain one insecure IAM policy and one insecure
Terraform stack. So the correct behavior here is that the linters FLAG them. This
script exits non-zero only if a gate fails to behave, not if it finds a problem.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from grc_playbook import EXAMPLES, iac, policy


def main():
    broken = iac.run(EXAMPLES / "terraform" / "broken", quiet=True)
    fixed = iac.run(EXAMPLES / "terraform" / "fixed", quiet=True)
    pol = policy.run(EXAMPLES, quiet=True)

    checks = {
        "insecure Terraform is rejected": broken["ok"] is False,
        "remediated Terraform is clean": fixed["ok"] is True,
        "insecure IAM policy is flagged": pol["ok"] is False,
    }
    for name, ok in checks.items():
        print("  [{0}] {1}".format("ok" if ok else "FAIL", name))

    failed = [n for n, ok in checks.items() if not ok]
    if failed:
        print("policy gate misbehaved: " + "; ".join(failed))
        return 1
    print("policy gates behaved as expected")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
