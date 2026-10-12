"""Scan Terraform for missing security controls. The idea behind checkov/tfsec, small enough to read.

Scans *.tf in a target directory for required security constructs and prints the
recommended fix. run() returns a result dict; the CLI exits non-zero when findings
exist, so it can gate CI.
"""
from __future__ import annotations

import re
from pathlib import Path

CHECKS = [
    ("S3 bucket has server-side encryption",
     lambda s: "aws_s3_bucket_server_side_encryption_configuration" in s,
     "add aws_s3_bucket_server_side_encryption_configuration with aws:kms"),
    ("S3 bucket blocks all public access",
     lambda s: "aws_s3_bucket_public_access_block" in s,
     "add aws_s3_bucket_public_access_block with all four = true"),
    ("S3 bucket has versioning enabled",
     lambda s: "aws_s3_bucket_versioning" in s,
     "add aws_s3_bucket_versioning = Enabled"),
    ("No security group open to the internet on 22/3389",
     lambda s: not (("0.0.0.0/0" in s or "::/0" in s) and re.search(r"from_port\s*=\s*(?:22|3389)(?!\d)", s)),
     "restrict cidr_blocks to the VPN/internal range, and cover IPv6"),
    ("RDS encrypted at rest",
     lambda s: bool(re.search(r"storage_encrypted\s*=\s*true", s)),
     "set storage_encrypted = true"),
    ("RDS not publicly accessible",
     lambda s: ("publicly_accessible = false" in s or "publicly_accessible = true" not in s),
     "set publicly_accessible = false"),
    ("No inline secret",
     lambda s: not re.search(r'password\s*=\s*"', s),
     "use a variable / Secrets Manager, never inline"),
    ('No IAM policy with a bare wildcard action',
     lambda s: not re.search(r'Action\s*=\s*"\*"', s),
     "scope actions and resources; no full-admin"),
    ("EBS volumes encrypted (if any)",
     lambda s: ("aws_ebs_volume" not in s) or ("encrypted" in s),
     "set encrypted = true and enable ebs_encryption_by_default"),
]


def scan(target_dir: Path):
    text = "\n".join(p.read_text(encoding="utf-8") for p in sorted(Path(target_dir).glob("*.tf")))
    results = []
    for title, fn, fix in CHECKS:
        try:
            ok = fn(text)
        except Exception:  # noqa: BLE001
            ok = False
        results.append((title, ok, fix))
    return results


def run(target_dir: Path, quiet=False):
    results = scan(target_dir)
    failed = 0
    lines = ["=" * 72, "TERRAFORM SECURITY REVIEW: {0}".format(target_dir), "=" * 72]
    for title, ok, fix in results:
        lines.append("  [{0}] {1}".format("PASS" if ok else "FAIL", title))
        if not ok:
            failed += 1
            lines.append("        fix: " + fix)
    lines.append("-" * 72)
    lines.append("{0} finding(s)".format(failed) if failed else "clean - no findings")
    if not quiet:
        print("\n".join(lines))
    return {"ok": failed == 0, "findings": failed}


if __name__ == "__main__":
    import sys
    from grc_playbook import EXAMPLES
    target = Path(sys.argv[1]) if len(sys.argv) > 1 else EXAMPLES / "terraform" / "broken"
    raise SystemExit(0 if run(target)["ok"] else 1)
