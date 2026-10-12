"""A narrated, self-contained test case: one finding, start to finish.

    python -m grc_playbook scenario

Runs against a throwaway copy of the examples, so nothing on disk changes.
"""
from __future__ import annotations

import json
import shutil
import tempfile
from pathlib import Path

from grc_playbook import EXAMPLES, controls, drift


def _rule(title):
    print("\n" + title)
    print("-" * len(title))


def _control(data: Path, control_id: str):
    definition = next(c for c in json.loads((data / "controls.json").read_text())["controls"]
                      if c["id"] == control_id)
    return controls.evaluate_control(definition, data / "evidence")


def run(source: Path = EXAMPLES):
    tmp = Path(tempfile.mkdtemp(prefix="grc-scenario-"))
    data = tmp / "data"
    shutil.copytree(source, data)

    print("=" * 68)
    print("SCENARIO - one finding, start to finish")
    print("=" * 68)
    print("A rule says: every S3 bucket must be encrypted. A bucket that was")
    print("encrypted yesterday is not, today. Walk it from detection to fix.")

    _rule("1. Detect - the control fails")
    r = _control(data, "GR-S3-001")
    print("[{0}] GR-S3-001  {1}".format(r["status"], r["title"]))
    for f in r["findings"]:
        print("         resource: {0} (account {1})".format(f["resource"], f["account"]))
        for fail in f["failures"]:
            print("            - " + fail["detail"])

    _rule("2. Attribute - who changed it")
    report = drift.run(data / "drift", quiet=True)
    ev = next((e for e in report["events"] if e["resource"] == "bucket-prod-data"), None)
    if ev:
        a = ev.get("attribution") or {}
        print("drift: {0}".format("; ".join(ev["changes"])))
        print("attributed to: {0} via {1} ({2})".format(a.get("identity"), a.get("source"), a.get("action")))
    print("-> drift is a change from baseline; the control is the current state.")
    print("   This is both: the bucket moved, and it now violates the rule.")

    _rule("3. Fix - turn encryption back on")
    buckets = json.loads((data / "evidence" / "s3_buckets.json").read_text())
    for b in buckets:
        if b["name"] == "bucket-prod-data":
            b["encryption"] = {"enabled": True, "type": "aws:kms"}
    (data / "evidence" / "s3_buckets.json").write_text(json.dumps(buckets, indent=2))
    print("set bucket-prod-data encryption.enabled = true")
    print("(in production this is a Terraform change, reviewed, then applied)")

    _rule("4. Verify - re-evaluate")
    r2 = _control(data, "GR-S3-001")
    print("[{0}] GR-S3-001  {1}".format(r2["status"], r2["title"]))
    if not r2["findings"]:
        print("         all in-scope buckets now encrypted")

    _rule("Done")
    print("detected -> attributed -> fixed -> verified, against the same evidence model.")
    print("nothing on disk changed: this ran on a throwaway copy, now removed.")
    print("=" * 68)
    shutil.rmtree(tmp, ignore_errors=True)
    return {"fixed": r2["status"] == "PASS"}


if __name__ == "__main__":
    run()
