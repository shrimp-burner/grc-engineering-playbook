"""grc-playbook CLI: run each module, the full demo, or the narrated test case."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from grc_playbook import EXAMPLES
from grc_playbook import controls, drift, iac, logs, ownership, policy, triage

MODULES = {
    "drift": lambda d: drift.run(d / "drift"),
    "triage": lambda d: triage.run(d / "triage"),
    "logs": lambda d: logs.run(d / "logs"),
    "ownership": lambda d: ownership.run(d / "ownership"),
    "policy": lambda d: policy.run(d),
}


def _banner(title):
    print("\n" + "#" * 70)
    print("# " + title)
    print("#" * 70)


def _crosswalk():
    controls = json.loads((EXAMPLES / "controls.json").read_text())["controls"]
    frameworks, refs = set(), 0
    print("CONTROL CROSSWALK  (one evaluation -> many frameworks)")
    print("-" * 68)
    for c in controls:
        maps = c.get("mappings") or [{"framework": c.get("framework"), "ref": c.get("ref")}]
        refs += len(maps)
        for m in maps:
            frameworks.add(m["framework"])
        print("{0:<12} {1}".format(c["id"], "  |  ".join("{0} {1}".format(m["framework"], m["ref"]) for m in maps)))
    print("-" * 68)
    print("{0} controls -> {1} framework refs across {2} frameworks".format(len(controls), refs, len(frameworks)))
    print("The engine evaluates each control once; every mapped framework ref inherits the result.")


def _list_frameworks():
    print("bundled control sets:")
    print("  examples/controls.json               SOC 2 / ISO 27001")
    d = EXAMPLES / "frameworks"
    if d.exists():
        for p in sorted(d.glob("*.json")):
            print("  examples/frameworks/{0}".format(p.name))


def cmd_demo(args):
    _banner("Controls engine")
    controls.run(EXAMPLES)
    _banner("Drift detection")
    drift.run(EXAMPLES / "drift")
    _banner("Misconfiguration triage")
    triage.run(EXAMPLES / "triage")
    _banner("Security-log guard")
    logs.run(EXAMPLES / "logs")
    _banner("Ownership attribution")
    ownership.run(EXAMPLES / "ownership")
    _banner("Policy-as-code (SCP + IAM)")
    policy.run(EXAMPLES)
    _banner("IaC security review (broken Terraform)")
    iac.run(EXAMPLES / "terraform" / "broken")
    _banner("IaC security review (fixed Terraform)")
    iac.run(EXAMPLES / "terraform" / "fixed")


def main(argv=None):
    ap = argparse.ArgumentParser(prog="grc-playbook",
                                 description="Reference implementations for continuous compliance automation on AWS.")
    sub = ap.add_subparsers(dest="cmd")

    for name in ["demo", "scenario", *[m for m in MODULES if m != "controls"]]:
        sub.add_parser(name, help="run the {0}".format(name))

    p_ctrl = sub.add_parser("controls", help="evaluate a control set")
    p_ctrl.add_argument("--controls", default=None, help="path to a controls JSON (default: examples/controls.json)")
    p_ctrl.add_argument("--framework", default=None, help="a set from examples/frameworks, e.g. nist-csf-2.0")
    p_ctrl.add_argument("--control", default=None, help="evaluate a single control id")
    p_ctrl.add_argument("--evidence", default=None, help="evidence directory (default: examples/evidence)")

    sub.add_parser("frameworks", help="list bundled control sets")
    sub.add_parser("crosswalk", help="show how one control maps across frameworks")

    p_iac = sub.add_parser("iac", help="scan a Terraform directory")
    p_iac.add_argument("target", nargs="?", default=str(EXAMPLES / "terraform" / "broken"))

    p_wh = sub.add_parser("webhook", help="run the webhook receiver")
    p_wh.add_argument("--port", type=int, default=8765)

    p_mock = sub.add_parser("mock-api", help="run the mock GRC product API")
    p_mock.add_argument("--port", type=int, default=8770)

    args = ap.parse_args(argv)

    if args.cmd == "demo":
        cmd_demo(args)
    elif args.cmd == "scenario":
        from grc_playbook import scenario
        scenario.run()
    elif args.cmd == "controls":
        controls_file = None
        if args.framework:
            controls_file = EXAMPLES / "frameworks" / (args.framework + ".json")
            if not controls_file.exists():
                print("unknown framework: {0}".format(args.framework))
                return 2
        elif args.controls:
            controls_file = Path(args.controls)
        result = controls.run(EXAMPLES, control_id=args.control, controls_file=controls_file, evidence_dir=args.evidence)
        if result["summary"]["FAIL"] or result["summary"]["ERROR"]:
            return 1
    elif args.cmd == "frameworks":
        _list_frameworks()
    elif args.cmd == "crosswalk":
        _crosswalk()
    elif args.cmd in MODULES:
        result = MODULES[args.cmd](EXAMPLES)
        if isinstance(result, dict) and result.get("ok") is False:
            return 1
    elif args.cmd == "iac":
        rc = iac.run(Path(args.target))
        return 0 if rc["ok"] else 1
    elif args.cmd == "webhook":
        from grc_playbook import webhook
        webhook.serve(args.port, workdir=Path.cwd())
    elif args.cmd == "mock-api":
        from grc_playbook import mock_grc_api
        mock_grc_api.serve(args.port)
    else:
        ap.print_help()
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
