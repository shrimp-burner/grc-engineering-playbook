import json
import sys
import threading
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from grc_playbook import EXAMPLES, controls, drift, iac, logs, mock_grc_api, ownership, policy, triage
from grc_playbook.grc_api import GrcClient
from grc_playbook.policy import _denies


def test_drift_detects_unmanaged_resource():
    report = drift.run(EXAMPLES / "drift", quiet=True)
    kinds = {(e["resource"], e["kind"]) for e in report["events"]}
    assert ("bucket-dev-scratch", "UNMANAGED") in kinds


def test_drift_attribution_matches_field():
    report = drift.run(EXAMPLES / "drift", quiet=True)
    prod = next(e for e in report["events"] if e["resource"] == "bucket-prod-data")
    # encryption is the highest-severity change -> attributed to the DeleteBucketEncryption actor
    assert prod["attribution"]["identity"] == "ci-deployer"


def test_triage_dedupes():
    report = triage.run(EXAMPLES / "triage", quiet=True)
    assert report["raw"] == 14 and report["deduped"] == 10


def test_policy_flags_full_admin():
    report = policy.run(EXAMPLES, quiet=True)
    assert report["ok"] is False


def test_iac_broken_fails_and_fixed_passes():
    assert iac.run(EXAMPLES / "terraform" / "broken", quiet=True)["ok"] is False
    assert iac.run(EXAMPLES / "terraform" / "fixed", quiet=True)["ok"] is True


def test_policy_credits_service_wildcard_not_bare_star():
    bare = {"Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}]}
    svc = {"Statement": [{"Effect": "Deny", "Action": "cloudtrail:*", "Resource": "*"}]}
    exact = {"Statement": [{"Effect": "Deny", "Action": ["cloudtrail:StopLogging"], "Resource": "*"}]}
    # A bare "*" may be scoped by a condition we do not evaluate, so it is not credited.
    assert _denies(bare, ["cloudtrail:StopLogging"]) is False
    assert _denies(svc, ["cloudtrail:StopLogging"]) is True
    assert _denies(exact, ["cloudtrail:StopLogging"]) is True


def test_policy_does_not_credit_a_conditioned_deny():
    # A deny scoped to one admin role is not org-wide coverage.
    conditioned = {"Statement": [{"Effect": "Deny", "Action": "cloudtrail:StopLogging", "Resource": "*",
                                  "Condition": {"StringEquals": {"aws:PrincipalArn": "arn:aws:iam::1:role/admin"}}}]}
    assert _denies(conditioned, ["cloudtrail:StopLogging"]) is False


def test_ownership_uses_the_earliest_event_as_creator(tmp_path):
    (tmp_path / "assets.json").write_text(json.dumps(
        [{"id": "A", "name": "res", "type": "s3", "account": "1", "owner_team": None, "created_by": "x"}]))
    (tmp_path / "identities.json").write_text(json.dumps({"creator@acme.com": "team-x"}))
    (tmp_path / "cloudtrail.json").write_text(json.dumps([
        {"time": "2025-01-01T00:00:00Z", "identity": "modifier@acme.com", "event": "PutBucketTagging", "resource": "res"},
        {"time": "2024-01-01T00:00:00Z", "identity": "creator@acme.com", "event": "CreateBucket", "resource": "res"},
    ]))
    rep = ownership.run(tmp_path, quiet=True)
    assert rep["proposals"][0]["propose_team"] == "team-x"


def test_logs_detects_tamper_in_an_out_of_order_feed(tmp_path):
    (tmp_path / "cloudtrail-events.json").write_text(json.dumps([
        {"time": "2026-10-06T02:20:00Z", "identity": "svc", "source_ip": "198.51.100.4", "event": "RunInstances", "resource": "i", "outcome": "Allow"},
        {"time": "2026-10-06T02:14:00Z", "identity": "svc", "source_ip": "198.51.100.4", "event": "StopLogging", "resource": "trail", "outcome": "Allow"},
    ]))
    (tmp_path / "log-posture.json").write_text(json.dumps({"org_trail": True}))
    rep = logs.run(tmp_path, quiet=True)
    assert any(sev == "critical" for _, sev, _ in rep["detections"])


def test_controls_run_against_the_nist_csf_2_set():
    report = controls.run(EXAMPLES, quiet=True, controls_file=EXAMPLES / "frameworks" / "nist-csf-2.0.json")
    assert report["summary"]["total"] == 106          # the full CSF 2.0 core
    assert report["summary"]["MANUAL"] >= 1           # non-technical subcategories are attested, not measured
    assert report["summary"]["FAIL"] >= 1             # the sample data has real gaps, by design


def test_crosswalk_maps_one_control_to_many_frameworks():
    controls = json.loads((EXAMPLES / "controls.json").read_text())["controls"]
    mapped = [c for c in controls if c.get("mappings")]
    assert mapped, "expected crosswalk mappings on the canonical controls"
    frameworks = {m["framework"] for c in mapped for m in c["mappings"]}
    assert {"SOC2", "ISO27001", "NIST-CSF-2.0"} <= frameworks


def test_nist_measured_reuses_canonical_controls():
    nist = json.loads((EXAMPLES / "frameworks" / "nist-csf-2.0.json").read_text())["controls"]
    controls = {c["id"]: c for c in json.loads((EXAMPLES / "controls.json").read_text())["controls"]}
    uses = [c for c in nist if c.get("uses")]
    assert uses, "expected some NIST subcategories to reuse a canonical control"
    # a `uses` control must not also re-declare its own conditions (that would drift)
    assert not any("conditions" in c for c in uses)
    for c in uses:
        # the target must exist, and it must actually map this subcategory, or the
        # "cannot drift" claim is false
        assert c["uses"] in controls, "uses target {0} does not exist".format(c["uses"])
        mapped = [m["ref"] for m in controls[c["uses"]].get("mappings", [])
                  if m["framework"] == "NIST-CSF-2.0"]
        assert c["ref"] in mapped, "{0} uses {1} but {1} does not map {0}".format(c["ref"], c["uses"])


def test_client_paginates_the_mock_api():
    server = mock_grc_api.create_server(0)
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        client = GrcClient("http://127.0.0.1:{0}".format(port), mock_grc_api.TOKEN, verbose=False)
        assert len(client.get_controls()) == len(mock_grc_api.CONTROLS)
        assert len(client.get_findings()) == len(mock_grc_api.FINDINGS)
    finally:
        server.shutdown()
