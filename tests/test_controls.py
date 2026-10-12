import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from grc_playbook import controls


def _control(resource, conditions):
    return {"id": "T-1", "title": "test", "framework": "SOC2", "severity": "low",
            "resource": resource, "filters": [], "conditions": conditions}


def test_missing_evidence_is_error(tmp_path):
    r = controls.evaluate_control(_control("nope", []), tmp_path)
    assert r["status"] == "ERROR"


def test_empty_evidence_file_is_a_collection_failure(tmp_path):
    (tmp_path / "things.json").write_text("[]")
    r = controls.evaluate_control(_control("things", [{"path": "ok", "op": "eq", "value": True}]), tmp_path)
    assert r["status"] == "ERROR"
    assert any("empty" in n for n in r["notes"])


def test_malformed_evidence_is_error_not_a_crash(tmp_path):
    (tmp_path / "things.json").write_text("{not json")
    r = controls.evaluate_control(_control("things", []), tmp_path)
    assert r["status"] == "ERROR"
    assert any("valid JSON" in n for n in r["notes"])


def test_empty_scope_is_vacuous_pass(tmp_path):
    # The file has resources; the control's scope matches none of them.
    (tmp_path / "things.json").write_text('[{"name": "a", "ok": true}]')
    c = _control("things", [{"path": "ok", "op": "eq", "value": True}])
    c["filters"] = [{"path": "name", "op": "eq", "value": "b"}]
    r = controls.evaluate_control(c, tmp_path)
    assert r["status"] == "PASS"
    assert any("vacuous" in n for n in r["notes"])


def test_condition_fail(tmp_path):
    (tmp_path / "things.json").write_text('[{"name": "a", "encrypted": false}]')
    r = controls.evaluate_control(_control("things", [{"path": "encrypted", "op": "eq", "value": True}]), tmp_path)
    assert r["status"] == "FAIL"
    assert r["findings"][0]["resource"] == "a"


def test_condition_pass(tmp_path):
    (tmp_path / "things.json").write_text('[{"name": "a", "encrypted": true}]')
    r = controls.evaluate_control(_control("things", [{"path": "encrypted", "op": "eq", "value": True}]), tmp_path)
    assert r["status"] == "PASS"


def test_eq_is_type_strict_for_booleans(tmp_path):
    # 1 != true: a scalar that merely looks truthy must not satisfy a boolean control.
    (tmp_path / "things.json").write_text('[{"name": "a", "enabled": 1}]')
    r = controls.evaluate_control(_control("things", [{"path": "enabled", "op": "eq", "value": True}]), tmp_path)
    assert r["status"] == "FAIL"


def test_max_field_lt(tmp_path):
    (tmp_path / "users.json").write_text('[{"name": "u", "keys": [{"age_days": 412}]}]')
    r = controls.evaluate_control(
        _control("users", [{"op": "max_field_lt", "path": "keys", "field": "age_days", "value": 90}]), tmp_path)
    assert r["status"] == "FAIL"


def test_expected_count_min_fails_closed(tmp_path):
    # Non-empty evidence, but fewer resources than the declared floor.
    (tmp_path / "things.json").write_text('[{"name": "a", "ok": true}]')
    c = _control("things", [{"path": "ok", "op": "eq", "value": True}])
    c["expected_count_min"] = 3
    r = controls.evaluate_control(c, tmp_path)
    assert r["status"] == "ERROR"
    assert any("collection gap" in n for n in r["notes"])


def _controls_json(tmp_path, max_age):
    ctrl = {"id": "T-1", "title": "t", "framework": "SOC2", "severity": "low",
            "resource": "things", "filters": [], "conditions": [{"path": "ok", "op": "eq", "value": True}]}
    if max_age is not None:
        ctrl["max_age_hours"] = max_age
    (tmp_path / "controls.json").write_text(json.dumps({"controls": [ctrl]}))
    ev = tmp_path / "evidence"
    ev.mkdir()
    (ev / "things.json").write_text('[{"name": "a", "ok": true}]')
    return ev


def test_fresh_evidence_passes(tmp_path):
    ev = _controls_json(tmp_path, max_age=24)
    (ev / "_meta.json").write_text(json.dumps({"things": "2999-01-01T00:00:00+00:00"}))
    rep = controls.run(tmp_path, quiet=True)
    assert rep["results"][0]["status"] == "PASS"


def test_stale_evidence_fails_closed(tmp_path):
    ev = _controls_json(tmp_path, max_age=24)
    (ev / "_meta.json").write_text(json.dumps({"things": "2000-01-01T00:00:00+00:00"}))
    rep = controls.run(tmp_path, quiet=True)
    assert rep["results"][0]["status"] == "ERROR"
    assert any("stale" in n for n in rep["results"][0]["notes"])


def test_missing_timestamp_with_max_age_fails_closed(tmp_path):
    ev = _controls_json(tmp_path, max_age=24)  # no _meta.json at all
    rep = controls.run(tmp_path, quiet=True)
    assert rep["results"][0]["status"] == "ERROR"


def test_no_max_age_means_no_freshness_check(tmp_path):
    ev = _controls_json(tmp_path, max_age=None)  # control opts out -> unchanged behavior
    rep = controls.run(tmp_path, quiet=True)
    assert rep["results"][0]["status"] == "PASS"


def test_freshness_does_not_mask_a_fail(tmp_path):
    # A FAIL stays FAIL even if evidence is fresh; freshness only flips green -> ERROR.
    ev = _controls_json(tmp_path, max_age=24)
    (ev / "things.json").write_text('[{"name": "a", "ok": false}]')
    (ev / "_meta.json").write_text(json.dumps({"things": "2999-01-01T00:00:00+00:00"}))
    rep = controls.run(tmp_path, quiet=True)
    assert rep["results"][0]["status"] == "FAIL"


def test_naive_timestamp_does_not_crash_the_run(tmp_path):
    # A naive (offset-less) timestamp must not raise TypeError; it is treated as UTC.
    ev = _controls_json(tmp_path, max_age=24)
    (ev / "_meta.json").write_text(json.dumps({"things": "2999-01-01T00:00:00"}))
    rep = controls.run(tmp_path, quiet=True)
    assert rep["results"][0]["status"] == "PASS"  # far future = fresh


def test_non_dict_meta_does_not_crash_the_run(tmp_path):
    # Valid JSON but the wrong shape (a list) must not raise AttributeError.
    ev = _controls_json(tmp_path, max_age=24)
    (ev / "_meta.json").write_text('["not", "a", "dict"]')
    rep = controls.run(tmp_path, quiet=True)
    assert rep["results"][0]["status"] == "ERROR"  # no usable timestamp -> fail closed


def test_uses_inherits_max_age_hours(tmp_path):
    # A framework control reusing a base control via "uses" must inherit its freshness guard.
    # The base lives in data_dir/controls.json; the framework control (with uses) is the controls_file.
    base = {"id": "B-1", "title": "b", "framework": "SOC2", "severity": "low",
            "resource": "things", "filters": [], "conditions": [{"path": "ok", "op": "eq", "value": True}],
            "max_age_hours": 24}
    (tmp_path / "controls.json").write_text(json.dumps({"controls": [base]}))
    framework = tmp_path / "framework.json"
    framework.write_text(json.dumps({"controls": [
        {"id": "T-1", "title": "t", "framework": "NIST", "severity": "low", "uses": "B-1"}]}))
    ev = tmp_path / "evidence"
    ev.mkdir()
    (ev / "things.json").write_text('[{"name": "a", "ok": true}]')
    (ev / "_meta.json").write_text(json.dumps({"things": "2000-01-01T00:00:00+00:00"}))
    rep = controls.run(tmp_path, controls_file=framework, quiet=True)
    assert rep["results"][0]["status"] == "ERROR"  # stale -> fail closed, not a silent PASS


def test_dangling_uses_fails_closed_not_manual(tmp_path):
    # A typo'd "uses" target must read ERROR, never MANUAL (fail closed, not fail open).
    framework = tmp_path / "controls.json"
    framework.write_text(json.dumps({"controls": [
        {"id": "T-1", "title": "t", "framework": "NIST", "severity": "low", "uses": "NOPE-1"}]}))
    (tmp_path / "evidence").mkdir()
    rep = controls.run(tmp_path, controls_file=framework, quiet=True)
    r = rep["results"][0]
    assert r["status"] == "ERROR"
    assert any("uses target not found" in n for n in r["notes"])
