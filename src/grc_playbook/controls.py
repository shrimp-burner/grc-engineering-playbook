"""Evaluate declarative controls against evidence, and report PASS, FAIL, or ERROR.

A control is data: a scope (filters) plus conditions. The engine is deliberately
declarative; adding a control is a JSON diff, not a code change.

Status semantics:
  PASS   all in-scope resources satisfy every condition (vacuously true if none)
  FAIL   at least one in-scope resource violates a condition
  ERROR  evidence is missing, malformed, empty (collection failure), or unresolvable
  MANUAL a subcategory with no technical evidence source, assessed by attestation

A control may also declare `"uses": "<control-id>"` to reuse another control's
resource + filters + conditions. That is how one evaluation feeds many frameworks.

Evidence freshness is D2 over time. A control may declare `"max_age_hours": N`; if
the evidence dir has a `_meta.json` mapping source -> collected_at timestamp, a
PASS whose evidence is older than N hours is flipped to ERROR. Stale reads as a
gap, not as green. Opt-in per control, so fixtures without it are unaffected.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path


def get_path(obj, path):
    cur = obj
    for part in path.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return None
    return cur


def eval_condition(resource, cond):
    op = cond["op"]
    if op == "max_field_lt":
        arr = get_path(resource, cond["path"]) or []
        vals = [it.get(cond["field"]) for it in arr if isinstance(it, dict)]
        vals = [v for v in vals if v is not None]
        if not vals:
            return True, "no {0} values (vacuous)".format(cond["field"])
        worst = max(vals)
        return worst < cond["value"], "max {0}={1} (limit <{2})".format(cond["field"], worst, cond["value"])
    val = get_path(resource, cond.get("path"))
    target = cond.get("value")
    if op == "eq":
        # Strict about booleans: evidence emitting {"enabled": 1} must not satisfy
        # an `eq true` control.
        if isinstance(target, bool) or isinstance(val, bool):
            ok = isinstance(val, bool) and isinstance(target, bool) and val == target
        else:
            ok = val == target
    elif op == "neq":
        ok = val != target
    elif op == "lt":
        ok = val is not None and val < target
    elif op == "lte":
        ok = val is not None and val <= target
    elif op == "gt":
        ok = val is not None and val > target
    elif op == "gte":
        ok = val is not None and val >= target
    elif op == "not_null":
        ok = val is not None
    elif op == "in":
        ok = val in (target or [])
    elif op == "contains":
        ok = isinstance(val, str) and isinstance(target, str) and target in val
    else:
        raise ValueError("unknown operator: " + op)
    return ok, "{0} = {1!r} ({2} {3!r})".format(cond.get("path"), val, op, target)


def _resource_name(res):
    for key in ("name", "user_name", "account_name", "resource"):
        if isinstance(res, dict) and key in res:
            return res[key]
    return "?"


def _matches(resource, filters):
    return all(eval_condition(resource, f)[0] for f in filters)


def _result(control):
    return {
        "id": control["id"], "title": control["title"], "framework": control["framework"],
        "ref": control.get("ref"), "mappings": control.get("mappings"),
        "owner": control.get("owner"), "severity": control["severity"],
        "resource": control.get("resource"), "max_age_hours": control.get("max_age_hours"),
        "status": None, "in_scope": 0, "findings": [], "notes": [],
    }


def evaluate_control(control, evidence_dir: Path):
    result = _result(control)

    if control.get("assessment") == "manual" or "resource" not in control:
        result["status"] = "MANUAL"
        result["notes"].append("not automated; assessed by attestation")
        return result

    res_type = control["resource"]
    evidence_file = evidence_dir / (res_type + ".json")
    if not evidence_file.exists():
        result["status"] = "ERROR"
        result["notes"].append("evidence source missing: evidence/{0}.json (silent gap = control failure)".format(res_type))
        return result

    # Malformed evidence fails this control, not the whole run.
    try:
        resources = json.loads(evidence_file.read_text())
    except Exception as e:  # noqa: BLE001
        result["status"] = "ERROR"
        result["notes"].append("evidence file is not valid JSON: {0}".format(e))
        return result
    if isinstance(resources, dict):
        resources = [resources]

    # An empty evidence file is a collection failure, not a clean estate.
    if not resources and not control.get("allow_empty"):
        result["status"] = "ERROR"
        result["notes"].append("evidence file is empty (likely a collection failure; set allow_empty to override)")
        return result

    try:
        in_scope = [r for r in resources if _matches(r, control.get("filters", []))]
    except (TypeError, ValueError) as e:
        result["status"] = "ERROR"
        result["notes"].append("filter evaluation error: {0}".format(e))
        return result
    result["in_scope"] = len(in_scope)

    expected_min = control.get("expected_count_min")
    if expected_min is not None and len(in_scope) < expected_min:
        result["status"] = "ERROR"
        result["notes"].append("collection gap: {0} in scope, expected at least {1}".format(len(in_scope), expected_min))
        return result

    if not in_scope:
        result["status"] = "PASS"
        result["notes"].append("no in-scope resources (vacuously true)")
        return result

    try:
        for res in in_scope:
            failures = []
            for cond in control.get("conditions", []):
                ok, detail = eval_condition(res, cond)
                if not ok:
                    failures.append({"condition": cond.get("path") or cond["op"], "detail": detail})
            if failures:
                result["findings"].append({
                    "resource": _resource_name(res),
                    "account": res.get("account") or res.get("account_id"),
                    "failures": failures,
                })
    except (TypeError, ValueError) as e:
        result["status"] = "ERROR"
        result["findings"] = []
        result["notes"].append("evaluation error: {0}".format(e))
        return result
    result["status"] = "FAIL" if result["findings"] else "PASS"
    return result


def _read_freshness(evidence_dir: Path):
    """Optional evidence-collection timestamps: <evidence_dir>/_meta.json ->
    {source_name: collected_at_iso8601}. Absent or unparseable entries are ignored
    (no freshness check), so existing fixtures keep working unchanged."""
    meta = evidence_dir / "_meta.json"
    if not meta.exists():
        return {}
    try:
        parsed = json.loads(meta.read_text())
    except Exception:  # noqa: BLE001  a bad meta file must not fail the run
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _parse_ts(value):
    if not isinstance(value, str):
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    # A naive timestamp (e.g. from datetime.utcnow().isoformat()) cannot be
    # subtracted from an aware "now". Treat it as UTC rather than crash the run;
    # the collector always writes aware UTC, so this only affects foreign meta files.
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=timezone.utc)


def _apply_freshness(results, freshness, now):
    """D2 over time: evidence past a control's max_age_hours is stale, and stale
    fails closed (ERROR), exactly like missing evidence. Opt-in per control via a
    max_age_hours field; a control with no max_age_hours is never touched."""
    for r in results:
        if r["status"] != "PASS":
            continue
        max_age = r.get("max_age_hours")
        if max_age is None:
            continue
        collected = _parse_ts(freshness.get(r["resource"]))
        if collected is None:
            r["status"] = "ERROR"
            r["notes"].append("no collection timestamp for evidence/{0}.json (cannot prove freshness)".format(r["resource"]))
            continue
        age_h = (now - collected).total_seconds() / 3600
        if age_h > max_age:
            r["status"] = "ERROR"
            r["notes"].append(
                "evidence stale: collected {0:.1f}h ago, exceeds max_age_hours={1} (stale = fail closed)".format(age_h, max_age))


def run(data_dir: Path, control_id=None, verbose: bool = False, quiet=False, controls_file=None, evidence_dir=None):
    path = Path(controls_file) if controls_file else (data_dir / "controls.json")
    controls = json.loads(path.read_text())["controls"]
    evidence = Path(evidence_dir) if evidence_dir else (data_dir / "evidence")

    # Registry lets a framework control reuse another control's definition via `uses`,
    # so one check feeds many frameworks instead of being copied and drifting.
    registry = {}
    reg_file = data_dir / "controls.json"
    if reg_file.exists() and reg_file.resolve() != path.resolve():
        registry = {c["id"]: c for c in json.loads(reg_file.read_text())["controls"]}

    resolved = []
    for c in controls:
        if c.get("uses") and c["uses"] in registry:
            base = registry[c["uses"]]
            c = dict(c)
            c["resource"] = base.get("resource")
            c["filters"] = base.get("filters", [])
            c["conditions"] = base.get("conditions", [])
            if base.get("max_age_hours") is not None:
                c.setdefault("max_age_hours", base["max_age_hours"])
        elif c.get("uses"):
            # A dangling reuse target is a broken control definition, not a manual
            # attestation; mark it so the eval loop fails closed on it.
            c = dict(c)
            c["_dangling_uses"] = c["uses"]
        resolved.append(c)

    if control_id:
        resolved = [c for c in resolved if c["id"] == control_id]

    results = []
    for c in resolved:
        try:
            if c.get("_dangling_uses"):
                r = _result(c)
                r["status"] = "ERROR"
                r["notes"].append("uses target not found: {0} (fail closed)".format(c["_dangling_uses"]))
                results.append(r)
                continue
            results.append(evaluate_control(c, evidence))
        except Exception as e:  # noqa: BLE001  one bad control must not kill the run
            r = _result(c)
            r["status"] = "ERROR"
            r["notes"].append("control raised: {0}".format(e))
            results.append(r)

    # Evidence freshness (D2 over time): opt-in per control, applied only to results
    # that otherwise passed, so a stale estate cannot read green.
    _apply_freshness(results, _read_freshness(evidence), datetime.now(timezone.utc))

    summary = {
        "PASS": sum(1 for r in results if r["status"] == "PASS"),
        "FAIL": sum(1 for r in results if r["status"] == "FAIL"),
        "ERROR": sum(1 for r in results if r["status"] == "ERROR"),
        "MANUAL": sum(1 for r in results if r["status"] == "MANUAL"),
        "total": len(results),
    }
    if not quiet:
        print("=" * 68)
        print("CONTINUOUS CONTROLS RUN  " + datetime.now(timezone.utc).isoformat(timespec="seconds"))
        print("=" * 68)
        for r in results:
            mark = {"PASS": "[PASS]", "FAIL": "[FAIL]", "ERROR": "[ERR ]", "MANUAL": "[MANU]"}[r["status"]]
            print("{0} {1:<12} {2:<9} {3}".format(mark, r["id"], r["severity"], r["title"]))
            if verbose or r["status"] != "PASS":
                for n in r["notes"]:
                    print("         note: " + n)
                for f in r["findings"]:
                    print("         resource: {0} (account {1})".format(f["resource"], f["account"]))
                    for fail in f["failures"]:
                        print("            - " + fail["detail"])
        print("-" * 68)
        print("summary: {PASS} pass | {FAIL} fail | {ERROR} error | {MANUAL} manual | {total} total".format(**summary))
    report = {"run_at": datetime.now(timezone.utc).isoformat(timespec="seconds"), "summary": summary, "results": results}
    return report


if __name__ == "__main__":
    from grc_playbook import EXAMPLES
    run(EXAMPLES)
