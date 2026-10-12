#!/usr/bin/env python3
"""Render the docs HTML from the data. Stdlib only.

    python scripts/render_docs.py

- docs/nist-csf-2.0.html  from examples/frameworks/nist-csf-2.0.json
- docs/integrations.html  from docs/integrations/*.json + the control set

Add a tool: drop docs/integrations/<tool>.json in the same shape, add its name to
INTEGRATION_TOOLS below, and re-run this script.
"""
import html
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NIST = ROOT / "examples" / "frameworks" / "nist-csf-2.0.json"
SPEC_DIR = ROOT / "docs" / "integrations"
INTEGRATION_TOOLS = ["okta", "jamf", "github", "kubernetes", "wiz"]

FUNCTIONS = [("GV", "Govern"), ("ID", "Identify"), ("PR", "Protect"),
             ("DE", "Detect"), ("RS", "Respond"), ("RC", "Recover")]


def esc(x):
    return html.escape(str(x))


def code(obj):
    return "<pre class='samp'>" + esc(json.dumps(obj, indent=2)) + "</pre>"


CSS = """:root{--page:#f6f7f9;--surface:#fff;--ink:#0b0f17;--ink2:#374151;--muted:#667085;--line:#e7eaef;--accent:#067a5b;--soft:#e8f4ef;--mono:ui-monospace,Consolas,monospace;--sans:"Geist","Segoe UI",system-ui,sans-serif}
*{box-sizing:border-box}body{margin:0;background:var(--page);color:var(--ink);font-family:var(--sans);line-height:1.55}
.wrap{max-width:1160px;margin:0 auto;padding:0 24px}
header{padding:44px 0 24px;border-bottom:1px solid var(--line)}
.eyebrow{font-family:var(--mono);font-size:11px;letter-spacing:.16em;text-transform:uppercase;color:var(--accent)}
h1{font-size:33px;letter-spacing:-.03em;margin:10px 0 8px}h2{font-size:20px;margin:0 0 12px}h3{font-size:14px;margin:18px 0 8px;color:var(--ink2)}
h2 .cnt{font-family:var(--mono);font-size:11px;color:var(--muted);font-weight:400}
.muted{color:var(--muted)}.mono{font-family:var(--mono)}
.stats{display:grid;grid-template-columns:repeat(5,1fr);gap:10px;margin:20px 0 0}
.stat{background:var(--surface);border:1px solid var(--line);border-radius:12px;padding:14px}
.stat .n{font-size:25px;font-weight:700;letter-spacing:-.03em}.stat .l{font-family:var(--mono);font-size:10.5px;text-transform:uppercase;letter-spacing:.08em;color:var(--muted)}
section{padding:28px 0;border-bottom:1px solid var(--line)}
.kv{color:var(--ink2);font-size:13.5px;margin:0 0 14px}
table{width:100%;border-collapse:collapse;font-size:13px;background:var(--surface);border:1px solid var(--line);border-radius:10px;overflow:hidden;margin-bottom:8px}
th,td{text-align:left;padding:8px 12px;border-bottom:1px solid var(--line);vertical-align:top}
th{font-family:var(--mono);font-size:10px;text-transform:uppercase;letter-spacing:.07em;color:var(--muted);background:#fbfcfd}
tr.cat td{background:var(--soft);font-family:var(--mono);font-size:11px;color:#14453a}
td.ref{font-family:var(--mono);font-size:12px;color:var(--accent);white-space:nowrap}
td.src{font-family:var(--mono);font-size:12px;color:var(--ink2);white-space:nowrap}
td.msr{color:var(--ink2)}td.m{font-family:var(--mono);color:var(--accent)}
td.p{font-family:var(--mono);font-size:11.5px;color:var(--ink2)}td.f{font-family:var(--mono);font-size:11px;color:var(--muted)}
.pill{font-family:var(--mono);font-size:9.5px;padding:2px 7px;border-radius:10px;white-space:nowrap}
.pill.measured{background:var(--soft);color:var(--accent);border:1px solid #bfe0d3}
.pill.suggested{background:#f2f4f7;color:var(--muted);border:1px solid var(--line)}
.callout{border-left:3px solid var(--accent);background:var(--soft);border-radius:0 12px 12px 0;padding:14px 18px;color:#14453a;margin:16px 0}
pre.samp{margin:0;background:#0b0f17;color:#cfe0d8;border-radius:8px;padding:8px 10px;font-family:var(--mono);font-size:11px;line-height:1.45;overflow:auto}
footer{padding:24px 0 60px;color:var(--muted);font-size:12.5px}
@media(max-width:900px){.stats{grid-template-columns:repeat(2,1fr)}}"""


def render_nist(doc):
    controls = doc["controls"]
    measured = sum(1 for c in controls if c.get("status") == "measured")
    suggested = len(controls) - measured
    categories = sorted({c["category"] for c in controls})
    sections = ""
    for code_, name in FUNCTIONS:
        items = [c for c in controls if c["function"] == code_]
        m = sum(1 for c in items if c.get("status") == "measured")
        cats = []
        for c in items:
            if c["category"] not in cats:
                cats.append(c["category"])
        rows = ""
        for cat in cats:
            rows += '<tr class="cat"><td colspan="4">{0}</td></tr>'.format(esc(cat))
            for c in [x for x in items if x["category"] == cat]:
                pill = '<span class="pill {0}">{0}</span>'.format(c.get("status", ""))
                rows += ('<tr><td class="ref">{ref}</td><td>{title}</td><td class="src">{source}</td>'
                         '<td class="msr">{measure} {pill}</td></tr>').format(
                    ref=esc(c["ref"]), title=esc(c["title"]), source=esc(c.get("source", "")),
                    measure=esc(c.get("measure", "")), pill=pill)
        sections += ("<section><h2>{name} <span class='cnt'>{code} · {n} subcategories · {m} measured</span></h2>"
                     "<table><thead><tr><th>Ref</th><th>Outcome</th><th>Source</th><th>What would be measured</th></tr>"
                     "</thead><tbody>{rows}</tbody></table></section>").format(
            name=name, code=code_, n=len(items), m=m, rows=rows)
    return """<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>NIST CSF 2.0 coverage - GRC Engineering Playbook</title><style>{css}</style></head><body><div class="wrap">
<header><div class="eyebrow">Framework coverage</div>
<h1>NIST CSF 2.0 - every subcategory, and what would evidence it</h1>
<p class="muted">The full CSF 2.0 core as a control set. Subcategories with an AWS evidence source are <b>measured</b> by the
engine; the rest carry a <b>suggested</b> source and what a human would measure or attest.</p>
<div class="stats"><div class="stat"><div class="n">6</div><div class="l">functions</div></div>
<div class="stat"><div class="n">{ncat}</div><div class="l">categories</div></div>
<div class="stat"><div class="n">{ntotal}</div><div class="l">subcategories</div></div>
<div class="stat"><div class="n">{measured}</div><div class="l">measured</div></div>
<div class="stat"><div class="n">{suggested}</div><div class="l">suggested</div></div></div></header>
<section><div class="callout"><b>Measured</b>: the engine evaluates it now against AWS evidence. <b>Suggested</b>:
a governance, response, or process outcome that is not a config check - the row names the source and the record a human relies on.
Some measured rows are <b>proxy checks</b> (for example, a detection service being enabled) rather than full outcome verification; treat them as a starting signal, not proof.</div></section>
{sections}<footer>GRC Engineering Playbook · NIST CSF 2.0 core (106 subcategories) · {measured} measured, {suggested} suggested.</footer>
</div></body></html>""".format(css=CSS, ncat=len(categories), ntotal=len(controls), measured=measured,
                             suggested=suggested, sections=sections)


def render_integrations(doc):
    specs = [json.loads((SPEC_DIR / (n + ".json")).read_text(encoding="utf-8")) for n in INTEGRATION_TOOLS]
    spec_refs = {c["ref"] for s in specs for c in s.get("controls", [])}
    aws = [c for c in doc["controls"] if c.get("aws")]
    program = [c for c in doc["controls"] if not c.get("aws") and c["ref"] not in spec_refs]
    sections = ""
    total_endpoints = 0
    for s in specs:
        total_endpoints += len(s.get("endpoints", []))
        rows = "".join("<tr><td class='m'>{0}</td><td class='p'>{1}</td><td>{2}</td></tr>".format(
            esc(e.get("method")), esc(e.get("path")), esc(e.get("purpose"))) for e in s.get("endpoints", []))
        ctrls = "".join("<tr><td class='ref'>{ref}</td><td class='p'>{api}</td><td class='f'>{fields}</td><td>{sample}</td></tr>".format(
            ref=esc(c["ref"]), api=esc(c.get("api")), fields=esc(", ".join(c.get("fields", []))),
            sample=code(c.get("sample", {}))) for c in s.get("controls", []))
        sections += ("<section><h2>{tool} <span class='cnt'>{ne} endpoints · {nc} controls</span></h2>"
                     "<p class='kv'><b>Auth</b> {auth}<br><b>Base URL</b> <span class='mono'>{base}</span></p>"
                     "<table><thead><tr><th>Method</th><th>Endpoint</th><th>Purpose</th></tr></thead><tbody>{rows}</tbody></table>"
                     "<h3>Controls this tool evidences</h3><table><thead><tr><th>Ref</th><th>API</th><th>Fields</th>"
                     "<th>Draft response</th></tr></thead><tbody>{ctrls}</tbody></table></section>").format(
            tool=esc(s["tool"]), auth=esc(s.get("auth", "")), base=esc(s.get("base_url", "")),
            ne=len(s.get("endpoints", [])), nc=len(s.get("controls", [])), rows=rows, ctrls=ctrls)
    aws_rows = "".join("<tr><td class='ref'>{0}</td><td class='p'>{1}</td></tr>".format(esc(c["ref"]), esc(c["aws"])) for c in aws)
    prog = {}
    for c in program:
        prog.setdefault(c.get("source", ""), []).append(c["ref"])
    prog_rows = "".join("<tr><td>{0}</td><td class='f'>{1}</td></tr>".format(esc(src), esc(", ".join(refs)))
                        for src, refs in sorted(prog.items()))
    sections += ("<section><h2>AWS <span class='cnt'>{n} measured controls</span></h2>"
                 "<p class='kv'>Config checks evaluated by the engine. Sources with collector code are read live by <span class='mono'>src/grc_playbook/collect_aws.py</span> (boto3); the rest run against bundled fixtures in <span class='mono'>examples/evidence/</span>.</p>"
                 "<table><thead><tr><th>Ref</th><th>AWS API</th></tr></thead><tbody>{aws}</tbody></table></section>"
                 "<section><h2>Program &amp; governance sources <span class='cnt'>{pn} sources</span></h2>"
                 "<p class='kv'>Not config checks; evidenced by a platform record (attested).</p>"
                 "<table><thead><tr><th>Source</th><th>Controls</th></tr></thead><tbody>{prog}</tbody></table></section>").format(
        n=len(aws), aws=aws_rows, pn=len(prog), prog=prog_rows)
    return """<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Integrations - every tool, API and draft response - GRC Engineering Playbook</title><style>{css}</style></head><body><div class="wrap">
<header><div class="eyebrow">Integrations</div><h1>Every tool, its API, and a draft response</h1>
<p class="muted">The evidence sources behind the NIST CSF 2.0 mapping: <b>Okta</b> for identity, <b>Jamf</b> for devices,
<b>GitHub</b> for SDLC and supply chain, <b>Kubernetes</b> for workloads, <b>Wiz</b> for cloud posture, plus <b>AWS</b>
for infrastructure config and governance platforms for program records. Each spec is a draft drawn from the vendor's API docs.</p>
<div class="stats"><div class="stat"><div class="n">{ntools}</div><div class="l">API tools</div></div>
<div class="stat"><div class="n">{neps}</div><div class="l">endpoints</div></div>
<div class="stat"><div class="n">{ncov}</div><div class="l">subcategories covered</div></div>
<div class="stat"><div class="n">{ntotal}</div><div class="l">in the framework</div></div>
<div class="stat"><div class="n">{nprog}</div><div class="l">program sources</div></div></div></header>
{sections}<footer>GRC Engineering Playbook · draft integration specs · docs/integrations/.</footer>
</div></body></html>""".format(css=CSS, ntools=len(specs), neps=total_endpoints, ncov=len(spec_refs),
                             ntotal=doc["_meta"]["counts"]["total"], nprog=len(prog), sections=sections)


def main():
    doc = json.loads(NIST.read_text(encoding="utf-8"))
    (ROOT / "docs" / "nist-csf-2.0.html").write_text(render_nist(doc), encoding="utf-8")
    (ROOT / "docs" / "integrations.html").write_text(render_integrations(doc), encoding="utf-8")
    print("rendered docs/nist-csf-2.0.html and docs/integrations.html")


if __name__ == "__main__":
    main()
