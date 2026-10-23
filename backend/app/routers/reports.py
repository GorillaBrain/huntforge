from __future__ import annotations

import html
import sqlite3

from fastapi import APIRouter, Depends, Query
from fastapi.responses import HTMLResponse, PlainTextResponse

from ..core import get_db, now_iso
from .cases import get_case

router = APIRouter(prefix="/api/reports", tags=["reports"])


def build(db, case_id: str) -> dict:
    c = get_case(case_id, db)
    dets = [i["snapshot"] for i in c["items"] if i["kind"] == "detection" and i["snapshot"]]
    evidence = [i for i in c["items"] if i["kind"] == "evidence" and i["snapshot"]]
    notes = [i for i in c["items"] if i["kind"] == "note"]
    scope = None
    if evidence:
        ts = sorted(i["snapshot"]["ts"] for i in evidence)
        scope = {"first_event": ts[0], "last_event": ts[-1], "event_count": len(evidence),
                 "hosts": sorted({i["snapshot"]["hostname"] for i in evidence if i["snapshot"].get("hostname")}),
                 "users": sorted({i["snapshot"]["username"] for i in evidence if i["snapshot"].get("username")}),
                 "ips": sorted({ip for i in evidence for ip in (i["snapshot"].get("src_ip"), i["snapshot"].get("dst_ip")) if ip})}
    summary = (f"Case {c['id']} ({c['severity']} severity, status {c['status']}) contains {len(dets)} detection(s), "
               f"{len(evidence)} evidence event(s) and {len(notes)} analyst note(s).")
    return {"generated_at": now_iso(), "case": {k: c[k] for k in ("id", "title", "description", "severity", "status", "assignee", "created_at", "updated_at")},
            "executive_summary": summary, "scope": scope, "detections": dets, "timeline": c["timeline"], "evidence": evidence,
            "actions": [{"ts": n["created_at"], "text": n["body"]} for n in notes],
            "findings": c["findings"], "conclusion": c["conclusion"], "uncertainty": c["uncertainty"], "recommendations": c["recommendations"]}


def _or(v, empty="Not recorded."):
    return v.strip() if v and v.strip() else empty


def to_markdown(r: dict) -> str:
    c = r["case"]
    L = [f"# Investigation Report: {c['title']}", "", f"**Case:** {c['id']}  ", f"**Severity:** {c['severity']}  ", f"**Status:** {c['status']}  ",
         f"**Analyst:** {c['assignee'] or 'Unassigned'}  ", f"**Created:** {c['created_at']}  ", f"**Report generated:** {r['generated_at']}", "",
         "## Executive summary", r["executive_summary"], "", _or(c["description"], ""), "", "## Investigation scope"]
    s = r["scope"]
    if s:
        L += [f"- Event window: {s['first_event']} to {s['last_event']}", f"- Evidence events: {s['event_count']}",
              f"- Hosts: {', '.join(s['hosts']) or 'n/a'}", f"- Users: {', '.join(s['users']) or 'n/a'}", f"- IPs: {', '.join(s['ips']) or 'n/a'}"]
    else:
        L.append("No evidence events have been collected.")
    L += ["", "## Timeline of important events"]
    L += [f"- `{t['ts']}` {t['ref']}: {t['summary']}" + (f" — _{t['note']}_" if t["note"] else "") for t in r["timeline"]] or ["No timeline events."]
    L += ["", "## Detection findings"]
    for d in r["detections"]:
        L += [f"### {d['id']}: {d['title']}", f"Severity **{d['severity']}**, confidence **{int(d['confidence'] * 100)}%**, rule {d['rule_id']}, status {d['status']}.", d["explanation"], ""]
    if not r["detections"]:
        L.append("No detections attached.")
    L += ["", "## Supporting evidence", "| Ref | Time | Summary |", "|---|---|---|"]
    L += [f"| EVT-{i['ref']} | {i['snapshot']['ts']} | {_md(_summ(i['snapshot']))} |" for i in r["evidence"]]
    L += ["", "## Actions performed"] + ([f"- `{a['ts']}` {a['text']}" for a in r["actions"]] or ["No analyst notes recorded."])
    L += ["", "## Analyst findings", _or(r["findings"]), "", "## Analyst conclusion", _or(r["conclusion"]),
          "", "## Remaining uncertainty", _or(r["uncertainty"]), "", "## Recommendations", _or(r["recommendations"]), ""]
    return "\n".join(L)


def _md(s: str) -> str:
    return s.replace("|", "\\|").replace("\n", " ")


def _summ(e: dict) -> str:
    bits = [e.get("event_type"), e.get("outcome"), e.get("username"), e.get("hostname"), e.get("src_ip"),
            (f"-> {e['dst_ip']}:{e['dst_port']}" if e.get("dst_ip") else None), e.get("command_line") or e.get("message")]
    return " ".join(str(b) for b in bits if b)[:300]


def to_html(r: dict) -> str:
    e = html.escape  # every dynamic value is escaped; log content is untrusted
    c = r["case"]
    def para(t): return "".join(f"<p>{e(x)}</p>" for x in _or(t).split("\n") if x.strip()) or "<p>Not recorded.</p>"
    s = r["scope"]
    scope = (f"<ul><li>Event window: {e(s['first_event'])} to {e(s['last_event'])}</li><li>Evidence events: {s['event_count']}</li>"
             f"<li>Hosts: {e(', '.join(s['hosts']) or 'n/a')}</li><li>Users: {e(', '.join(s['users']) or 'n/a')}</li><li>IPs: {e(', '.join(s['ips']) or 'n/a')}</li></ul>") if s else "<p>No evidence events collected.</p>"
    dets = "".join(f"<h3>{e(d['id'])}: {e(d['title'])}</h3><p><b>{e(d['severity'])}</b> severity, {int(d['confidence'] * 100)}% confidence, rule {e(d['rule_id'])}, status {e(d['status'])}</p><p>{e(d['explanation'])}</p>" for d in r["detections"]) or "<p>No detections attached.</p>"
    tl = "".join(f"<tr><td class=m>{e(t['ts'])}</td><td class=m>{e(t['ref'])}</td><td>{e(t['summary'])}</td><td>{e(t['note'] or '')}</td></tr>" for t in r["timeline"])
    acts = "".join(f"<li><span class=m>{e(a['ts'])}</span> {e(a['text'])}</li>" for a in r["actions"]) or "<li>No analyst notes recorded.</li>"
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><title>{e(c['id'])} report</title>
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<style>body{{font:14px/1.5 system-ui,sans-serif;max-width:900px;margin:2rem auto;padding:0 1rem;color:#111}}h1,h2{{border-bottom:1px solid #ccc;padding-bottom:.2rem}}
table{{border-collapse:collapse;width:100%;font-size:12px}}td,th{{border:1px solid #ccc;padding:4px 6px;text-align:left;vertical-align:top}}.m{{font-family:ui-monospace,monospace;white-space:nowrap}}
@media print{{body{{margin:0}}}}</style></head><body>
<h1>Investigation Report: {e(c['title'])}</h1>
<p><b>Case</b> {e(c['id'])} · <b>Severity</b> {e(c['severity'])} · <b>Status</b> {e(c['status'])} · <b>Analyst</b> {e(c['assignee'] or 'Unassigned')}<br>Created {e(c['created_at'])} · Generated {e(r['generated_at'])}</p>
<h2>Executive summary</h2><p>{e(r['executive_summary'])}</p>{para(c['description']) if c['description'] else ''}
<h2>Investigation scope</h2>{scope}
<h2>Timeline of important events</h2><table><tr><th>Time (UTC)</th><th>Ref</th><th>Event</th><th>Analyst note</th></tr>{tl or '<tr><td colspan=4>No timeline events.</td></tr>'}</table>
<h2>Detection findings</h2>{dets}
<h2>Actions performed</h2><ul>{acts}</ul>
<h2>Analyst findings</h2>{para(r['findings'])}<h2>Analyst conclusion</h2>{para(r['conclusion'])}
<h2>Remaining uncertainty</h2>{para(r['uncertainty'])}<h2>Recommendations</h2>{para(r['recommendations'])}
<hr><p><small>Detections are suspicious patterns, not confirmed attacks. Evidence is a snapshot taken when collected.</small></p></body></html>"""


@router.get("/cases/{case_id}")
def case_report(case_id: str, format: str = Query("json", pattern="^(json|markdown|html)$"), db: sqlite3.Connection = Depends(get_db)):
    r = build(db, case_id)
    if format == "markdown":
        return PlainTextResponse(to_markdown(r), media_type="text/markdown",
                                 headers={"Content-Disposition": f'attachment; filename="{case_id}-report.md"'})
    if format == "html":
        return HTMLResponse(to_html(r), headers={"Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'"})
    return r
