"""Security report generator (Task 5): Markdown and self-contained HTML."""
import json
from html import escape as e

from .config import METRICS_PATH

SEV_COLOR = {"Critical": "#b91c1c", "High": "#ea580c", "Medium": "#ca8a04", "Low": "#2563eb", "Informational": "#6b7280"}


def _metrics():
    try:
        return json.loads(METRICS_PATH.read_text(encoding="utf-8"))
    except Exception:
        return None


def to_markdown(res: dict) -> str:
    s, m = res["summary"], _metrics()
    L = ["# Security Assessment Report", "",
         f"**Period analysed:** {s['period'][0]} → {s['period'][1]}  ",
         f"**Events:** {s['events_analyzed']:,} · **Alerts:** {s['alerts']:,} · **Incidents:** {s['incidents']} · **Findings:** {s['findings']}  ",
         f"**Detector:** {s['model']} (alert threshold {s['threshold']})", "",
         "## 1. Executive summary", "",
         "| Severity | Incidents |", "|---|---|"]
    L += [f"| {k} | {v} |" for k, v in s["incidents_by_severity"].items() if v]
    top = [i for i in res["incidents"] if i["severity_rank"] >= 3][:5]
    if top:
        L += ["", "**Priority incidents:**", ""]
        L += [f"- `{i['incident_id']}` ({i['severity']}) – {', '.join(i['stages'])} from {', '.join(i['src_ips'][:2])} → {', '.join(i['assets'][:3])}" for i in top]
    if m:
        t = m["test_metrics"]
        L += ["", "## 2. Detection model performance (temporal hold-out)", "",
              f"Model **{m['selected_model']}** – precision {t['precision']}, recall {t['recall']}, F1 {t['f1']}, "
              f"PR-AUC {t['pr_auc']}, FPR {t['false_positive_rate']}. Confusion matrix: {t['confusion_matrix']}."]
    if "correlation_evaluation" in res:
        L += ["", "**Correlation vs ground truth:** " + json.dumps(res["correlation_evaluation"])]
    L += ["", "## 3. Correlated incidents", ""]
    for i in res["incidents"]:
        L += [f"### {i['incident_id']} – {i['severity']}", "",
              f"- **Window:** {i['start']} → {i['end']} ({i['duration_s']:.0f}s)",
              f"- **Sources:** {', '.join(i['src_ips'])}  **Assets:** {', '.join(i['assets'])}",
              f"- **Kill-chain stages:** {' → '.join(i['stages'])}  **Alerts:** {i['n_alerts']} (mean P={i['mean_prob']})",
              "- **Why it was flagged:**"] + [f"  - {r}" for r in i["reasoning"]]
        L += ["- **Sample evidence:**"] + [
            f"  - #{x['event_id']} {x['timestamp']} {x['src_ip']} → {x['dst_asset']}:{x['dst_port']} {x['event_type']} "
            f"user={x['user']} status={x['status']} P={x['prob']:.2f}" for x in i["evidence"]] + [""]
    L += ["## 4. Compliance-mapped findings", ""]
    for f in res["findings"]:
        c = f["controls"]
        L += [f"### {f['finding_id']} – {f['title']} ({f['risk_level']})", "",
              f"- Incident: {f['incident_id']} · MITRE: {f['mitre']} · Assets: {', '.join(f['affected_assets'])} · Events: {f['n_events']}",
              f"- NIST CSF 2.0: " + "; ".join(f"{x['ref']} {x['name']}" for x in c["NIST_CSF_2.0"]),
              f"- ISO 27001:2022: " + "; ".join(f"{x['ref']} {x['name']}" for x in c["ISO_27001_2022"]),
              "- Evidence: " + " | ".join(f["evidence"]), "- Remediation:"] + [f"  1. {r}" for r in f["remediation"]] + [""]
    return "\n".join(L)


def to_html(res: dict) -> str:
    s, m = res["summary"], _metrics()
    def badge(sev): return f'<span class="b" style="background:{SEV_COLOR.get(sev, "#6b7280")}">{e(sev)}</span>'
    h = ["<!doctype html><html lang=en><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'>",
         "<title>Security Assessment Report</title><style>body{font:14px/1.5 system-ui,sans-serif;max-width:1000px;margin:24px auto;padding:0 16px;color:#111}"
         "table{border-collapse:collapse;width:100%;margin:8px 0}td,th{border:1px solid #ddd;padding:6px 8px;text-align:left;vertical-align:top}th{background:#f3f4f6}"
         ".b{color:#fff;border-radius:4px;padding:1px 8px;font-size:12px}.card{border:1px solid #ddd;border-radius:8px;padding:12px 16px;margin:14px 0}"
         "code{background:#f3f4f6;padding:1px 4px;border-radius:3px}h1,h2{border-bottom:1px solid #eee;padding-bottom:4px}</style>",
         "<h1>Security Assessment Report</h1>",
         f"<p><b>Period:</b> {e(s['period'][0])} → {e(s['period'][1])}<br><b>Events:</b> {s['events_analyzed']:,} · <b>Alerts:</b> {s['alerts']:,} · "
         f"<b>Incidents:</b> {s['incidents']} · <b>Findings:</b> {s['findings']}<br><b>Detector:</b> {e(s['model'])}, threshold {s['threshold']}</p>",
         "<h2>1. Executive summary</h2><table><tr><th>Severity</th><th>Incidents</th></tr>"]
    h += [f"<tr><td>{badge(k)}</td><td>{v}</td></tr>" for k, v in s["incidents_by_severity"].items() if v]
    h.append("</table>")
    if m:
        t = m["test_metrics"]
        h.append(f"<h2>2. Detection model (temporal hold-out)</h2><p>{e(m['selected_model'])}: precision <b>{t['precision']}</b>, recall <b>{t['recall']}</b>, "
                 f"F1 <b>{t['f1']}</b>, PR-AUC {t['pr_auc']}, FPR {t['false_positive_rate']}. Confusion: <code>{e(json.dumps(t['confusion_matrix']))}</code></p>")
    if "correlation_evaluation" in res:
        h.append(f"<p><b>Correlation vs ground truth:</b> <code>{e(json.dumps(res['correlation_evaluation']))}</code></p>")
    h.append("<h2>3. Correlated incidents</h2>")
    for i in res["incidents"]:
        h.append(f"<div class=card><h3>{e(i['incident_id'])} {badge(i['severity'])}</h3>"
                 f"<p>{e(i['start'])} → {e(i['end'])} · sources <code>{e(', '.join(i['src_ips']))}</code> · assets <code>{e(', '.join(i['assets']))}</code><br>"
                 f"Stages: {e(' → '.join(i['stages']))} · alerts {i['n_alerts']} · mean P={i['mean_prob']}</p><b>Why flagged</b><ul>"
                 + "".join(f"<li>{e(r)}</li>" for r in i["reasoning"]) + "</ul><b>Sample evidence</b><table><tr><th>#</th><th>Time</th><th>Source</th><th>Target</th><th>Event</th><th>User</th><th>P</th></tr>"
                 + "".join(f"<tr><td>{x['event_id']}</td><td>{e(x['timestamp'])}</td><td>{e(x['src_ip'])}</td><td>{e(x['dst_asset'])}:{x['dst_port']}</td><td>{e(x['event_type'])}</td><td>{e(str(x['user']))}</td><td>{x['prob']:.2f}</td></tr>" for x in i["evidence"])
                 + "</table></div>")
    h.append("<h2>4. Compliance-mapped findings</h2><table><tr><th>ID</th><th>Finding</th><th>Risk</th><th>NIST CSF 2.0</th><th>ISO 27001:2022</th><th>Evidence</th><th>Remediation</th></tr>")
    for f in res["findings"]:
        c = f["controls"]
        h.append(f"<tr><td>{e(f['finding_id'])}<br><small>{e(f['incident_id'])}</small></td><td>{e(f['title'])}<br><small>{e(f['mitre'])} · {e(', '.join(f['affected_assets']))}</small></td>"
                 f"<td>{badge(f['risk_level'])}</td><td>{'<br>'.join(e(x['ref'] + ' ' + x['name']) for x in c['NIST_CSF_2.0'])}</td>"
                 f"<td>{'<br>'.join(e(x['ref'] + ' ' + x['name']) for x in c['ISO_27001_2022'])}</td><td>{'<br>'.join(e(x) for x in f['evidence'])}</td>"
                 f"<td><ol>{''.join(f'<li>{e(r)}</li>' for r in f['remediation'])}</ol></td></tr>")
    h.append("</table></html>")
    return "".join(h)
