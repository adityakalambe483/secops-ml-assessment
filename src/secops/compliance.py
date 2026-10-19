"""Compliance mapping (Task 3): detected incidents -> findings with NIST CSF / ISO 27001 controls."""
from .knowledge import CATEGORIES, RISK


def build_findings(incidents: list[dict]) -> list[dict]:
    findings, n = [], 0
    for inc in incidents:
        alerts = inc["_alerts"]
        for cat, count in inc["categories"].items():
            k = CATEGORIES[cat]
            s = alerts[alerts["category"] == cat]
            risk = k["risk"]
            if len(inc["stages"]) >= 2:
                risk = min(risk + 1, 4)                    # part of a multi-stage chain
            if inc.get("threat_intel_hits"):
                risk = min(risk + 1, 4) if risk < 4 else risk
            if count < 3 and cat in ("reconnaissance", "credential_attack", "anomalous_activity"):
                risk = max(risk - 1, 0)                    # a couple of events is weak evidence
            n += 1
            findings.append({
                "finding_id": f"F-{n:04d}", "incident_id": inc["incident_id"], "category": cat,
                "title": k["title"], "risk_level": RISK[risk], "risk_rank": risk,
                "mitre": k["mitre"], "affected_assets": sorted(s["dst_asset"].unique().tolist()),
                "source_ips": sorted(s["src_ip"].unique().tolist()), "n_events": int(count),
                "first_seen": s["timestamp"].iloc[0].isoformat(), "last_seen": s["timestamp"].iloc[-1].isoformat(),
                "evidence": [r for r in inc["reasoning"] if r.startswith(f"[{k['title']}]")][:1]
                            + [f"event_ids: {s['event_id'].astype(int).tolist()[:10]}"
                               + (" …" if count > 10 else "")],
                "controls": {"NIST_CSF_2.0": [{"ref": r, "name": nme} for r, nme in k["nist"]],
                             "ISO_27001_2022": [{"ref": r, "name": nme} for r, nme in k["iso"]]},
                "remediation": k["remediation"],
            })
    findings.sort(key=lambda f: (-f["risk_rank"], f["first_seen"]))
    return findings
