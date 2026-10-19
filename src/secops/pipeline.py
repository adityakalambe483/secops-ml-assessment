"""End-to-end analysis: validate -> features -> ML detection -> correlation -> TI -> compliance."""
import numpy as np
import pandas as pd

from .compliance import build_findings
from .connectors import ThreatIntelConnector, normalize_events
from .correlate import correlate, score_correlation
from .features import build_features
from .knowledge import RISK, categorize
from .model import Detector

_detector = None


def get_detector() -> Detector:
    global _detector
    if _detector is None:
        _detector = Detector()
    return _detector


def analyze(raw: pd.DataFrame, enrich: bool = True, ti: ThreatIntelConnector | None = None,
            detector: Detector | None = None) -> dict:
    truth = None
    if {"label", "incident_id"} <= set(raw.columns):          # labelled data: keep for evaluation only
        truth = raw[["incident_id", "label"]].copy().reset_index(drop=True)
        raw = raw.drop(columns=[c for c in ("label", "incident_id", "attack_type") if c in raw.columns])
    df = normalize_events(raw).reset_index(drop=True)
    df["event_id"] = np.arange(len(df))
    if truth is not None:
        truth["event_id"] = np.arange(len(truth))
    det = detector or get_detector()
    feats = build_features(df)
    feats["prob"] = det.score(feats)
    alerts = feats[feats["prob"] >= det.threshold].copy()
    incidents = correlate(alerts)

    if enrich and incidents:
        ti = ti or ThreatIntelConnector()
        cache = {}
        for inc in incidents:
            hits = []
            for ip in inc["src_ips"]:
                r = cache.setdefault(ip, ti.lookup(ip))
                if r["listed"]:
                    hits.append(r)
            inc["threat_intel_hits"] = hits
            if hits:
                inc["reasoning"].append("Threat intel: " + "; ".join(
                    f"{h['ip']} listed as {h['category']} (confidence {h['confidence']}, {h['source']})" for h in hits))
                if max(h["confidence"] for h in hits) >= 80:
                    inc["severity_rank"] = min(inc["severity_rank"] + 1, 4)
                    inc["severity"] = RISK[inc["severity_rank"]]
    findings = build_findings(incidents)

    by_sev = {s: 0 for s in RISK}
    for inc in incidents:
        by_sev[inc["severity"]] += 1
    result = {
        "summary": {"events_analyzed": int(len(df)), "alerts": int(len(alerts)), "incidents": len(incidents),
                    "findings": len(findings), "incidents_by_severity": by_sev,
                    "model": det.name, "threshold": round(float(det.threshold), 4),
                    "period": [df["timestamp"].min().isoformat(), df["timestamp"].max().isoformat()]},
        "alerts": [{"event_id": int(r.event_id), "timestamp": r.timestamp.isoformat(), "src_ip": r.src_ip,
                    "dst_asset": r.dst_asset, "event_type": r.event_type, "score": round(float(r.prob), 4),
                    "category": categorize(r.event_type, bool(r.src_internal))} for r in alerts.itertuples()],
        "incidents": [], "findings": findings,
    }
    for inc in incidents:
        inc = {k: v for k, v in inc.items() if k != "_alerts"} | {"threat_intel_hits": inc.get("threat_intel_hits", [])}
        result["incidents"].append(inc)
    result["incidents"].sort(key=lambda i: (-i["severity_rank"], i["start"]))
    if truth is not None:
        result["correlation_evaluation"] = score_correlation(incidents, truth[truth["label"] == 1])
    return result
