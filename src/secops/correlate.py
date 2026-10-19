"""Alert correlation (Task 2): group related alerts into incidents and explain why."""
from collections import Counter

import numpy as np
import pandas as pd

from .config import (ASSET_IP_TO_NAME, CORR_PIVOT_GAP_S, CORR_SAME_ASSET_GAP_S, CORR_SAME_SRC_GAP_S)
from .knowledge import CATEGORIES, RISK, STAGE_ORDER, categorize


class _UF:
    def __init__(self, n): self.p = list(range(n))
    def find(self, x):
        while self.p[x] != x:
            self.p[x] = self.p[self.p[x]]; x = self.p[x]
        return x
    def union(self, a, b): self.p[self.find(a)] = self.find(b)


def correlate(alerts: pd.DataFrame) -> list[dict]:
    """alerts: rows flagged by the model (needs timestamp, src_ip, dst_asset, event_type, event_id, prob...).

    Three linking rules (any one links two alerts):
      R1  same source IP, gap <= 15 min                       (one actor, one campaign)
      R2  same target asset, gap <= 5 min, both from non-internal sources   (distributed / multi-IP attack)
      R3  pivot: alert B's source is the asset (by IP) that alert A targeted, B within 60 min after A
          (attacker compromises a host, then the host exfiltrates / beacons)
    """
    if alerts.empty:
        return []
    a = alerts.sort_values("timestamp").reset_index(drop=True).copy()
    a["category"] = [categorize(e, bool(i)) for e, i in zip(a["event_type"], a["src_internal"])]
    ts = (a["timestamp"].astype("datetime64[ns]").astype("int64") // 10**9).to_numpy()
    src, asset, internal = a["src_ip"].to_numpy(), a["dst_asset"].to_numpy(), a["src_internal"].to_numpy()
    asset_of_src = np.array([ASSET_IP_TO_NAME.get(s) for s in src], dtype=object)
    uf = _UF(len(a))
    for i in range(len(a)):
        for j in range(i - 1, -1, -1):
            dt = ts[i] - ts[j]
            if dt > CORR_PIVOT_GAP_S:
                break
            if dt <= CORR_SAME_SRC_GAP_S and src[i] == src[j]:
                uf.union(i, j)
            elif dt <= CORR_SAME_ASSET_GAP_S and asset[i] == asset[j] and not internal[i] and not internal[j]:
                uf.union(i, j)
            elif asset_of_src[i] is not None and asset_of_src[i] == asset[j]:
                uf.union(i, j)
    a["_g"] = [uf.find(i) for i in range(len(a))]

    incidents = []
    for _, g in a.groupby("_g"):
        incidents.append(_build_incident(g.sort_values("timestamp")))
    incidents.sort(key=lambda x: x["start"])
    for n, inc in enumerate(incidents, 1):
        inc["incident_id"] = f"INC-{n:04d}"
    return incidents


def _severity(cats: set, n_alerts: int) -> int:
    base = max(CATEGORIES[c]["risk"] for c in cats)
    stages = {CATEGORIES[c]["stage_name"] for c in cats} - {"Unclassified"}
    if len(stages) >= 3:
        return 4
    if len(stages) == 2:
        base += 1
    if n_alerts < 3 and base <= 2:
        base = max(base - 1, 0)
    return min(base, 4)


def _fmt_dur(s: float) -> str:
    return f"{int(s)}s" if s < 120 else f"{s / 60:.1f} min"


def _build_incident(g: pd.DataFrame) -> dict:
    start, end = g["timestamp"].iloc[0], g["timestamp"].iloc[-1]
    dur = (end - start).total_seconds()
    cats = Counter(g["category"])
    stages = sorted({CATEGORIES[c]["stage_name"] for c in cats}, key=STAGE_ORDER.index)
    sev = _severity(set(cats), len(g))
    reasons = []
    for cat, n in cats.most_common():
        s = g[g["category"] == cat]
        d = (s["timestamp"].iloc[-1] - s["timestamp"].iloc[0]).total_seconds()
        srcs = ", ".join(sorted(s["src_ip"].unique())[:3]); tgts = ", ".join(sorted(s["dst_asset"].unique())[:3])
        if cat == "credential_attack":
            r = (f"{n} failed logins from {srcs} against {tgts} within {_fmt_dur(d)} "
                 f"({s['user'].nunique()} distinct account(s)); peak {int(s['n_failed_src_5m'].max())} failures in a 5-min window")
        elif cat == "suspicious_login":
            r = f"successful login for '{s['user'].iloc[0]}' from {srcs} after hostile activity from the same source"
        elif cat == "reconnaissance":
            r = (f"{n} blocked/scan events from {srcs} touching up to {int(s['n_ports_src_5m'].max())} distinct ports "
                 f"in a 5-min window against {tgts}")
        elif cat == "web_attack":
            r = (f"{n} SQL-injection attempts from {srcs} on {tgts} over {_fmt_dur(d)} "
                 f"({int((s['status'] == 'success').sum())} not blocked)")
        elif cat == "privilege_escalation":
            r = f"privilege escalation by '{s['user'].iloc[0]}' on {tgts}, occurring after earlier alerts in this incident"
        elif cat == "persistence_account":
            r = f"new account '{s['user'].iloc[0]}' created on {tgts} during hostile activity"
        elif cat == "malware":
            r = f"malware detection on {tgts} (source host {srcs})"
        elif cat == "c2_beaconing":
            r = (f"{n} near-periodic outbound connections from internal host {srcs} "
                 f"(inter-arrival CV≈{s['iat_cv'].median():.2f}, low variance = automated beaconing)")
        elif cat == "data_staging":
            r = f"{n} file-access events by {s['user'].nunique()} user(s) from {srcs} within {_fmt_dur(d)} (peak {int(s['n_src_5m'].max())} events in 5 min, off-hours={bool(s['off_hours'].iloc[0])})"
        elif cat == "data_exfiltration":
            r = f"{s['bytes_out'].sum() / 1e6:,.0f} MB sent out in {n} transfer(s) from {srcs} to {tgts}"
        else:
            r = f"{n} anomalous event(s) from {srcs}"
        reasons.append(f"[{CATEGORIES[cat]['title']}] {r}.")
    if len(stages) > 1:
        reasons.append("Multi-stage chain: " + " → ".join(stages) + " – linked by shared source IP / pivot through compromised asset.")
    reasons.append(f"Model confidence: mean P(suspicious)={g['prob'].mean():.2f}, min={g['prob'].min():.2f}.")
    ev_cols = ["event_id", "timestamp", "src_ip", "dst_asset", "dst_port", "event_type", "user", "bytes_out", "status", "prob"]
    top = g.sort_values("prob", ascending=False).head(5).sort_values("timestamp")[ev_cols]
    return {
        "start": start.isoformat(), "end": end.isoformat(), "duration_s": dur,
        "src_ips": sorted(g["src_ip"].unique().tolist()), "assets": sorted(g["dst_asset"].unique().tolist()),
        "n_alerts": int(len(g)), "categories": dict(cats), "stages": stages,
        "severity": RISK[sev], "severity_rank": sev, "mean_prob": round(float(g["prob"].mean()), 4),
        "reasoning": reasons,
        "evidence": [{**{k: (v.isoformat() if k == "timestamp" else v) for k, v in r.items()}}
                     for r in top.to_dict("records")],
        "event_ids": g["event_id"].astype(int).tolist(),
        "_alerts": g,
    }


def score_correlation(incidents: list[dict], truth: pd.DataFrame) -> dict:
    """Objective check of correlation against ground-truth incident ids (only for labelled data).

    truth: DataFrame with event_id, incident_id for attack events (label==1).
    """
    gt = truth[truth["incident_id"].astype(str).str.startswith("GT-")].set_index("event_id")["incident_id"]
    if gt.empty:
        return {}
    ev2inc = {e: inc["incident_id"] for inc in incidents for e in inc["event_ids"]}
    purities, frag = [], {}
    for inc in incidents:
        labels = [gt.get(e) for e in inc["event_ids"]]
        c = Counter(l for l in labels if l)
        purities.append(max(c.values()) / len(labels) if c else 0.0)
    for gid, evs in gt.groupby(gt).groups.items():
        homes = Counter(ev2inc.get(e) for e in evs if e in ev2inc)
        frag[gid] = {"n_clusters": len(homes), "best_share": (max(homes.values()) / len(evs)) if homes else 0.0}
    n = len(frag)
    return {"ground_truth_incidents_in_data": n, "detected_incidents": len(incidents),
            "clusters_with_no_true_attack_events": int(sum(p == 0 for p in purities)),
            "mean_purity_of_clusters_containing_attacks": round(float(np.mean([p for p in purities if p > 0] or [0])), 4),
            "gt_incidents_recovered_in_single_cluster_pct": round(100 * sum(v["n_clusters"] == 1 and v["best_share"] >= 0.8 for v in frag.values()) / n, 1),
            "gt_incidents_split_across_clusters": sum(v["n_clusters"] > 1 for v in frag.values()),
            "gt_incidents_missed": sum(v["n_clusters"] == 0 for v in frag.values())}
