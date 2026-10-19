"""Demo: side-by-side features + model score for a normal vs an attack event.
Run:  python demo_compare.py   (with PYTHONPATH=src)"""
import numpy as np
import pandas as pd

from secops.connectors import normalize_events
from secops.features import build_features
from secops.model import Detector

raw = pd.read_csv("data/holdout_logs.csv")
gt = raw[["label", "attack_type"]].reset_index(drop=True)
df = normalize_events(raw.drop(columns=["label", "incident_id", "attack_type"]))
df["event_id"] = np.arange(len(df))
df = pd.concat([df, gt], axis=1)
f = build_features(df)
det = Detector()
f["prob"] = det.score(f)

show = ["event_type", "src_ip", "dst_asset", "hour", "src_internal", "n_src_5m", "n_failed_src_5m",
        "n_ports_src_5m", "n_deny_src_5m", "n_same_type_src_5m", "iat_cv", "log_bytes_src_5m", "prob"]
pick = {}
# normal event: a login_failed that is NOT an attack (typo) with the most failures
n = f[(f.label == 0) & (f.event_type == "login_failed")].sort_values("n_failed_src_5m").iloc[-1]
a = f[(f.label == 1) & (f.attack_type == "brute_force") & (f.event_type == "login_failed")].sort_values("n_failed_src_5m").iloc[-1]
s_norm = f[(f.label == 0) & (f.src_ip == "10.0.50.5")].iloc[-1]       # authorised scanner
s_att = f[(f.label == 1) & (f.attack_type == "recon_scan")].sort_values("n_ports_src_5m").iloc[-1]
rows = {"NORMAL: typo'd password": n, "ATTACK: brute force": a,
        "NORMAL: authorised scanner": s_norm, "ATTACK: recon scan": s_att}
out = pd.DataFrame({k: v[show] for k, v in rows.items()})
print(out.to_string())
print(f"\nAlert threshold = {det.threshold:.2f}  (prob >= threshold -> alert)")
