"""Feature engineering: per-event fields + trailing-window behavioural features.

All window features look BACKWARD only (events at or before the current one), so the same code
works for batch analysis and streaming, and nothing from the future leaks into a prediction.
"""
import numpy as np
import pandas as pd

from .config import EVENT_TYPES, FEATURE_WINDOW_S, SEVERITY_RANK

PRIVILEGED_USERS = {"admin", "root", "www-data", "svc_backup", "svc_app", "backdoor"}

TYPE_COLS = [f"type_{t}" for t in EVENT_TYPES]
TOOL_COLS = TYPE_COLS + ["severity_num"]       # signals that depend on the source tool's own labelling
BEHAVIOUR_COLS = [
    "hour", "off_hours", "is_weekend", "dst_port", "log_bytes_out", "status_failure", "status_blocked",
    "src_internal", "user_privileged",
    "n_src_5m", "n_failed_src_5m", "n_ports_src_5m", "n_assets_src_5m", "n_deny_src_5m",
    "log_bytes_src_5m", "n_failed_asset_5m", "n_same_type_src_5m", "iat_mean", "iat_cv",
]
FEATURE_COLS = BEHAVIOUR_COLS + TOOL_COLS


def _win_sum(ts, groups, values, W):
    """Trailing-window sum of `values` per group (rows must be sorted by ts)."""
    out = np.zeros(len(ts))
    for _, idx in groups.items():
        t = ts[idx]
        lo = np.searchsorted(t, t - W, side="left")
        cs = np.concatenate([[0.0], np.cumsum(values[idx])])
        out[idx] = cs[np.arange(1, len(idx) + 1)] - cs[lo]
    return out


def _win_distinct(ts, groups, col, W):
    out = np.zeros(len(ts))
    for _, idx in groups.items():
        t = ts[idx]; v = col[idx]
        lo = np.searchsorted(t, t - W, side="left")
        for i in range(len(idx)):
            out[idx[i]] = np.unique(v[lo[i]:i + 1]).size
    return out


def build_features(df: pd.DataFrame) -> pd.DataFrame:
    """Return a copy sorted by time with an `event_id` (original row order) and FEATURE_COLS."""
    df = df.copy()
    if "event_id" not in df.columns:
        df["event_id"] = np.arange(len(df))
    df = df.sort_values(["timestamp", "event_id"], kind="stable").reset_index(drop=True)
    W = FEATURE_WINDOW_S
    ts = (df["timestamp"].astype("datetime64[ns]").astype("int64") // 10**9).to_numpy()

    df["hour"] = df["timestamp"].dt.hour + df["timestamp"].dt.minute / 60
    df["off_hours"] = ((df["timestamp"].dt.hour < 7) | (df["timestamp"].dt.hour >= 20)).astype(int)
    df["is_weekend"] = (df["timestamp"].dt.weekday >= 5).astype(int)
    df["log_bytes_out"] = np.log1p(df["bytes_out"])
    df["status_failure"] = (df["status"] == "failure").astype(int)
    df["status_blocked"] = (df["status"] == "blocked").astype(int)
    df["src_internal"] = df["src_ip"].str.startswith(("10.", "192.168.", "172.16.")).astype(int)
    df["user_privileged"] = df["user"].isin(PRIVILEGED_USERS).astype(int)
    df["severity_num"] = df["severity"].map(SEVERITY_RANK).fillna(0).astype(int)
    for t in EVENT_TYPES:
        df[f"type_{t}"] = (df["event_type"] == t).astype(int)

    by_src = df.groupby("src_ip", sort=False).indices
    by_asset = df.groupby("dst_asset", sort=False).indices
    by_src_type = df.groupby(["src_ip", "event_type"], sort=False).indices
    ones = np.ones(len(df))
    failed = (df["event_type"] == "login_failed").to_numpy(float)
    deny = df["event_type"].isin(["firewall_deny", "port_scan_detected"]).to_numpy(float)

    df["n_src_5m"] = _win_sum(ts, by_src, ones, W)
    df["n_failed_src_5m"] = _win_sum(ts, by_src, failed, W)
    df["n_deny_src_5m"] = _win_sum(ts, by_src, deny, W)
    df["log_bytes_src_5m"] = np.log1p(_win_sum(ts, by_src, df["bytes_out"].to_numpy(float), W))
    df["n_failed_asset_5m"] = _win_sum(ts, by_asset, failed, W)
    df["n_same_type_src_5m"] = _win_sum(ts, by_src_type, ones, W)
    df["n_ports_src_5m"] = _win_distinct(ts, by_src, df["dst_port"].to_numpy(), W)
    df["n_assets_src_5m"] = _win_distinct(ts, by_src, df["dst_asset"].to_numpy(), W)

    # beaconing: mean and coefficient-of-variation of the last 8 inter-arrival times per (src, type)
    iat = df.groupby(["src_ip", "event_type"], sort=False)["timestamp"].diff().dt.total_seconds()
    key = [df["src_ip"], df["event_type"]]
    roll = iat.groupby(key, sort=False)
    mean8 = roll.transform(lambda s: s.rolling(8, min_periods=4).mean())
    std8 = roll.transform(lambda s: s.rolling(8, min_periods=4).std())
    df["iat_mean"] = np.log1p(mean8.fillna(3600).clip(lower=0))
    df["iat_cv"] = (std8 / mean8.replace(0, np.nan)).fillna(5).clip(upper=5)
    return df
