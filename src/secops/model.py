"""Training + evaluation of the suspicious-activity detector (Task 1)."""
import json
from datetime import datetime, timezone

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier, RandomForestClassifier
from sklearn.inspection import permutation_importance
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (average_precision_score, confusion_matrix, f1_score, precision_recall_curve,
                             precision_score, recall_score, roc_auc_score)
from sklearn.model_selection import StratifiedKFold, cross_val_predict
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler

from .config import DATASET, HOLDOUT, METRICS_PATH, MODEL_DIR, MODEL_PATH
from .connectors import normalize_events
from .features import BEHAVIOUR_COLS, FEATURE_COLS, build_features

SEED = 42


def candidates():
    return {
        "logistic_regression": make_pipeline(StandardScaler(), LogisticRegression(max_iter=3000, class_weight="balanced")),
        "random_forest": RandomForestClassifier(n_estimators=300, min_samples_leaf=2, class_weight="balanced_subsample",
                                                n_jobs=-1, random_state=SEED),
        "hist_gradient_boosting": HistGradientBoostingClassifier(max_iter=250, learning_rate=0.08,
                                                                 class_weight="balanced", random_state=SEED),
    }


def _metrics(y, prob, thr):
    pred = (prob >= thr).astype(int)
    tn, fp, fn, tp = confusion_matrix(y, pred, labels=[0, 1]).ravel()
    return {"precision": round(precision_score(y, pred, zero_division=0), 4),
            "recall": round(recall_score(y, pred), 4), "f1": round(f1_score(y, pred), 4),
            "roc_auc": round(roc_auc_score(y, prob), 4), "pr_auc": round(average_precision_score(y, prob), 4),
            "false_positive_rate": round(fp / max(fp + tn, 1), 5),
            "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)}}


def _best_f1_threshold(y, prob):
    p, r, t = precision_recall_curve(y, prob)
    f1 = 2 * p[:-1] * r[:-1] / np.clip(p[:-1] + r[:-1], 1e-9, None)
    return float(t[int(np.argmax(f1))])


def train(dataset=DATASET) -> dict:
    raw = pd.read_csv(dataset)
    gt = raw[["label", "incident_id", "attack_type"]].copy()
    df = normalize_events(raw.drop(columns=["label", "incident_id", "attack_type"]))
    df["event_id"] = np.arange(len(df))
    df = pd.concat([df, gt], axis=1)
    df = build_features(df)                      # sorted by time; windows only look backwards

    # temporal hold-out: first 70% of days train, last 30% test (never shuffled across time)
    days = np.sort(df["timestamp"].dt.normalize().unique())
    cut = days[int(len(days) * 0.7)]
    tr, te = df[df["timestamp"] < cut], df[df["timestamp"] >= cut]
    ytr, yte = tr["label"].to_numpy(), te["label"].to_numpy()

    # ---- model selection on TRAIN only (5-fold OOF), threshold also chosen on OOF predictions
    skf = StratifiedKFold(5, shuffle=True, random_state=SEED)
    sel, oof_store = {}, {}
    for name, m in candidates().items():
        oof = cross_val_predict(m, tr[FEATURE_COLS], ytr, cv=skf, method="predict_proba")[:, 1]
        oof_store[name] = oof
        sel[name] = {"cv_pr_auc": round(average_precision_score(ytr, oof), 4),
                     "cv_f1_at_best_thr": round(f1_score(ytr, oof >= _best_f1_threshold(ytr, oof)), 4)}
    best = max(sel, key=lambda k: sel[k]["cv_pr_auc"])
    thr = _best_f1_threshold(ytr, oof_store[best])

    model = candidates()[best].fit(tr[FEATURE_COLS], ytr)
    prob = model.predict_proba(te[FEATURE_COLS])[:, 1]
    test = _metrics(yte, prob, thr)

    # ---- diagnostics: per-scenario recall, false-positive anatomy, baselines, ablation, importance
    te = te.assign(prob=prob, pred=(prob >= thr).astype(int))
    per_scn = {a: {"events": int(len(g)), "recall": round(float(g["pred"].mean()), 4)}
               for a, g in te[te["label"] == 1].groupby("attack_type")}
    fps = te[(te["pred"] == 1) & (te["label"] == 0)]
    fp_anat = {"total": int(len(fps)),
               "by_event_type": {k: int(v) for k, v in fps["event_type"].value_counts().items()},
               "internal_source": int((fps["src_internal"] == 1).sum())}
    fns = te[(te["pred"] == 0) & (te["label"] == 1)]
    fn_anat = {"total": int(len(fns)), "by_event_type": {k: int(v) for k, v in fns["event_type"].value_counts().items()}}

    baseline = _metrics(yte, te["severity_num"].to_numpy() / 4, 0.5)     # "alert if tool severity >= medium"
    m_beh = candidates()[best].fit(tr[BEHAVIOUR_COLS], ytr)
    p_beh = m_beh.predict_proba(te[BEHAVIOUR_COLS])[:, 1]
    ablation = _metrics(yte, p_beh, _best_f1_threshold(ytr, cross_val_predict(
        candidates()[best], tr[BEHAVIOUR_COLS], ytr, cv=skf, method="predict_proba")[:, 1]))

    pi = permutation_importance(model, te[FEATURE_COLS], yte, scoring="average_precision",
                                n_repeats=3, random_state=SEED, n_jobs=-1)
    imp = sorted(zip(FEATURE_COLS, pi.importances_mean), key=lambda x: -x[1])[:12]

    metrics = {
        "trained_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "dataset": {"rows": int(len(df)), "attack_events": int(df["label"].sum()),
                    "attack_rate": round(float(df["label"].mean()), 4),
                    "ground_truth_incidents": int(df.loc[df["label"] == 1, "incident_id"].nunique()),
                    "train_rows": int(len(tr)), "test_rows": int(len(te)), "split_date": str(cut)[:10]},
        "model_selection_cv_on_train": sel, "selected_model": best, "threshold": round(thr, 4),
        "test_metrics": test, "baseline_tool_severity_rule": baseline,
        "ablation_behaviour_features_only": ablation,
        "per_attack_type_recall": per_scn, "false_positives": fp_anat, "false_negatives": fn_anat,
        "top_permutation_importance": [{"feature": f, "drop_in_pr_auc": round(float(v), 4)} for f, v in imp],
    }
    MODEL_DIR.mkdir(exist_ok=True)
    joblib.dump({"model": model, "features": FEATURE_COLS, "threshold": thr, "name": best}, MODEL_PATH)
    METRICS_PATH.write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    # hold-out file (ground truth stripped is NOT done: kept so demos can score correlation too)
    HOLDOUT.write_text(raw[pd.to_datetime(raw["timestamp"]) >= cut].to_csv(index=False), encoding="utf-8")
    return metrics


class Detector:
    def __init__(self, path=MODEL_PATH):
        if not path.exists():
            raise FileNotFoundError("Model not found. Run: python -m secops.cli all")
        b = joblib.load(path)
        self.model, self.features, self.threshold, self.name = b["model"], b["features"], b["threshold"], b["name"]

    def score(self, feats: pd.DataFrame) -> np.ndarray:
        return self.model.predict_proba(feats[self.features])[:, 1]
