"""CLI:  python -m secops.cli {generate|train|analyze|all|serve}"""
import argparse
import json

import pandas as pd

from .config import DATASET, HOLDOUT, REPORT_DIR


def _analyze(path, out_dir=REPORT_DIR):
    from .pipeline import analyze
    from .report import to_html, to_markdown
    res = analyze(pd.read_csv(path))
    out_dir.mkdir(exist_ok=True)
    (out_dir / "analysis.json").write_text(json.dumps(res, indent=2, default=str), encoding="utf-8")
    (out_dir / "security_report.md").write_text(to_markdown(res), encoding="utf-8")
    (out_dir / "security_report.html").write_text(to_html(res), encoding="utf-8")
    print(json.dumps(res["summary"], indent=2))
    if "correlation_evaluation" in res:
        print("correlation vs ground truth:", json.dumps(res["correlation_evaluation"], indent=2))
    print(f"report written to {out_dir}/")
    return res


def main():
    p = argparse.ArgumentParser(prog="secops")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("generate"); sub.add_parser("train"); sub.add_parser("all")
    a = sub.add_parser("analyze"); a.add_argument("--input", default=str(HOLDOUT))
    s = sub.add_parser("serve"); s.add_argument("--port", type=int, default=8000)
    args = p.parse_args()
    if args.cmd in ("generate", "all"):
        from .datagen import generate
        df = generate(); print(f"dataset: {len(df)} rows, {int(df.label.sum())} attack events -> {DATASET}")
    if args.cmd in ("train", "all"):
        from .model import train
        m = train(); print(json.dumps({k: m[k] for k in ("selected_model", "threshold", "test_metrics")}, indent=2))
    if args.cmd in ("analyze", "all"):
        _analyze(getattr(args, "input", HOLDOUT))
    if args.cmd == "serve":
        import uvicorn
        uvicorn.run("secops.api:app", host="127.0.0.1", port=args.port)


if __name__ == "__main__":
    main()
