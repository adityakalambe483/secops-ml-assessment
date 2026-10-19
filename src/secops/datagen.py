"""Synthetic-but-realistic security log generator (Task 1).

No public dataset is bundled; instead we simulate 21 days of an SME network with
(a) noisy benign traffic that includes *hard negatives* (authorised vuln scans, nightly
backups, admin sudo, typo'd passwords, internet background noise) and
(b) six attack scenarios with ground-truth incident ids so detection AND correlation
can be evaluated objectively.

Everything uses reserved documentation IP ranges for attackers (RFC 5737).
"""
from datetime import datetime, timedelta

import numpy as np
import pandas as pd

from .config import ASSETS, DATASET, DATA_DIR, TI_FEED

SEV_BASE = {
    "login_success": 0, "login_failed": 1, "web_request": 0, "file_access": 0,
    "dns_query": 0, "firewall_deny": 1, "port_scan_detected": 2, "priv_escalation": 3,
    "large_transfer": 2, "malware_detected": 3, "sql_injection_attempt": 3,
    "new_account_created": 2, "service_start": 0,
}
SEV_NAMES = ["info", "low", "medium", "high", "critical"]


def generate(seed: int = 42, days: int = 21, out=DATASET) -> pd.DataFrame:
    rng = np.random.default_rng(seed)
    t0 = datetime(2026, 9, 1)
    rows = []

    def add(ts, src, asset, port, etype, user, nbytes, status, label=0, inc="", atype=""):
        rows.append((ts, src, asset, int(port), etype, user, int(nbytes), status, label, inc, atype))

    users = [f"user{i:02d}" for i in range(1, 41)]
    admins = ["admin", "svc_backup", "root"]
    ws = [(f"ws-{i:02d}", f"10.1.{i // 50}.{10 + i % 50}") for i in range(60)]
    attackers = ([f"203.0.113.{x}" for x in rng.choice(np.arange(1, 255), 14, replace=False)]
                 + [f"198.51.100.{x}" for x in rng.choice(np.arange(1, 255), 10, replace=False)]
                 + [f"192.0.2.{x}" for x in rng.choice(np.arange(1, 255), 6, replace=False)])
    benign_ext = []
    while len(benign_ext) < 800:
        a = int(rng.integers(11, 223))
        if a in (10, 127, 172, 192, 198, 203):
            continue
        benign_ext.append(f"{a}.{rng.integers(0, 256)}.{rng.integers(0, 256)}.{rng.integers(1, 255)}")
    asset_names = list(ASSETS)
    login_assets = ["web-01", "app-01", "file-01", "ad-01", "vpn-gw"]
    port_of = {"web-01": 443, "app-01": 8080, "file-01": 445, "ad-01": 389, "vpn-gw": 443,
               "db-01": 5432, "backup-01": 873}

    def bh(day, mu=13.0, sd=3.2):
        h = float(np.clip(rng.normal(mu, sd), 6, 21))
        return day + timedelta(seconds=h * 3600)

    # ------------------------------------------------------------------ benign
    for d in range(days):
        day = t0 + timedelta(days=d)
        f = 0.35 if day.weekday() >= 5 else 1.0
        for _ in range(int(420 * f)):                      # logins (+ occasional typo)
            wsn, wip = ws[rng.integers(len(ws))]
            a = login_assets[rng.integers(len(login_assets))]
            u = users[rng.integers(len(users))]
            t = bh(day)
            if rng.random() < 0.03:                         # mistyped password
                for k in range(int(rng.integers(1, 4))):
                    add(t, wip, a, port_of[a], "login_failed", u, 0, "failure")
                    t += timedelta(seconds=float(rng.integers(3, 20)))
            add(t, wip, a, port_of[a], "login_success", u, 0, "success")
        for _ in range(int(600 * f)):                      # web traffic from the internet
            add(bh(day, 14, 5), benign_ext[rng.integers(800)], "web-01", 443, "web_request",
                "-", rng.lognormal(9.5, 1.0), "success")
        for _ in range(int(250 * f)):                      # file access
            wsn, wip = ws[rng.integers(len(ws))]
            add(bh(day), wip, "file-01", 445, "file_access", users[rng.integers(40)],
                rng.lognormal(11, 1.5), "success")
        for _ in range(int(300 * f)):                      # dns
            wsn, wip = ws[rng.integers(len(ws))]
            add(bh(day), wip, "ad-01", 53, "dns_query", users[rng.integers(40)], 120, "success")
        for _ in range(60):                                # internet background noise
            ip = benign_ext[rng.integers(800)]
            for _k in range(int(rng.integers(1, 4))):
                add(day + timedelta(seconds=float(rng.uniform(0, 86400))), ip,
                    asset_names[rng.integers(len(asset_names))], int(rng.choice([22, 23, 80, 3389, 8080, 445])),
                    "firewall_deny", "-", 0, "blocked")
        for _ in range(int(20 * f)):                       # service starts
            add(bh(day), ASSETS[asset_names[rng.integers(5)]], "app-01", 0, "service_start",
                "svc_app", 0, "success")
        for _ in range(int(rng.integers(1, 4))):           # legit sudo by admins
            wsn, wip = ws[rng.integers(len(ws))]
            add(bh(day, 11, 2), wip, f"{wsn}", 22, "priv_escalation", admins[rng.integers(3)], 0, "success")
        if rng.random() < 0.5:                             # legit account creation (HR onboarding)
            add(bh(day, 10, 1), ASSETS["ad-01"], "ad-01", 389, "new_account_created", "admin", 0, "success")
        for _ in range(int(rng.integers(2, 5))):           # legit big file transfers
            wsn, wip = ws[rng.integers(len(ws))]
            add(bh(day, 14, 2), wip, "file-01", 445, "large_transfer", users[rng.integers(40)],
                rng.uniform(5e7, 4e8), "success")
        if rng.random() < 0.4:                             # AV false alarm (PUA)
            wsn, wip = ws[rng.integers(len(ws))]
            add(bh(day), wip, wsn, 0, "malware_detected", users[rng.integers(40)], 0, "blocked")
        # nightly backup
        add(day + timedelta(hours=2, minutes=float(rng.integers(0, 20))), ASSETS["db-01"], "backup-01",
            873, "large_transfer", "svc_backup", rng.normal(5e9, 3e8), "success")
        # weekly authorised vulnerability scan (internal scanner, 10.0.50.5)
        if day.weekday() == 0:
            t = day + timedelta(hours=3)
            for k in range(int(rng.integers(100, 160))):
                a = asset_names[rng.integers(len(asset_names))]
                add(t + timedelta(seconds=k * 0.8), "10.0.50.5", a, int(rng.integers(1, 10000)),
                    "port_scan_detected", "scanner", 0, "blocked")

    # ------------------------------------------------------------------ attacks
    inc_no = [0]

    def new_inc(atype):
        inc_no[0] += 1
        return f"GT-{inc_no[0]:03d}", atype

    def start_time():
        day = t0 + timedelta(days=int(rng.integers(0, days)))
        h = rng.uniform(0, 5) if rng.random() < 0.6 else rng.uniform(8, 20)
        return day + timedelta(hours=float(h))

    def brute(t, ip, inc, atype, success=None, asset=None):
        asset = asset or ["web-01", "vpn-gw", "ad-01"][rng.integers(3)]
        n = int(rng.integers(20, 80)); dur = float(rng.uniform(120, 360))
        target = users[rng.integers(40)] if rng.random() < 0.5 else None
        for k in range(n):
            add(t + timedelta(seconds=dur * k / n), ip, asset, port_of[asset], "login_failed",
                target or users[rng.integers(40)], 0, "failure", 1, inc, atype)
        success = rng.random() < 0.5 if success is None else success
        t_end = t + timedelta(seconds=dur + 20)
        if success:
            add(t_end, ip, asset, port_of[asset], "login_success", target or users[rng.integers(40)],
                0, "success", 1, inc, atype)
        return asset, t_end

    def scan(t, ip, inc, atype, n=None, asset=None):
        n = n or int(rng.integers(30, 200)); dur = float(rng.uniform(60, 180))
        asset = asset or asset_names[rng.integers(len(asset_names))]
        ports = rng.choice(np.arange(1, 65535), n, replace=False)
        for k in range(n):
            et = "firewall_deny" if rng.random() < 0.7 else "port_scan_detected"
            add(t + timedelta(seconds=dur * k / n), ip, asset, int(ports[k]), et, "-", 0,
                "blocked", 1, inc, atype)
        return t + timedelta(seconds=dur)

    plan = ["brute_force"] * 18 + ["recon_scan"] * 15 + ["web_attack"] * 12 + ["attack_chain"] * 10 \
        + ["malware_c2"] * 8 + ["insider_exfil"] * 7
    rng.shuffle(plan)
    for atype in plan:
        inc, _ = new_inc(atype)
        t = start_time(); ip = attackers[rng.integers(len(attackers))]
        if atype == "brute_force":
            brute(t, ip, inc, atype)
        elif atype == "recon_scan":
            scan(t, ip, inc, atype)
        elif atype == "web_attack":
            n = int(rng.integers(5, 26)); dur = float(rng.uniform(180, 600))
            for k in range(n):
                add(t + timedelta(seconds=dur * k / n), ip, "web-01", 443, "sql_injection_attempt", "-",
                    rng.lognormal(7, 0.8), "blocked" if rng.random() < 0.7 else "success", 1, inc, atype)
        elif atype == "attack_chain":
            t1 = scan(t, ip, inc, atype, n=40, asset="web-01")
            a, t2 = brute(t1 + timedelta(minutes=8), ip, inc, atype, success=True, asset="web-01")
            t3 = t2 + timedelta(minutes=float(rng.uniform(4, 8)))
            add(t3, ip, "web-01", 22, "priv_escalation", "www-data", 0, "success", 1, inc, atype)
            t4 = t3 + timedelta(minutes=float(rng.uniform(3, 6)))
            add(t4, ip, "web-01", 22, "new_account_created", "backdoor", 0, "success", 1, inc, atype)
            add(t4 + timedelta(minutes=float(rng.uniform(10, 25))), ASSETS["web-01"], "external-egress", 443,
                "large_transfer", "www-data", rng.uniform(2e8, 2e9), "success", 1, inc, atype)
        elif atype == "malware_c2":
            wsn, wip = ws[rng.integers(len(ws))]
            add(t, wip, wsn, 0, "malware_detected", users[rng.integers(40)], 0, "success", 1, inc, atype)
            period = float(rng.uniform(45, 90)); n = int(rng.integers(20, 60))
            for k in range(n):
                add(t + timedelta(seconds=60 + k * period + float(rng.normal(0, 4))), wip, "external-egress",
                    int(rng.choice([443, 8443])), "web_request", "-", rng.uniform(200, 600), "success",
                    1, inc, atype)
        elif atype == "insider_exfil":
            wsn, wip = ws[rng.integers(len(ws))]; u = users[rng.integers(40)]
            t = t.replace(hour=int(rng.integers(22, 24)), minute=int(rng.integers(0, 59)))
            n = int(rng.integers(60, 150))
            for k in range(n):
                add(t + timedelta(seconds=k * 2), wip, "file-01", 445, "file_access", u,
                    rng.lognormal(12, 1.0), "success", 1, inc, atype)
            for k in range(int(rng.integers(3, 7))):
                add(t + timedelta(minutes=6 + k * 3), wip, "external-egress", 443, "large_transfer", u,
                    rng.uniform(1e9, 8e9), "success", 1, inc, atype)

    df = pd.DataFrame(rows, columns=["timestamp", "src_ip", "dst_asset", "dst_port", "event_type",
                                     "user", "bytes_out", "status", "label", "incident_id", "attack_type"])
    df = df.sort_values("timestamp").reset_index(drop=True)
    # severity as emitted by the (noisy) source tool: base by type, +/-1 with p=0.15
    base = df["event_type"].map(SEV_BASE).to_numpy()
    jitter = np.where(rng.random(len(df)) < 0.15, rng.choice([-1, 1], len(df)), 0)
    df["severity"] = [SEV_NAMES[int(np.clip(b + j, 0, 4))] for b, j in zip(base, jitter)]
    df["timestamp"] = df["timestamp"].dt.strftime("%Y-%m-%dT%H:%M:%S")
    DATA_DIR.mkdir(exist_ok=True)
    df.to_csv(out, index=False)

    # synthetic threat-intel feed: ~60% of attacker IPs are listed (feed is intentionally incomplete)
    listed = rng.choice(attackers, int(len(attackers) * 0.6), replace=False)
    cats = ["scanner", "brute-force", "web-attacker", "c2"]
    ti = pd.DataFrame({"ip": listed, "category": [cats[i % 4] for i in range(len(listed))],
                       "confidence": rng.integers(60, 100, len(listed)),
                       "source": "synthetic-demo-feed"})
    ti.to_csv(TI_FEED, index=False)
    return df
