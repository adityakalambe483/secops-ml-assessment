"""Central configuration: paths, schema constants, asset inventory."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DATA_DIR = ROOT / "data"
MODEL_DIR = ROOT / "models"
REPORT_DIR = ROOT / "reports"

DATASET = DATA_DIR / "security_logs.csv"
HOLDOUT = DATA_DIR / "holdout_logs.csv"          # temporal test split, used for demos
TI_FEED = DATA_DIR / "threat_intel_feed.csv"
MODEL_PATH = MODEL_DIR / "detector.joblib"
METRICS_PATH = MODEL_DIR / "metrics.json"

EVENT_TYPES = [
    "login_success", "login_failed", "web_request", "file_access", "dns_query",
    "firewall_deny", "port_scan_detected", "priv_escalation", "large_transfer",
    "malware_detected", "sql_injection_attempt", "new_account_created", "service_start",
]
STATUSES = ["success", "failure", "blocked"]
SEVERITIES = ["info", "low", "medium", "high", "critical"]
SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITIES)}

REQUIRED_COLUMNS = ["timestamp", "src_ip", "dst_asset", "dst_port", "event_type",
                    "user", "bytes_out", "status"]
MAX_EVENTS = 50_000

# Asset inventory (name -> IP). Used by the correlation engine to follow an attacker
# who pivots from "attacker -> asset" to "asset -> outside".
ASSETS = {
    "web-01": "10.0.1.10", "app-01": "10.0.1.11", "db-01": "10.0.2.20",
    "file-01": "10.0.2.30", "ad-01": "10.0.3.5", "vpn-gw": "10.0.0.1",
    "backup-01": "10.0.9.9",
}
ASSET_IP_TO_NAME = {v: k for k, v in ASSETS.items()}

# Window (seconds) for behavioural features and correlation rules
FEATURE_WINDOW_S = 300
CORR_SAME_SRC_GAP_S = 900       # alerts from the same source within 15 min -> same incident
CORR_SAME_ASSET_GAP_S = 300     # alerts on the same asset within 5 min -> same incident
CORR_PIVOT_GAP_S = 3600         # attacker -> asset, then asset acts as a source within 60 min
