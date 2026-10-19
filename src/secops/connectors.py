"""Data connectors (Task 4): log ingestion + threat-intelligence enrichment, with validation."""
import io
import ipaddress
import json
import os
from pathlib import Path

import pandas as pd

from .config import EVENT_TYPES, MAX_EVENTS, REQUIRED_COLUMNS, SEVERITIES, STATUSES, TI_FEED


class LogValidationError(ValueError):
    """Raised when incoming logs do not match the expected schema."""


def _valid_ip(s) -> bool:
    try:
        ipaddress.ip_address(str(s))
        return True
    except ValueError:
        return False


def normalize_events(df: pd.DataFrame) -> pd.DataFrame:
    """Validate + normalise a raw log DataFrame. Raises LogValidationError with a clear message."""
    if df is None or df.empty:
        raise LogValidationError("No events supplied.")
    if len(df) > MAX_EVENTS:
        raise LogValidationError(f"Too many events ({len(df)}); limit is {MAX_EVENTS}.")
    missing = [c for c in REQUIRED_COLUMNS if c not in df.columns]
    if missing:
        raise LogValidationError(f"Missing required column(s): {', '.join(missing)}")
    df = df.copy()
    ts = pd.to_datetime(df["timestamp"], errors="coerce", utc=True)
    if ts.isna().any():
        raise LogValidationError(f"{int(ts.isna().sum())} row(s) have an unparseable timestamp.")
    df["timestamp"] = ts.dt.tz_localize(None)
    bad_ip = ~df["src_ip"].map(_valid_ip)
    if bad_ip.any():
        raise LogValidationError(f"Invalid src_ip at row(s) {df.index[bad_ip].tolist()[:5]}.")
    bad_type = ~df["event_type"].isin(EVENT_TYPES)
    if bad_type.any():
        raise LogValidationError(f"Unknown event_type values: {sorted(df.loc[bad_type, 'event_type'].astype(str).unique())[:5]}")
    bad_status = ~df["status"].isin(STATUSES)
    if bad_status.any():
        raise LogValidationError(f"status must be one of {STATUSES}.")
    for col in ("dst_port", "bytes_out"):
        df[col] = pd.to_numeric(df[col], errors="coerce")
        if df[col].isna().any():
            raise LogValidationError(f"Column '{col}' must be numeric.")
    if ((df["dst_port"] < 0) | (df["dst_port"] > 65535)).any():
        raise LogValidationError("dst_port must be within 0-65535.")
    if (df["bytes_out"] < 0).any():
        raise LogValidationError("bytes_out must be >= 0.")
    df["dst_port"] = df["dst_port"].astype(int)
    df["bytes_out"] = df["bytes_out"].astype(float)
    df["dst_asset"] = df["dst_asset"].astype(str)
    df["user"] = df["user"].fillna("-").astype(str)
    if "severity" not in df.columns:
        df["severity"] = "info"
    df["severity"] = df["severity"].where(df["severity"].isin(SEVERITIES), "info")
    return df


class FileLogConnector:
    """Reads CSV / JSON / JSONL security logs from disk or from raw bytes (uploads)."""

    def load(self, source) -> pd.DataFrame:
        try:
            if isinstance(source, (bytes, bytearray)):
                text = bytes(source).decode("utf-8", errors="strict")
                if text.lstrip().startswith(("{", "[")):
                    df = self._json(text)
                else:
                    df = pd.read_csv(io.StringIO(text))
            else:
                p = Path(source)
                if not p.exists():
                    raise LogValidationError(f"File not found: {p}")
                if p.suffix.lower() in (".json", ".jsonl", ".ndjson"):
                    df = self._json(p.read_text(encoding="utf-8"))
                else:
                    df = pd.read_csv(p)
        except (UnicodeDecodeError, pd.errors.ParserError, pd.errors.EmptyDataError, json.JSONDecodeError) as e:
            raise LogValidationError(f"Could not parse log file: {e}") from e
        return normalize_events(df)

    @staticmethod
    def _json(text: str) -> pd.DataFrame:
        text = text.strip()
        if text.startswith("["):
            return pd.DataFrame(json.loads(text))
        if text.startswith("{") and "\n" not in text:
            obj = json.loads(text)
            return pd.DataFrame(obj["events"] if "events" in obj else [obj])
        return pd.DataFrame([json.loads(line) for line in text.splitlines() if line.strip()])


class ThreatIntelConnector:
    """IP reputation lookup.

    1. Local feed (CSV: ip,category,confidence,source) - always available, offline.
    2. Optional live lookup against AbuseIPDB when ABUSEIPDB_API_KEY is set in the environment
       (never hard-code keys). Private IPs are never sent to external services.
    """

    LIVE_LIMIT = 20

    def __init__(self, feed_path=TI_FEED, api_key: str | None = None):
        self.api_key = api_key if api_key is not None else os.getenv("ABUSEIPDB_API_KEY")
        self.feed = {}
        if Path(feed_path).exists():
            for r in pd.read_csv(feed_path).itertuples():
                self.feed[r.ip] = {"category": r.category, "confidence": int(r.confidence), "source": r.source}
        self._live_calls = 0

    def lookup(self, ip: str) -> dict:
        if ip in self.feed:
            return {"ip": ip, "listed": True, **self.feed[ip]}
        res = {"ip": ip, "listed": False, "category": None, "confidence": 0, "source": "local-feed"}
        try:
            private = ipaddress.ip_address(ip).is_private
        except ValueError:
            return res
        if self.api_key and not private and self._live_calls < self.LIVE_LIMIT:
            self._live_calls += 1
            try:
                import httpx
                r = httpx.get("https://api.abuseipdb.com/api/v2/check",
                              params={"ipAddress": ip, "maxAgeInDays": 90},
                              headers={"Key": self.api_key, "Accept": "application/json"}, timeout=5)
                r.raise_for_status()
                score = int(r.json()["data"]["abuseConfidenceScore"])
                res.update(listed=score >= 25, category="abuseipdb", confidence=score, source="abuseipdb-live")
            except Exception as e:  # network/auth/quota problems must never break the pipeline
                res["note"] = f"live lookup failed: {type(e).__name__}"
        return res
