import pandas as pd
import pytest
from fastapi.testclient import TestClient

from secops.config import HOLDOUT, MODEL_PATH
from secops.connectors import LogValidationError, ThreatIntelConnector, normalize_events
from secops.correlate import correlate
from secops.knowledge import CATEGORIES

pytestmark = pytest.mark.skipif(not MODEL_PATH.exists(), reason="run `python -m secops.cli all` first")


def ev(**kw):
    base = dict(timestamp="2026-09-20T02:00:00", src_ip="203.0.113.9", dst_asset="web-01", dst_port=22,
                event_type="login_failed", user="root", bytes_out=0, status="failure", severity="low")
    return base | kw


def test_every_category_has_controls_and_remediation():
    for k, v in CATEGORIES.items():
        assert v["nist"] and v["iso"] and v["remediation"], k


@pytest.mark.parametrize("bad", [dict(src_ip="999.1.1.1"), dict(event_type="nope"), dict(dst_port=70000),
                                 dict(bytes_out=-5), dict(timestamp="not-a-date"), dict(status="maybe")])
def test_validation_rejects_bad_rows(bad):
    with pytest.raises(LogValidationError):
        normalize_events(pd.DataFrame([ev(**bad)]))


def test_validation_missing_column():
    with pytest.raises(LogValidationError):
        normalize_events(pd.DataFrame([ev()]).drop(columns=["src_ip"]))


def test_correlation_groups_same_source_and_splits_distant_ones():
    rows = []
    for i in range(6):
        rows.append(ev(timestamp=f"2026-09-20T02:0{i}:00"))
    rows.append(ev(timestamp="2026-09-20T09:00:00", src_ip="198.51.100.7"))
    df = normalize_events(pd.DataFrame(rows))
    df["event_id"] = range(len(df)); df["prob"] = 0.9; df["src_internal"] = 0
    df["n_failed_src_5m"] = 5; df["n_ports_src_5m"] = 1; df["n_src_5m"] = 5; df["iat_cv"] = 1.0; df["off_hours"] = 1
    inc = correlate(df)
    assert len(inc) == 2 and sorted(i["n_alerts"] for i in inc) == [1, 6]


def test_threat_intel_offline_feed():
    ti = ThreatIntelConnector(api_key="")
    assert ti.lookup("10.0.0.5")["listed"] is False


@pytest.fixture(scope="module")
def client():
    from secops.api import app
    return TestClient(app)


def test_health(client):
    assert client.get("/health").json()["model_ready"] is True


def test_sample_analysis_finds_incidents_with_compliance(client):
    r = client.get("/analyze/sample").json()
    assert r["summary"]["incidents"] > 0 and r["findings"]
    f = r["findings"][0]
    assert f["controls"]["NIST_CSF_2.0"] and f["controls"]["ISO_27001_2022"] and f["remediation"]
    assert r["correlation_evaluation"]["gt_incidents_missed"] == 0


def test_api_validation_errors(client):
    assert client.post("/analyze", json={"events": []}).status_code == 422
    assert client.post("/analyze", json={"events": [ev(src_ip="bad")]}).status_code == 422
    assert client.post("/analyze/upload", files={"file": ("x.csv", b"")}).status_code == 400
    assert client.post("/analyze/upload", files={"file": ("x.csv", b"a,b\n1,2\n")}).status_code == 422
    assert client.get("/threat-intel/not-an-ip").status_code == 422


def test_api_json_brute_force_detected(client):
    events = [ev(timestamp=f"2026-09-20T02:{i // 60:02d}:{i % 60:02d}") for i in range(60)]
    events.append(ev(timestamp="2026-09-20T02:01:05", event_type="login_success", status="success", user="root"))
    r = client.post("/analyze", json={"events": events}).json()
    assert any("credential_attack" in i["categories"] for i in r["incidents"])


def test_report_html(client):
    ev_list = [ev(timestamp=f"2026-09-20T02:00:{i:02d}") for i in range(50)]
    r = client.post("/report?format=html", json={"events": ev_list})
    assert r.status_code == 200 and "Security Assessment Report" in r.text
