"""REST API (Task 4). Run: uvicorn secops.api:app --reload  ->  docs at /docs"""
import ipaddress
import json
from typing import Literal

import pandas as pd
from fastapi import FastAPI, File, HTTPException, Query, UploadFile
from fastapi.responses import HTMLResponse, PlainTextResponse
from pydantic import BaseModel, Field, field_validator

from .config import EVENT_TYPES, HOLDOUT, MAX_EVENTS, MODEL_PATH, SEVERITIES, STATUSES
from .connectors import FileLogConnector, LogValidationError, ThreatIntelConnector
from .pipeline import analyze
from .report import to_html, to_markdown

app = FastAPI(title="SecOps ML Analyzer", version="1.0.0",
              description="Detects suspicious activity in security logs, correlates alerts into incidents and maps findings to NIST CSF / ISO 27001.")
EventType = Literal[tuple(EVENT_TYPES)]  # type: ignore[valid-type]


class LogEvent(BaseModel):
    timestamp: str = Field(..., examples=["2026-09-20T02:14:05"])
    src_ip: str
    dst_asset: str = Field(..., min_length=1, max_length=64)
    dst_port: int = Field(..., ge=0, le=65535)
    event_type: EventType
    user: str = Field("-", max_length=64)
    bytes_out: float = Field(0, ge=0)
    status: Literal[tuple(STATUSES)]  # type: ignore[valid-type]
    severity: Literal[tuple(SEVERITIES)] = "info"  # type: ignore[valid-type]

    @field_validator("src_ip")
    @classmethod
    def _ip(cls, v):
        try:
            ipaddress.ip_address(v)
        except ValueError:
            raise ValueError("not a valid IP address")
        return v


class AnalyzeRequest(BaseModel):
    events: list[LogEvent] = Field(..., min_length=1, max_length=MAX_EVENTS)
    enrich_threat_intel: bool = True


def _run(df: pd.DataFrame, enrich: bool) -> dict:
    if not MODEL_PATH.exists():
        raise HTTPException(503, "Model not trained yet. Run `python -m secops.cli all`.")
    try:
        return analyze(df, enrich=enrich)
    except LogValidationError as ex:
        raise HTTPException(422, str(ex))


@app.get("/health")
def health():
    return {"status": "ok", "model_ready": MODEL_PATH.exists()}


@app.post("/analyze", summary="Detect, correlate and map JSON events")
def analyze_json(req: AnalyzeRequest):
    return _run(pd.DataFrame([e.model_dump() for e in req.events]), req.enrich_threat_intel)


@app.post("/analyze/upload", summary="Upload a CSV/JSON/JSONL log file")
async def analyze_upload(file: UploadFile = File(...), enrich_threat_intel: bool = True):
    data = await file.read()
    if not data:
        raise HTTPException(400, "Empty file.")
    if len(data) > 25 * 1024 * 1024:
        raise HTTPException(413, "File too large (max 25 MB).")
    try:
        df = FileLogConnector().load(data)
    except LogValidationError as ex:
        raise HTTPException(422, str(ex))
    return _run(df, enrich_threat_intel)


@app.get("/analyze/sample", summary="Analyse the bundled hold-out logs")
def analyze_sample(enrich_threat_intel: bool = True):
    if not HOLDOUT.exists():
        raise HTTPException(503, "Hold-out data missing. Run `python -m secops.cli all`.")
    return _run(pd.read_csv(HOLDOUT), enrich_threat_intel)


@app.post("/report", summary="Generate HTML/Markdown report from JSON events")
def report(req: AnalyzeRequest, format: Literal["html", "md"] = Query("html")):
    res = _run(pd.DataFrame([e.model_dump() for e in req.events]), req.enrich_threat_intel)
    return HTMLResponse(to_html(res)) if format == "html" else PlainTextResponse(to_markdown(res))


@app.get("/threat-intel/{ip}", summary="Reputation lookup for one IP")
def threat_intel(ip: str):
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        raise HTTPException(422, "Invalid IP address.")
    return ThreatIntelConnector().lookup(ip)
