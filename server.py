"""
Full-Stack FastAPI Backend Server (server.py)
=============================================
Exposes REST API endpoints connecting the custom web frontend to all 6 core
Python modules:
  1. data_preprocessing.py
  2. model_training.py
  3. prediction.py
  4. risk_engine.py
  5. database.py
  6. transcript_analyzer.py
  + test_suite.py

Run with:
  python server.py
Then open http://127.0.0.1:8000 in your browser.

Authors: Silvia Noatia (2026279652), Fatima Iqbal (2026187337)
Mentor: Dharmendra Kumar | Sharda University (CSCR2600 PBL-1)
"""

from __future__ import annotations

import random
from pathlib import Path
from typing import Any, Dict, List, Optional

import numpy as np
import pandas as pd
import uvicorn
from fastapi import FastAPI, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from data_preprocessing import (
    ALL_FEATURES,
    CATEGORICAL_FEATURES,
    CLASSES,
    CSV_PATH,
    FEATURE_METADATA,
    NUMERIC_FEATURES,
    load_and_clean_dataset,
    sanitize_phone_number,
)
from database import (
    export_table_to_csv_string,
    get_all_community_reports,
    get_dashboard_statistics,
    get_number_intelligence,
    init_database,
    submit_community_report,
    upvote_community_report,
)
from model_training import load_evaluation_metrics, train_and_evaluate_all
from prediction import (
    DEFAULT_CALL_FEATURES,
    PRESET_CALL_SCENARIOS,
    load_artifacts,
    predict_call_risk,
)
from risk_engine import evaluate_incoming_call
from test_suite import run_all_verification_checks
from transcript_analyzer import SAMPLE_TRANSCRIPTS, SCAM_CATEGORIES, analyze_transcript

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"
STATIC_DIR.mkdir(parents=True, exist_ok=True)

app = FastAPI(
    title="AI-Based Spam & Scam Call Detection System API",
    description="Multi-Signal Telecom Threat Intelligence & Call Forensics Platform (Sharda University CSCR2600 PBL-1)",
    version="2.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


class CallAnalyzeRequest(BaseModel):
    phone_number: str = Field(default="+91-98104-52391")
    calls_last_24h: int = Field(default=3, ge=0, le=500)
    calls_last_7d: int = Field(default=14, ge=0, le=3000)
    avg_call_duration_sec: float = Field(default=165.0, ge=0.0, le=3600.0)
    answer_rate: float = Field(default=0.86, ge=0.0, le=1.0)
    short_call_ratio: float = Field(default=0.08, ge=0.0, le=1.0)
    silence_initial_sec: float = Field(default=0.25, ge=0.0, le=15.0)
    unique_recipients_ratio: float = Field(default=0.24, ge=0.0, le=1.0)
    hour_of_day: int = Field(default=14, ge=0, le=23)
    number_age_days: int = Field(default=1120, ge=1, le=5000)
    prior_complaint_rate: float = Field(default=0.01, ge=0.0, le=1.0)
    prefix_type: str = Field(default="Domestic_Mobile")
    caller_line_type: str = Field(default="Mobile_SIM")
    in_contact_network: str = Field(default="Yes")
    cli_verification_status: str = Field(default="STIR_SHAKEN_A")
    model_name: Optional[str] = Field(default=None)
    transcript_text: Optional[str] = Field(default=None)
    persist_log: bool = Field(default=True)


class TranscriptAnalyzeRequest(BaseModel):
    transcript_text: str


class CommunityReportRequest(BaseModel):
    phone_number: str
    reported_category: str = Field(default="Scam")
    scam_subtype: str = Field(default="Bank KYC / OTP Phishing")
    claimed_identity: str = Field(default="")
    severity: int = Field(default=4, ge=1, le=5)
    reporter_comment: str = Field(default="")
    reporter_region: str = Field(default="Delhi NCR")


class EdgeSandboxRequest(BaseModel):
    raw_phone: str = Field(default="'+91 (981) 045-2391")
    unseen_prefix: str = Field(default="Satellite_Global_Gateway")
    test_transcript: str = Field(default="Urgent: Share your 6-digit OTP within 10 minutes to stop account freeze.")


@app.on_event("startup")
def startup_initialize() -> None:
    init_database()
    load_artifacts()


@app.get("/api/overview")
def api_overview() -> Dict[str, Any]:
    metrics = load_evaluation_metrics()
    dash = get_dashboard_statistics()
    return {
        "project": {
            "course_code": "CSCR2600 - Project-Based Learning (PBL) - 1",
            "title": "AI-Based Spam & Scam Call Detection System",
            "university": "Sharda University, Greater Noida",
            "school": "Sharda School of Computing Science and Engineering",
            "department": "Department of Computer Science & Engineering",
            "session": "2025 – 2026",
            "section": "MG2",
            "mentor": "Prof. Dharmendra Kumar",
            "team": [
                {
                    "name": "Silvia Noatia",
                    "id": "2026279652",
                    "role": "Designer and Developer",
                },
                {
                    "name": "Fatima Iqbal",
                    "id": "2026187337",
                    "role": "Design and Tester",
                },
            ],
        },
        "metrics_summary": {
            "best_model_name": metrics["best_model_name"],
            "best_accuracy": metrics["best_accuracy"],
            "best_f1_macro": metrics["best_f1_macro"],
            "best_roc_auc": metrics["best_roc_auc"],
            "dataset_rows": metrics["dataset_rows"],
            "models_trained": len(metrics["models"]),
            "models": metrics["models"],
        },
        "live_telemetry": {
            "total_calls_analyzed": dash["total_calls_analyzed"],
            "scam_calls_detected": dash["scam_calls_detected"],
            "spam_calls_detected": dash["spam_calls_detected"],
            "safe_calls_verified": dash["safe_calls_verified"],
            "total_community_reports": dash["total_community_reports"],
            "high_risk_watchlist_count": dash["high_risk_watchlist_count"],
        },
    }


@app.get("/api/presets")
def api_presets() -> Dict[str, Any]:
    return {
        "call_scenarios": PRESET_CALL_SCENARIOS,
        "default_features": DEFAULT_CALL_FEATURES,
        "feature_metadata": FEATURE_METADATA,
        "sample_transcripts": SAMPLE_TRANSCRIPTS,
        "scam_categories": [
            {
                "id": c["id"],
                "name": c["name"],
                "weight": c["weight"],
                "severity": c["severity"],
                "description": c["description"],
                "patterns": c["patterns"],
            }
            for c in SCAM_CATEGORIES
        ],
    }


@app.post("/api/predict")
def api_predict(req: CallAnalyzeRequest) -> Dict[str, Any]:
    caller_dict = req.model_dump()
    model_name = caller_dict.pop("model_name", None)
    transcript_text = caller_dict.pop("transcript_text", None)
    persist_log = caller_dict.pop("persist_log", True)

    transcript_res = None
    transcript_score = None
    if transcript_text and transcript_text.strip():
        transcript_res = analyze_transcript(transcript_text)
        transcript_score = transcript_res["transcript_risk_score"]

    evaluation = evaluate_incoming_call(
        caller_input=caller_dict,
        model_name=model_name,
        transcript_score=transcript_score,
        persist_log=persist_log,
    )
    evaluation["transcript_analysis"] = transcript_res
    return evaluation


@app.post("/api/simulate-stream")
def api_simulate_stream() -> Dict[str, Any]:
    """
    Simulates a realistic burst of 5 incoming calls across Safe, Spam, and Scam profiles,
    evaluating each through the ML & Risk Engines and logging to SQLite.
    """
    scenarios = list(PRESET_CALL_SCENARIOS.items())
    results: List[Dict[str, Any]] = []
    for name, item in scenarios:
        feats = dict(item["features"])
        # Add slight realistic jitter so each simulated call is unique
        feats["calls_last_24h"] = max(1, int(feats["calls_last_24h"] + random.randint(-3, 5)))
        feats["avg_call_duration_sec"] = round(max(4.0, float(feats["avg_call_duration_sec"]) + random.uniform(-12, 15)), 1)
        eval_res = evaluate_incoming_call(feats, persist_log=True)
        eval_res["scenario_name"] = name
        results.append(eval_res)
    return {
        "simulated_count": len(results),
        "results": results,
    }


@app.post("/api/transcript")
def api_transcript(req: TranscriptAnalyzeRequest) -> Dict[str, Any]:
    return analyze_transcript(req.transcript_text)


@app.get("/api/reputation")
def api_reputation(phone: str = Query(default="+91-92104-88319")) -> Dict[str, Any]:
    return get_number_intelligence(phone)


@app.get("/api/reports")
def api_list_reports(
    category: str = Query(default="All"),
    search: str = Query(default=""),
    limit: int = Query(default=40, ge=5, le=200),
) -> Dict[str, Any]:
    rows = get_all_community_reports(category=category, search=search, limit=limit)
    return {"count": len(rows), "reports": rows}


@app.post("/api/report")
def api_submit_report(req: CommunityReportRequest) -> Dict[str, Any]:
    updated_intel = submit_community_report(
        phone_number=req.phone_number,
        reported_category=req.reported_category,
        scam_subtype=req.scam_subtype,
        claimed_identity=req.claimed_identity,
        severity=req.severity,
        reporter_comment=req.reporter_comment,
        reporter_region=req.reporter_region,
    )
    return {
        "status": "success",
        "message": f"Report recorded for {updated_intel['phone_number']}. Reputation index recalculated.",
        "intelligence": updated_intel,
    }


@app.post("/api/report/{report_id}/upvote")
def api_upvote_report(report_id: int) -> Dict[str, Any]:
    updated_intel = upvote_community_report(report_id)
    if updated_intel is None:
        return {"status": "error", "message": "Report not found"}
    return {
        "status": "success",
        "message": f"Confirmed incident report #{report_id}. Reputation updated.",
        "intelligence": updated_intel,
    }


@app.get("/api/dashboard")
def api_dashboard() -> Dict[str, Any]:
    return get_dashboard_statistics()


@app.get("/api/export/{table_name}")
def api_export_table(table_name: str) -> Response:
    csv_data = export_table_to_csv_string(table_name)
    safe_name = table_name if table_name in ("call_logs", "community_reports", "number_reputation") else "call_logs"
    return Response(
        content=csv_data,
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{safe_name}_export.csv"'},
    )


@app.get("/api/dataset")
def api_dataset(
    label: str = Query(default="All"),
    search: str = Query(default=""),
    feature: str = Query(default="calls_last_24h"),
    limit: int = Query(default=50, ge=10, le=500),
    offset: int = Query(default=0, ge=0),
) -> Dict[str, Any]:
    df = load_and_clean_dataset()

    class_counts = df["label"].value_counts().to_dict()

    # Compute mean numeric feature values grouped by class
    grouped_means: Dict[str, Dict[str, float]] = {}
    for cls_name in CLASSES:
        sub = df[df["label"] == cls_name]
        grouped_means[cls_name] = {
            col: round(float(sub[col].mean()), 3) for col in NUMERIC_FEATURES
        }

    # Compute correlation matrix across numeric features
    corr_df = df[NUMERIC_FEATURES].corr().round(3)
    corr_matrix = {
        "features": NUMERIC_FEATURES,
        "matrix": corr_df.values.tolist(),
    }

    # Compute 12-bin histogram distribution for the selected numeric feature by class
    hist_feature = feature if feature in NUMERIC_FEATURES else "calls_last_24h"
    valid_vals = df[hist_feature].dropna()
    counts_all, bin_edges = np.histogram(valid_vals, bins=12)
    bin_labels = [f"{bin_edges[i]:.1f}–{bin_edges[i+1]:.1f}" for i in range(len(bin_edges) - 1)]
    feature_histogram = {
        "feature": hist_feature,
        "label": FEATURE_METADATA.get(hist_feature, {}).get("label", hist_feature),
        "bins": bin_labels,
        "by_class": {},
    }
    for cls_name in CLASSES:
        sub_vals = df[df["label"] == cls_name][hist_feature].dropna()
        c_vals, _ = np.histogram(sub_vals, bins=bin_edges)
        feature_histogram["by_class"][cls_name] = c_vals.tolist()

    # Categorical distribution by class
    cat_distributions: Dict[str, Dict[str, Dict[str, int]]] = {}
    for cat_col in CATEGORICAL_FEATURES:
        cat_distributions[cat_col] = {}
        for cls_name in CLASSES:
            sub = df[df["label"] == cls_name]
            cat_distributions[cat_col][cls_name] = (
                sub[cat_col].fillna("Missing").value_counts().to_dict()
            )

    filtered_df = df if label == "All" or label not in CLASSES else df[df["label"] == label]
    if search and search.strip():
        q = search.strip().lower()
        filtered_df = filtered_df[
            filtered_df["phone_number"].str.lower().str.contains(q, na=False)
            | filtered_df["prefix_type"].str.lower().str.contains(q, na=False)
            | filtered_df["caller_line_type"].str.lower().str.contains(q, na=False)
        ]

    total_filtered = len(filtered_df)
    slice_df = filtered_df.iloc[offset : offset + limit].copy()
    slice_df = slice_df.replace({np.nan: None})

    return {
        "total_rows": len(df),
        "filtered_rows": total_filtered,
        "offset": offset,
        "limit": limit,
        "class_counts": class_counts,
        "numeric_features": NUMERIC_FEATURES,
        "categorical_features": CATEGORICAL_FEATURES,
        "feature_metadata": FEATURE_METADATA,
        "grouped_means": grouped_means,
        "feature_histogram": feature_histogram,
        "correlation": corr_matrix,
        "categorical_distributions": cat_distributions,
        "rows": slice_df.to_dict(orient="records"),
    }


@app.get("/api/dataset/download")
def api_dataset_download() -> FileResponse:
    if not CSV_PATH.exists():
        load_and_clean_dataset()
    return FileResponse(
        path=str(CSV_PATH),
        filename="calls_synthetic_6000.csv",
        media_type="text/csv",
    )


@app.get("/api/models")
def api_models() -> Dict[str, Any]:
    return load_evaluation_metrics()


@app.post("/api/models/retrain")
def api_retrain_models() -> Dict[str, Any]:
    summary = train_and_evaluate_all(force_regenerate_data=False)
    load_artifacts(force_reload=True)
    return summary


@app.get("/api/tests")
def api_tests() -> Dict[str, Any]:
    return run_all_verification_checks()


@app.post("/api/edge-test")
def api_edge_sandbox(req: EdgeSandboxRequest) -> Dict[str, Any]:
    """
    Interactive edge-case verification endpoint for Page 08.
    Tests phone sanitization, unseen categorical imputation, zero-history reputation,
    and regex transcript analysis on custom user-supplied edge cases.
    """
    sanitized = sanitize_phone_number(req.raw_phone)
    rep_intel = get_number_intelligence(sanitized)
    pred = predict_call_risk(
        {
            "phone_number": sanitized,
            "prefix_type": req.unseen_prefix,
            "silence_initial_sec": None,
        }
    )
    trans = analyze_transcript(req.test_transcript)
    return {
        "raw_phone": req.raw_phone,
        "sanitized_phone": sanitized,
        "unseen_prefix_tested": req.unseen_prefix,
        "reputation_lookup": {
            "known_in_db": rep_intel["known_in_db"],
            "reputation_risk_score": rep_intel["reputation_risk_score"],
            "status_tag": rep_intel["status_tag"],
        },
        "ml_prediction_with_unseen_category": {
            "predicted_label": pred["predicted_label"],
            "ml_risk_score": pred["ml_risk_score"],
            "probabilities": pred["probabilities"],
        },
        "transcript_check": {
            "score": trans["transcript_risk_score"],
            "verdict": trans["verdict_label"],
            "matched_count": trans["matched_count"],
        },
    }


app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


@app.get("/", response_class=HTMLResponse)
def serve_index() -> FileResponse:
    return FileResponse(str(STATIC_DIR / "index.html"))


if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000, log_level="info")
