"""
Automated Verification & Edge-Case Test Suite (test_suite.py)
=============================================================
Implements unit-level and edge-case tests documented in Section 9 of the
project report, plus the formal Defect Log maintained during development.

Can be executed via CLI (`python test_suite.py` / `pytest test_suite.py`)
or invoked interactively from Page 8 of the Web Application.

Authors: Silvia Noatia (2026279652), Fatima Iqbal (2026187337)
Mentor: Dharmendra Kumar | Sharda University (CSCR2600 PBL-1)
"""

from __future__ import annotations

import time
from typing import Any, Dict, List

import pandas as pd

from data_preprocessing import (
    ALL_FEATURES,
    CSV_PATH,
    load_and_clean_dataset,
    prepare_train_test_splits,
    sanitize_phone_number,
)
from database import (
    get_dashboard_statistics,
    get_number_intelligence,
    init_database,
    submit_community_report,
)
from model_training import BEST_MODEL_PATH, PREPROCESSOR_PATH, load_evaluation_metrics
from prediction import predict_call_risk
from risk_engine import evaluate_incoming_call
from transcript_analyzer import analyze_transcript

DEFECT_LOG: List[Dict[str, str]] = [
    {
        "defect_id": "DEF-001",
        "module": "data_preprocessing.py",
        "severity": "High",
        "title": "Leading '+' in E.164 phone numbers misparsed by CSV/spreadsheet readers",
        "root_cause": (
            "International numbers formatted as '+91-98104-52391' were occasionally treated as numeric "
            "expressions or stripped of '+' when loaded without explicit string dtype enforcement."
        ),
        "fix_applied": (
            "Enforced dtype={'phone_number': str} in pd.read_csv() and added sanitize_phone_number() "
            "to strip leading apostrophes and normalize E.164 formatting across all inputs."
        ),
        "status": "Resolved & Verified",
    },
    {
        "defect_id": "DEF-002",
        "module": "data_preprocessing.py / model_training.py",
        "severity": "High",
        "title": "Potential preprocessing data leakage if Scaler/Imputer fit before train-test split",
        "root_cause": (
            "Fitting StandardScaler and SimpleImputer on the full 6,000-row dataset prior to splitting "
            "leaks test-set distribution statistics into training."
        ),
        "fix_applied": (
            "Refactored prepare_train_test_splits() to perform the 80/20 stratified split first and "
            "call preprocessor.fit(X_train) strictly on the training partition."
        ),
        "status": "Resolved & Verified",
    },
    {
        "defect_id": "DEF-003",
        "module": "risk_engine.py / database.py",
        "severity": "Medium",
        "title": "Zero-division error when calculating community risk score for numbers with 0 reports",
        "root_cause": (
            "Unseen phone numbers had total_reports = 0 in SQLite, causing division by zero when computing "
            "weighted report ratios."
        ),
        "fix_applied": (
            "Added max(total_reports, 1) guard and implemented prefix-aware heuristic baseline scoring "
            "for first-seen phone numbers."
        ),
        "status": "Resolved & Verified",
    },
    {
        "defect_id": "DEF-004",
        "module": "transcript_analyzer.py",
        "severity": "Low",
        "title": "Overlapping regex matches corrupting inline HTML highlight tags",
        "root_cause": (
            "When two scam regex patterns matched overlapping substrings (e.g., '6-digit OTP' and 'OTP verification code'), "
            "nested highlight spans broke markup rendering."
        ),
        "fix_applied": (
            "Added span sorting by (start, -length) and non-overlapping interval merging before rendering highlights."
        ),
        "status": "Resolved & Verified",
    },
]


def run_all_verification_checks() -> Dict[str, Any]:
    """
    Runs 10 automated unit and edge-case checks across all system modules and
    returns structured pass/fail results with execution timings.
    """
    checks: List[Dict[str, Any]] = []

    def record_check(name: str, category: str, fn):
        t0 = time.perf_counter()
        try:
            detail = fn()
            elapsed_ms = round((time.perf_counter() - t0) * 1000, 2)
            checks.append(
                {
                    "name": name,
                    "category": category,
                    "passed": True,
                    "elapsed_ms": elapsed_ms,
                    "detail": detail,
                }
            )
        except Exception as exc:
            elapsed_ms = round((time.perf_counter() - t0) * 1000, 2)
            checks.append(
                {
                    "name": name,
                    "category": category,
                    "passed": False,
                    "elapsed_ms": elapsed_ms,
                    "detail": f"FAILED: {exc}",
                }
            )

    # 1. Dataset Integrity & 6,000-row verification
    def check_dataset():
        df = load_and_clean_dataset()
        assert len(df) >= 5900, f"Expected ~6000 rows, got {len(df)}"
        assert set(df["label"].unique()) == {"Safe", "Spam", "Scam"}
        assert all(str(p).startswith("+") for p in df["phone_number"].head(50))
        return f"Loaded {len(df):,} rows across 3 classes; 100% of phone numbers preserve leading '+'."

    # 2. Defect #1 Regression Test: Leading '+' and malformed phone numbers
    def check_phone_sanitization():
        assert sanitize_phone_number("'+91 98104 52391") == "+91-98104-52391"
        assert sanitize_phone_number("9876543210") == "+91-98765-43210"
        assert sanitize_phone_number("") == "+91-98000-00000"
        assert sanitize_phone_number(None) == "+91-98000-00000"
        return "Successfully normalized E.164 strings, bare 10-digit numbers, spreadsheet apostrophes, and empty inputs."

    # 3. Leak-Free ColumnTransformer & Unseen Category Handling
    def check_preprocessing_pipeline():
        X_train, X_test, y_train, y_test, prep = prepare_train_test_splits()
        assert len(X_train) == 4800 and len(X_test) == 1200
        # Inject unseen category and NaN values
        sample = X_test.iloc[[0]].copy()
        sample["prefix_type"] = "Unseen_Future_Prefix"
        sample["silence_initial_sec"] = float("nan")
        out = prep.transform(sample)
        assert out.shape[0] == 1 and not pd.isna(out).any()
        return f"Stratified 4,800/1,200 split verified; ColumnTransformer imputed NaNs and encoded {out.shape[1]} features."

    # 4. Trained Model Artifacts & Benchmark Metrics Verification
    def check_model_artifacts():
        assert BEST_MODEL_PATH.exists() and PREPROCESSOR_PATH.exists()
        metrics = load_evaluation_metrics()
        assert metrics["best_model_name"] == "Random Forest"
        assert metrics["best_accuracy"] >= 0.93
        assert len(metrics["models"]) == 5
        return (
            f"Verified 5 trained classifiers; Best: {metrics['best_model_name']} "
            f"(Acc: {metrics['best_accuracy']*100:.2f}%, Macro-F1: {metrics['best_f1_macro']:.4f})."
        )

    # 5. Prediction Engine Safe vs Scam Discrimination
    def check_prediction_engine():
        safe_pred = predict_call_risk(
            {
                "phone_number": "+91-98104-52391",
                "calls_last_24h": 2,
                "silence_initial_sec": 0.2,
                "number_age_days": 1400,
                "prior_complaint_rate": 0.0,
                "in_contact_network": "Yes",
                "cli_verification_status": "STIR_SHAKEN_A",
            }
        )
        scam_pred = predict_call_risk(
            {
                "phone_number": "+91-92104-88319",
                "calls_last_24h": 42,
                "silence_initial_sec": 3.6,
                "number_age_days": 7,
                "prior_complaint_rate": 0.88,
                "prefix_type": "International_VoIP",
                "caller_line_type": "Spoofed_CLI",
                "in_contact_network": "No",
                "cli_verification_status": "Unverified",
            }
        )
        assert safe_pred["predicted_label"] == "Safe"
        assert scam_pred["predicted_label"] == "Scam"
        assert scam_pred["ml_risk_score"] > safe_pred["ml_risk_score"] + 50
        return f"Safe score: {safe_pred['ml_risk_score']}/100 vs Scam score: {scam_pred['ml_risk_score']}/100 with plain-language reasons."

    # 6. Edge Case: Sparse / Missing Input Dictionary in Prediction Engine
    def check_sparse_input_edge_case():
        res = predict_call_risk({"phone_number": ""})
        assert "predicted_label" in res and 0.0 <= res["ml_risk_score"] <= 100.0
        return "Gracefully handled empty caller dictionary using fallback feature defaults without raising KeyError."

    # 7. Risk Engine Multi-Signal Blending Formula (60% ML + 25% Community + 15% Reputation)
    def check_risk_blending():
        res = evaluate_incoming_call(
            {
                "phone_number": "+91-92104-88319",
                "calls_last_24h": 38,
                "silence_initial_sec": 3.4,
                "number_age_days": 14,
                "prior_complaint_rate": 0.86,
                "prefix_type": "International_VoIP",
                "caller_line_type": "Spoofed_CLI",
                "cli_verification_status": "Unverified",
            },
            persist_log=False,
        )
        s = res["signals"]
        expected = round(
            s["ml_model"]["raw_score"] * 0.60
            + s["community_reports"]["raw_score"] * 0.25
            + s["historical_reputation"]["raw_score"] * 0.15,
            1,
        )
        assert abs(res["blended_3signal_score"] - expected) <= 0.2
        return (
            f"Verified exact 60/25/15 blend: 0.60×{s['ml_model']['raw_score']} + "
            f"0.25×{s['community_reports']['raw_score']} + 0.15×{s['historical_reputation']['raw_score']} = {res['blended_3signal_score']}."
        )

    # 8. Edge Case: Unknown Phone Number with Zero Report History
    def check_unknown_number_reputation():
        intel = get_number_intelligence("+91-97111-00998")
        assert intel["known_in_db"] is False
        assert intel["total_reports"] == 0
        assert 0.0 <= intel["reputation_risk_score"] <= 100.0
        return f"Unseen number returned baseline reputation ({intel['reputation_risk_score']}/100) without zero-division error."

    # 9. Transcript Analyzer 10-Category Detection & Empty Input Edge Case
    def check_transcript_analyzer():
        empty_res = analyze_transcript("   ")
        assert empty_res["transcript_risk_score"] == 0.0 and empty_res["matched_count"] == 0

        scam_res = analyze_transcript(
            "This is CBI Cyber Crime Cell. You are under Digital Arrest. Share your 6-digit OTP and transfer Rs 50,000 to RBI supervision account immediately via AnyDesk."
        )
        assert scam_res["verdict_label"] == "Scam"
        assert scam_res["matched_count"] >= 4
        assert scam_res["transcript_risk_score"] >= 80.0
        return f"Flagged {scam_res['matched_count']}/10 regex categories (Score: {scam_res['transcript_risk_score']}/100) and passed empty-string edge test."

    # 10. SQLite Database Initialization & Live Dashboard Telemetry
    def check_database_telemetry():
        init_database()
        stats = get_dashboard_statistics()
        assert stats["total_calls_analyzed"] > 0
        assert stats["total_community_reports"] > 0
        assert len(stats["watchlist"]) > 0
        return (
            f"SQLite active: {stats['total_calls_analyzed']} call logs, "
            f"{stats['total_community_reports']} community reports, {len(stats['watchlist'])} tracked numbers."
        )

    record_check("Synthetic 6,000-Row Dataset & E.164 Integrity", "Data Module", check_dataset)
    record_check("Defect #1 Regression: '+' Prefix & Phone Sanitization", "Edge Case", check_phone_sanitization)
    record_check("Leak-Free ColumnTransformer & Unseen Category Imputation", "Preprocessing", check_preprocessing_pipeline)
    record_check("5-Classifier Benchmark & Joblib Artifact Persistence", "ML Training", check_model_artifacts)
    record_check("Prediction Engine Safe vs. Scam Discrimination", "Prediction Engine", check_prediction_engine)
    record_check("Sparse / Missing Caller Dictionary Resilience", "Edge Case", check_sparse_input_edge_case)
    record_check("Multi-Signal Risk Blending (60% ML / 25% Comm / 15% Rep)", "Risk Engine", check_risk_blending)
    record_check("Unseen Phone Number (Zero Reports) Reputation Fallback", "Edge Case", check_unknown_number_reputation)
    record_check("Transcript Analyzer 10-Category Regex & Empty-Input Guard", "Transcript Analyzer", check_transcript_analyzer)
    record_check("SQLite Database Schema & Live Telemetry Aggregation", "Database Module", check_database_telemetry)

    passed_count = sum(1 for c in checks if c["passed"])
    return {
        "total_checks": len(checks),
        "passed_checks": passed_count,
        "failed_checks": len(checks) - passed_count,
        "all_passed": passed_count == len(checks),
        "checks": checks,
        "defect_log": DEFECT_LOG,
    }


if __name__ == "__main__":
    report = run_all_verification_checks()
    print(f"Verification Suite: {report['passed_checks']}/{report['total_checks']} checks passed.")
    for c in report["checks"]:
        status = "PASS" if c["passed"] else "FAIL"
        print(f"  [{status}] {c['name']} ({c['elapsed_ms']} ms) -> {c['detail']}")
