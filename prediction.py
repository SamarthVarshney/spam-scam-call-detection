"""
Prediction Engine Module (prediction.py)
========================================
Loads the persisted best ML model and fitted ColumnTransformer pipeline (.pkl),
transforms incoming caller behavioral features using the identical preprocessing
pipeline, and returns:
- Predicted class (Safe, Spam, Scam)
- Class probabilities (Safe, Spam, Scam)
- 0–100 ML risk score
- Feature-level risk contributions
- Plain-language, human-readable explanations (rule + probability grounded)

Authors: Silvia Noatia (2026279652), Fatima Iqbal (2026187337)
Mentor: Dharmendra Kumar | Sharda University (CSCR2600 PBL-1)
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

import joblib
import numpy as np
import pandas as pd

from data_preprocessing import (
    ALL_FEATURES,
    CATEGORICAL_FEATURES,
    CLASSES,
    NUMERIC_FEATURES,
     _hour_to_bucket,
    sanitize_phone_number,
)
from model_training import (
    ALL_MODELS_PATH,
    BEST_MODEL_PATH,
    PREPROCESSOR_PATH,
    train_and_evaluate_all,
)

_CACHED_MODEL = None
_CACHED_PREPROCESSOR = None
_CACHED_ALL_MODELS = None


def load_artifacts(force_reload: bool = False) -> Tuple[Any, Any, Dict[str, Any]]:
    """
    Loads the saved best model, preprocessing pipeline, and model dictionary.
    Automatically triggers training if the .pkl files are missing.
    """
    global _CACHED_MODEL, _CACHED_PREPROCESSOR, _CACHED_ALL_MODELS

    if (
        force_reload
        or _CACHED_MODEL is None
        or _CACHED_PREPROCESSOR is None
        or not BEST_MODEL_PATH.exists()
        or not PREPROCESSOR_PATH.exists()
    ):
        if not BEST_MODEL_PATH.exists() or not PREPROCESSOR_PATH.exists():
            train_and_evaluate_all(force_regenerate_data=False)

        _CACHED_MODEL = joblib.load(BEST_MODEL_PATH)
        _CACHED_PREPROCESSOR = joblib.load(PREPROCESSOR_PATH)
        if ALL_MODELS_PATH.exists():
            _CACHED_ALL_MODELS = joblib.load(ALL_MODELS_PATH)
        else:
            _CACHED_ALL_MODELS = {"Random Forest": _CACHED_MODEL}

    return _CACHED_MODEL, _CACHED_PREPROCESSOR, _CACHED_ALL_MODELS


DEFAULT_CALL_FEATURES: Dict[str, Any] = {
    "phone_number": "+91-98104-52391",
    "calls_last_24h": 3,
    "calls_last_7d": 14,
    "avg_call_duration_sec": 165.0,
    "answer_rate": 0.86,
    "short_call_ratio": 0.08,
    "silence_initial_sec": 0.25,
    "unique_recipients_ratio": 0.24,
    "hour_of_day": 14,
    "number_age_days": 1120,
    "prior_complaint_rate": 0.01,
    "prefix_type": "Domestic_Mobile",
    "caller_line_type": "Mobile_SIM",
    "time_bucket": "Afternoon",
    "in_contact_network": "Yes",
    "cli_verification_status": "STIR_SHAKEN_A",
}


PRESET_CALL_SCENARIOS: Dict[str, Dict[str, Any]] = {
    "Verified Safe Contact": {
        "title": "Verified Domestic Contact (+91-98104-52391)",
        "subtitle": "Known subscriber in contact graph with STIR/SHAKEN Level-A attestation",
        "features": {
            "phone_number": "+91-98104-52391",
            "calls_last_24h": 3,
            "calls_last_7d": 14,
            "avg_call_duration_sec": 185.0,
            "answer_rate": 0.89,
            "short_call_ratio": 0.06,
            "silence_initial_sec": 0.20,
            "unique_recipients_ratio": 0.22,
            "hour_of_day": 14,
            "number_age_days": 1280,
            "prior_complaint_rate": 0.005,
            "prefix_type": "Domestic_Mobile",
            "caller_line_type": "Mobile_SIM",
            "time_bucket": "Afternoon",
            "in_contact_network": "Yes",
            "cli_verification_status": "STIR_SHAKEN_A",
        },
    },
    "Telemarketing Robocall (Spam)": {
        "title": "140-Series Loan Telemarketer (+91-140-8834210)",
        "subtitle": "High-frequency commercial PRI trunk with predictive-dialer delay & short hang-ups",
        "features": {
            "phone_number": "+91-140-8834210",
            "calls_last_24h": 58,
            "calls_last_7d": 340,
            "avg_call_duration_sec": 22.0,
            "answer_rate": 0.19,
            "short_call_ratio": 0.78,
            "silence_initial_sec": 2.65,
            "unique_recipients_ratio": 0.94,
            "hour_of_day": 11,
            "number_age_days": 210,
            "prior_complaint_rate": 0.44,
            "prefix_type": "Telemarketing_140",
            "caller_line_type": "PRI_Trunk",
            "time_bucket": "Morning",
            "in_contact_network": "No",
            "cli_verification_status": "STIR_SHAKEN_B",
        },
    },
    "Digital Arrest / Customs Fraud (Scam)": {
        "title": "Spoofed VoIP 'Digital Arrest' Scam (+91-92104-88319)",
        "subtitle": "Unverified CLI, 3.4s VoIP gateway handoff delay, high complaint density",
        "features": {
            "phone_number": "+91-92104-88319",
            "calls_last_24h": 38,
            "calls_last_7d": 175,
            "avg_call_duration_sec": 290.0,
            "answer_rate": 0.31,
            "short_call_ratio": 0.46,
            "silence_initial_sec": 3.40,
            "unique_recipients_ratio": 0.96,
            "hour_of_day": 10,
            "number_age_days": 14,
            "prior_complaint_rate": 0.86,
            "prefix_type": "International_VoIP",
            "caller_line_type": "Spoofed_CLI",
            "time_bucket": "Morning",
            "in_contact_network": "No",
            "cli_verification_status": "Unverified",
        },
    },
    "Burner SIM Bank KYC Phishing (Scam)": {
        "title": "Burner SIM Bank KYC / OTP Theft (+91-81309-44102)",
        "subtitle": "9-day-old domestic SIM dialing 94% unique targets with long social-engineering calls",
        "features": {
            "phone_number": "+91-81309-44102",
            "calls_last_24h": 34,
            "calls_last_7d": 142,
            "avg_call_duration_sec": 245.0,
            "answer_rate": 0.34,
            "short_call_ratio": 0.42,
            "silence_initial_sec": 2.95,
            "unique_recipients_ratio": 0.94,
            "hour_of_day": 16,
            "number_age_days": 9,
            "prior_complaint_rate": 0.78,
            "prefix_type": "Domestic_Mobile",
            "caller_line_type": "VoIP_SIP",
            "time_bucket": "Afternoon",
            "in_contact_network": "No",
            "cli_verification_status": "Unverified",
        },
    },
    "Cross-Border Lottery Extortion (Scam)": {
        "title": "Cross-Border +92 VoIP Scam (+92-300-4918204)",
        "subtitle": "Foreign gateway origin during odd hours with spoofed caller ID",
        "features": {
            "phone_number": "+92-300-4918204",
            "calls_last_24h": 42,
            "calls_last_7d": 210,
            "avg_call_duration_sec": 195.0,
            "answer_rate": 0.24,
            "short_call_ratio": 0.58,
            "silence_initial_sec": 3.80,
            "unique_recipients_ratio": 0.98,
            "hour_of_day": 23,
            "number_age_days": 6,
            "prior_complaint_rate": 0.92,
            "prefix_type": "International_VoIP",
            "caller_line_type": "Spoofed_CLI",
            "time_bucket": "Late_Night",
            "in_contact_network": "No",
            "cli_verification_status": "Unverified",
        },
    },
}


def generate_plain_language_reasons(
    features: Dict[str, Any],
    predicted_label: str,
    probabilities: Dict[str, float],
) -> Tuple[List[str], List[Dict[str, Any]]]:
    """
    Produces human-readable, plain-language explanations and structured signal drivers
    explaining why the call was classified as Safe, Spam, or Scam.
    """
    reasons: List[str] = []
    drivers: List[Dict[str, Any]] = []

    calls_24h = float(features.get("calls_last_24h", 3))
    avg_dur = float(features.get("avg_call_duration_sec", 120))
    ans_rate = float(features.get("answer_rate", 0.75))
    short_ratio = float(features.get("short_call_ratio", 0.10))
    silence = float(features.get("silence_initial_sec", 0.3))
    uniq_ratio = float(features.get("unique_recipients_ratio", 0.25))
    hour = int(features.get("hour_of_day", 14))
    age_days = int(features.get("number_age_days", 365))
    complaint = float(features.get("prior_complaint_rate", 0.02))
    prefix_type = str(features.get("prefix_type", "Domestic_Mobile"))
    line_type = str(features.get("caller_line_type", "Mobile_SIM"))
    contact_net = str(features.get("in_contact_network", "No"))
    cli_status = str(features.get("cli_verification_status", "STIR_SHAKEN_A"))

    # 1. Caller ID Attestation & Line Type
    if cli_status == "Unverified" or line_type == "Spoofed_CLI":
        reasons.append(
            f"Caller ID lacks carrier cryptographic attestation ({cli_status}, line: {line_type.replace('_', ' ')}), a primary signature of CLI spoofing and VoIP scam gateways."
        )
        drivers.append({"factor": "CLI Attestation & Line Security", "impact": +26, "direction": "risk", "detail": f"{cli_status} / {line_type}"})
    elif cli_status == "STIR_SHAKEN_A" and line_type in ("Mobile_SIM", "Landline"):
        reasons.append(
            "Carrier STIR/SHAKEN Level-A cryptographic attestation confirms the caller owns this domestic subscriber line."
        )
        drivers.append({"factor": "CLI Attestation & Line Security", "impact": -22, "direction": "safe", "detail": "STIR/SHAKEN Class A Verified"})

    # 2. Initial Auto-Dialer / VoIP Bridge Silence
    if silence >= 2.2:
        reasons.append(
            f"Detected {silence:.2f}s of dead-air silence after pickup — typical of predictive auto-dialers or cross-border VoIP call-center bridges."
        )
        drivers.append({"factor": "Pickup Handshake Delay", "impact": +20, "direction": "risk", "detail": f"{silence:.2f}s dead-air delay"})
    elif silence <= 0.7:
        reasons.append(
            f"Immediate voice handshake ({silence:.2f}s delay) indicates direct human dialing rather than an automated dialer queue."
        )
        drivers.append({"factor": "Pickup Handshake Delay", "impact": -12, "direction": "safe", "detail": f"{silence:.2f}s direct pickup"})

    # 3. Call Velocity & Short Hang-up Ratio
    if calls_24h >= 35 and short_ratio >= 0.55:
        reasons.append(
            f"High outbound call burst ({int(calls_24h)} calls/24h) combined with {short_ratio*100:.0f}% short hang-ups (<10s) strongly matches commercial robocalling or mass telemarketing."
        )
        drivers.append({"factor": "Call Velocity & Hang-up Pattern", "impact": +22, "direction": "risk", "detail": f"{int(calls_24h)} calls/day, {short_ratio*100:.0f}% <10s"})
    elif calls_24h >= 20:
        reasons.append(
            f"Elevated outbound dialing rate ({int(calls_24h)} calls in the last 24 hours) exceeds normal personal subscriber behavior."
        )
        drivers.append({"factor": "Outbound Call Velocity", "impact": +15, "direction": "risk", "detail": f"{int(calls_24h)} calls in 24h"})
    elif calls_24h <= 8 and short_ratio <= 0.20:
        reasons.append(
            f"Low daily call volume ({int(calls_24h)} calls/24h) and low short-call ratio ({short_ratio*100:.0f}%) align with organic human conversation."
        )
        drivers.append({"factor": "Outbound Call Velocity", "impact": -15, "direction": "safe", "detail": f"{int(calls_24h)} calls/day"})

    # 4. Number Age (Burner SIM detection)
    if age_days <= 30:
        reasons.append(
            f"Number was activated only {age_days} days ago — newly provisioned 'burner' SIMs/DIDs are disproportionately used in short-lived fraud campaigns."
        )
        drivers.append({"factor": "SIM / Number Tenure", "impact": +24, "direction": "risk", "detail": f"Activated {age_days} days ago"})
    elif age_days >= 365:
        reasons.append(
            f"Established subscriber tenure ({age_days} days / {age_days/365:.1f} years active on network) lowers burner-fraud likelihood."
        )
        drivers.append({"factor": "SIM / Number Tenure", "impact": -14, "direction": "safe", "detail": f"{age_days} days active"})

    # 5. Historical Complaint Density & Recipient Dispersion
    if complaint >= 0.45:
        reasons.append(
            f"High carrier complaint density ({complaint*100:.1f}% of recipients flagged or blocked this caller) signals active abuse."
        )
        drivers.append({"factor": "Carrier Complaint Density", "impact": +28, "direction": "risk", "detail": f"{complaint*100:.1f}% block/flag rate"})
    elif complaint >= 0.18:
        reasons.append(
            f"Moderate carrier complaint rate ({complaint*100:.1f}%) typical of unsolicited promotional campaigns."
        )
        drivers.append({"factor": "Carrier Complaint Density", "impact": +14, "direction": "risk", "detail": f"{complaint*100:.1f}% complaint rate"})

    if uniq_ratio >= 0.80:
        reasons.append(
            f"Caller dials {uniq_ratio*100:.0f}% distinct one-time recipients (sequential/random number sweeping rather than repeat contacts)."
        )
        drivers.append({"factor": "Recipient Dispersion", "impact": +16, "direction": "risk", "detail": f"{uniq_ratio*100:.0f}% unique targets"})

    # 6. Prefix & Contact Network
    if prefix_type == "Telemarketing_140":
        reasons.append(
            "Originates from a registered 140/160 commercial telemarketing prefix designated for promotional bulk calling."
        )
        drivers.append({"factor": "Numbering Plan Prefix", "impact": +15, "direction": "risk", "detail": "140/160 Telemarketing Series"})
    elif prefix_type == "International_VoIP":
        reasons.append(
            "Originates from an international VoIP gateway prefix frequently abused for cross-border impersonation scams."
        )
        drivers.append({"factor": "Numbering Plan Prefix", "impact": +22, "direction": "risk", "detail": "International VoIP Gateway"})

    if contact_net == "Yes":
        reasons.append(
            "Caller is verified inside the recipient's 1st-degree contact graph with a strong historical answer rate."
        )
        drivers.append({"factor": "Contact Graph Proximity", "impact": -25, "direction": "safe", "detail": "In Address Book"})
    elif contact_net == "No" and ans_rate < 0.35:
        reasons.append(
            f"Unknown caller outside contact network with low recipient engagement ({ans_rate*100:.0f}% answer rate)."
        )
        drivers.append({"factor": "Contact Graph Proximity", "impact": +12, "direction": "risk", "detail": f"Unknown caller ({ans_rate*100:.0f}% answered)"})

    if hour <= 5 or hour >= 22:
        reasons.append(
            f"Call initiated during off-peak late-night hours ({hour:02d}:00), a common tactic for urgent emergency/extortion scams."
        )
        drivers.append({"factor": "Call Timing Window", "impact": +10, "direction": "risk", "detail": f"Off-hours ({hour:02d}:00)"})

    if not reasons:
        reasons.append(
            f"ML classifier evaluated 15 behavioral and carrier telemetry features with {max(probabilities.values())*100:.1f}% confidence for class '{predicted_label}'."
        )

    return reasons, drivers


def predict_call_risk(
    caller_input: Dict[str, Any],
    model_name: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Runs the fitted preprocessing pipeline and trained ML classifier on a single
    caller input dictionary. Returns class probabilities, 0-100 ML risk score,
    predicted label, and plain-language reasons.
    """
    best_model, preprocessor, all_models = load_artifacts()

    if model_name and model_name in all_models:
        active_model = all_models[model_name]
        used_model_name = model_name
    else:
        active_model = best_model
        used_model_name = "Random Forest (Best)"

    # Merge with defaults so missing keys never crash inference
    merged: Dict[str, Any] = dict(DEFAULT_CALL_FEATURES)
    for k, v in caller_input.items():
        if v is not None and v != "":
            merged[k] = v

    merged["phone_number"] = sanitize_phone_number(merged.get("phone_number", "+91-98000-00000"))
    merged["time_bucket"] = _hour_to_bucket(int(merged.get("hour_of_day", 14)))

    # Build 1-row DataFrame with exact training column order
    row_df = pd.DataFrame([{col: merged[col] for col in ALL_FEATURES}])

    X_trans = preprocessor.transform(row_df)
    proba_raw = active_model.predict_proba(X_trans)[0]
    model_classes = list(active_model.classes_)

    probabilities: Dict[str, float] = {}
    for cls_name in CLASSES:
        idx = model_classes.index(cls_name)
        probabilities[cls_name] = round(float(proba_raw[idx]), 4)

    # Predicted label is the highest-probability class
    predicted_label = max(probabilities.items(), key=lambda x: x[1])[0]

    # Compute continuous 0-100 ML Risk Score:
    # Scam probability carries full weight (100), Spam carries moderate-high weight (65),
    # Safe carries minimal baseline weight (3).
    ml_risk_score = (
        probabilities["Scam"] * 100.0
        + probabilities["Spam"] * 65.0
        + probabilities["Safe"] * 3.0
    )
    ml_risk_score = float(np.clip(round(ml_risk_score, 1), 0.0, 100.0))

    reasons, drivers = generate_plain_language_reasons(merged, predicted_label, probabilities)

    # Evaluate across all 5 trained classifiers for multi-model consensus view
    all_models_comparison: List[Dict[str, Any]] = []
    for m_name, m_clf in all_models.items():
        m_proba_raw = m_clf.predict_proba(X_trans)[0]
        m_classes = list(m_clf.classes_)
        m_probs = {c: round(float(m_proba_raw[m_classes.index(c)]), 4) for c in CLASSES}
        m_pred = max(m_probs.items(), key=lambda x: x[1])[0]
        m_score = float(
            np.clip(
                round(m_probs["Scam"] * 100.0 + m_probs["Spam"] * 65.0 + m_probs["Safe"] * 3.0, 1),
                0.0,
                100.0,
            )
        )
        all_models_comparison.append(
            {
                "model_name": m_name,
                "predicted_label": m_pred,
                "ml_risk_score": m_score,
                "prob_safe": m_probs["Safe"],
                "prob_spam": m_probs["Spam"],
                "prob_scam": m_probs["Scam"],
            }
        )

    return {
        "phone_number": merged["phone_number"],
        "model_used": used_model_name,
        "predicted_label": predicted_label,
        "probabilities": probabilities,
        "ml_risk_score": ml_risk_score,
        "reasons": reasons,
        "signal_drivers": drivers,
        "all_models_comparison": all_models_comparison,
        "normalized_features": merged,
    }


if __name__ == "__main__":
    for name, preset in PRESET_CALL_SCENARIOS.items():
        res = predict_call_risk(preset["features"])
        print(
            f"[{name}] -> Predicted: {res['predicted_label']} | "
            f"ML Risk: {res['ml_risk_score']}/100 | Probs: {res['probabilities']}"
        )
