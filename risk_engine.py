"""
Risk Engine Module (risk_engine.py)
===================================
Blends three independent threat intelligence signals into one final, transparent
0–100 risk score as specified in Section 8 of the project document:
  - ML Classifier Risk Score:        60% weight (0.60)
  - Community Report Risk Score:     25% weight (0.25)
  - Historical Reputation Score:     15% weight (0.15)

Also integrates optional Call Transcript Scam Analysis and logs every analyzed
call to the SQLite database (call_logs).

Authors: Silvia Noatia (2026279652), Fatima Iqbal (2026187337)
Mentor: Dharmendra Kumar | Sharda University (CSCR2600 PBL-1)
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from database import get_number_intelligence, log_analyzed_call
from prediction import predict_call_risk

WEIGHT_ML = 0.60
WEIGHT_COMMUNITY = 0.25
WEIGHT_REPUTATION = 0.15


def classify_risk_tier(final_score: float, predicted_label: str) -> Dict[str, str]:
    """
    Maps the 0–100 blended risk score and classifier prediction to a clear
    operational risk tier, badge color semantics, and recommended user action.
    """
    if final_score >= 78.0 or (predicted_label == "Scam" and final_score >= 65.0):
        return {
            "risk_level": "Critical Scam Alert",
            "verdict_class": "Scam",
            "severity_code": "CRITICAL",
            "headline": "High-Confidence Fraud / Scam Call Detected",
            "recommendation": (
                "Do NOT share OTPs, UPI PINs, Aadhaar/PAN numbers, or screen-sharing codes. "
                "Disconnect immediately and block this caller. No government agency or bank conducts 'Digital Arrests' or asks for verification transfers."
            ),
        }
    elif final_score >= 45.0 or predicted_label == "Spam":
        return {
            "risk_level": "Likely Telemarketing / Spam",
            "verdict_class": "Spam",
            "severity_code": "WARNING",
            "headline": "Unsolicited Commercial Spam or Robocall",
            "recommendation": (
                "Proceed with caution. This caller exhibits bulk-dialing or commercial telemarketing patterns. "
                "Avoid pressing IVR keys or confirming personal details; enable DND / spam filtering."
            ),
        }
    else:
        return {
            "risk_level": "Safe / Verified Caller",
            "verdict_class": "Safe",
            "severity_code": "SAFE",
            "headline": "Normal Subscriber Behavior — Likely Safe",
            "recommendation": (
                "Caller telemetry, carrier attestation, and community reputation show normal subscriber activity. "
                "Remain mindful of standard phone safety if unexpected financial requests arise."
            ),
        }


def evaluate_incoming_call(
    caller_input: Dict[str, Any],
    model_name: Optional[str] = None,
    transcript_score: Optional[float] = None,
    persist_log: bool = True,
) -> Dict[str, Any]:
    """
    Performs end-to-end multi-signal risk evaluation:
    1. Runs Prediction Engine (ML model + preprocessing pipeline) -> ML Score (60%)
    2. Queries SQLite Database for Community Reports -> Community Score (25%)
    3. Queries SQLite Database for Number Reputation -> Reputation Score (15%)
    4. Computes blended 0–100 risk score and transparent signal breakdown
    5. Logs the analysis into SQLite call_logs
    """
    ml_result = predict_call_risk(caller_input, model_name=model_name)
    phone_number = ml_result["phone_number"]

    db_intel = get_number_intelligence(phone_number)

    ml_score = float(ml_result["ml_risk_score"])
    comm_score = float(db_intel["community_risk_score"])
    rep_score = float(db_intel["reputation_risk_score"])

    # If the phone number is not yet known in the community DB, rely more heavily on
    # the ML behavioral classifier while keeping the 60/25/15 transparency formula.
    # For known numbers, use the exact 60% ML + 25% Community + 15% Reputation blend.
    ml_weighted = round(ml_score * WEIGHT_ML, 2)
    comm_weighted = round(comm_score * WEIGHT_COMMUNITY, 2)
    rep_weighted = round(rep_score * WEIGHT_REPUTATION, 2)

    blended_score = round(ml_weighted + comm_weighted + rep_weighted, 1)

    # If optional transcript analysis was also performed and flagged high risk,
    # surface both the standard 3-signal score and transcript-augmented score
    if transcript_score is not None and transcript_score > 0:
        effective_score = round(max(blended_score, 0.65 * blended_score + 0.35 * float(transcript_score)), 1)
    else:
        effective_score = blended_score

    effective_score = float(min(100.0, max(0.0, effective_score)))

    # Determine final predicted class considering overwhelming community evidence
    predicted_label = ml_result["predicted_label"]
    if db_intel["known_in_db"] and db_intel["scam_reports"] >= 10 and effective_score >= 72.0:
        predicted_label = "Scam"
    elif db_intel["known_in_db"] and db_intel["spam_reports"] >= 10 and predicted_label == "Safe" and effective_score >= 48.0:
        predicted_label = "Spam"

    tier_info = classify_risk_tier(effective_score, predicted_label)

    # Combine ML plain-language reasons with database intelligence reasons
    combined_reasons: List[str] = list(ml_result["reasons"])
    if db_intel["known_in_db"]:
        if db_intel["scam_reports"] > 0 or db_intel["spam_reports"] > 0:
            combined_reasons.insert(
                0,
                f"Community Intelligence: {db_intel['total_reports']} community reports on file "
                f"({db_intel['scam_reports']} Scam, {db_intel['spam_reports']} Spam) — Status: {db_intel['status_tag']}.",
            )
        elif db_intel["safe_votes"] > 0:
            combined_reasons.append(
                f"Community Intelligence: {db_intel['safe_votes']} community safe verifications on record ({db_intel['status_tag']})."
            )
    else:
        combined_reasons.append(
            f"Number Reputation: First-seen / unreported number; baseline prefix assessment applied ({db_intel['status_tag']})."
        )

    log_id = None
    if persist_log:
        log_id = log_analyzed_call(
            phone_number=phone_number,
            predicted_label=predicted_label,
            ml_risk_score=ml_score,
            community_risk_score=comm_score,
            reputation_risk_score=rep_score,
            final_risk_score=effective_score,
            risk_level=tier_info["risk_level"],
            probabilities=ml_result["probabilities"],
            reasons=combined_reasons,
            features=ml_result["normalized_features"],
            transcript_score=transcript_score,
        )

    return {
        "log_id": log_id,
        "phone_number": phone_number,
        "predicted_label": predicted_label,
        "verdict_class": tier_info["verdict_class"],
        "risk_level": tier_info["risk_level"],
        "severity_code": tier_info["severity_code"],
        "headline": tier_info["headline"],
        "recommendation": tier_info["recommendation"],
        "final_risk_score": effective_score,
        "blended_3signal_score": blended_score,
        "signals": {
            "ml_model": {
                "raw_score": ml_score,
                "weight": WEIGHT_ML,
                "weighted_contribution": ml_weighted,
                "label": "ML Classifier (60%)",
            },
            "community_reports": {
                "raw_score": comm_score,
                "weight": WEIGHT_COMMUNITY,
                "weighted_contribution": comm_weighted,
                "label": "Community Reports (25%)",
            },
            "historical_reputation": {
                "raw_score": rep_score,
                "weight": WEIGHT_REPUTATION,
                "weighted_contribution": rep_weighted,
                "label": "Historical Reputation (15%)",
            },
        },
        "probabilities": ml_result["probabilities"],
        "model_used": ml_result["model_used"],
        "reasons": combined_reasons,
        "signal_drivers": ml_result["signal_drivers"],
        "all_models_comparison": ml_result.get("all_models_comparison", []),
        "transcript_score": transcript_score,
        "number_intelligence": db_intel,
        "normalized_features": ml_result["normalized_features"],
    }
