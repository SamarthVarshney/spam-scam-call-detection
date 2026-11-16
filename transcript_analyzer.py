"""
Call Transcript Scam Analyzer Module (transcript_analyzer.py)
=============================================================
Scans a pasted or uploaded call transcript against 10 regex-based scam-indicator
categories and returns a weighted 0–100 risk score, matched categories, exact
character spans for inline UI highlighting, and plain-language forensic analysis.

Authors: Silvia Noatia (2026279652), Fatima Iqbal (2026187337)
Mentor: Dharmendra Kumar | Sharda University (CSCR2600 PBL-1)
"""

from __future__ import annotations

import re
from typing import Any, Dict, List

SCAM_CATEGORIES: List[Dict[str, Any]] = [
    {
        "id": "otp_credential_harvesting",
        "name": "OTP / PIN / Credential Request",
        "weight": 28,
        "severity": "Critical",
        "color": "#EF4444",
        "description": "Direct solicitation of One-Time Passwords (OTP), UPI PINs, CVV codes, or net-banking passwords.",
        "patterns": [
            r"\b(?:otp|one[\s\-]?time[\s\-]?password|verification[\s\-]?code|security[\s\-]?code)\b",
            r"\b(?:4|6)[\s\-]?digit\s+(?:code|number|pin|otp)\b",
            r"\b(?:upi\s*pin|atm\s*pin|cvv|mpin|net\s*banking\s*password|card\s*pin)\b",
            r"\b(?:read\s+out|share|tell\s+me|confirm)\s+(?:the|your)\s+(?:code|otp|pin|password)\b",
        ],
    },
    {
        "id": "legal_digital_arrest_threats",
        "name": "Legal / Police / 'Digital Arrest' Threats",
        "weight": 26,
        "severity": "Critical",
        "color": "#EF4444",
        "description": "Coercive threats of arrest warrants, FIR registration, CBI/Narcotics investigation, or 'Digital Arrest'.",
        "patterns": [
            r"\b(?:digital\s+arrest|arrest\s+warrant|non[\s\-]?bailable\s+warrant|fir\s+registered)\b",
            r"\b(?:cyber\s+crime\s+cell|cbi\s+officer|narcotics\s+bureau|enforcement\s+directorate|supreme\s+court\s+order)\b",
            r"\b(?:money\s+laundering|illegal\s+parcel|drugs\s+seized|contraband|terror\s+funding)\b",
            r"\b(?:police\s+custody|prison|jail|criminal\s+prosecution|freeze\s+all\s+assets)\b",
        ],
    },
    {
        "id": "payment_transfer_demands",
        "name": "Direct Payment / UPI / Wire Demand",
        "weight": 24,
        "severity": "Critical",
        "color": "#F97316",
        "description": "Demands to transfer money to a 'safe/supervision account', pay clearance fees, or send gift cards/crypto.",
        "patterns": [
            r"\b(?:transfer|deposit|send|pay)\s+(?:rs\.?|inr|\$|₹)?\s*\d*",
            r"\b(?:rbi\s+supervision\s+account|escrow\s+account|verification\s+deposit|refundable\s+security\s+deposit)\b",
            r"\b(?:gift\s+card|google\s+play\s+card|apple\s+card|bitcoin|crypto\s+wallet|wire\s+transfer)\b",
            r"\b(?:processing\s+fee|customs\s+duty|clearance\s+charge|tax\s+penalty\s+payment)\b",
            r"\b(?:scan\s+this\s+qr|approve\s+collect\s+request|upi\s+transfer)\b",
        ],
    },
    {
        "id": "remote_access_coercion",
        "name": "Remote Access / Screen-Share Coercion",
        "weight": 24,
        "severity": "Critical",
        "color": "#EF4444",
        "description": "Instructions to install or open remote desktop tools (AnyDesk, TeamViewer, QuickSupport, APK files).",
        "patterns": [
            r"\b(?:anydesk|teamviewer|quicksupport|rustdesk|ultraviewer|screen\s*share)\b",
            r"\b(?:download|install)\s+(?:our|the|this)\s+(?:support\s+app|apk|verification\s+app|remote\s+tool)\b",
            r"\b(?:9[\s\-]?digit\s+address|remote\s+access\s+code|share\s+your\s+screen)\b",
        ],
    },
    {
        "id": "bank_kyc_account_freeze",
        "name": "Bank / KYC / Account Suspension Threat",
        "weight": 20,
        "severity": "High",
        "color": "#F59E0B",
        "description": "Claims that a bank account, SIM card, credit card, or electricity connection will be blocked immediately.",
        "patterns": [
            r"\b(?:kyc\s+(?:expired|update|pending|suspended|verification))\b",
            r"\b(?:account|debit\s+card|credit\s+card|sim\s+card)\s+will\s+be\s+(?:blocked|frozen|suspended|deactivated)\b",
            r"\b(?:electricity|power)\s+(?:supply|connection)\s+will\s+be\s+(?:disconnected|cut\s+tonight)\b",
            r"\b(?:unauthorized\s+transaction|suspicious\s+withdrawal)\s+of\s+(?:rs\.?|inr|\$|₹)\b",
        ],
    },
    {
        "id": "urgency_time_pressure",
        "name": "Extreme Urgency & Countdown Pressure",
        "weight": 16,
        "severity": "High",
        "color": "#F59E0B",
        "description": "Artificial time deadlines designed to prevent the victim from verifying with family or official channels.",
        "patterns": [
            r"\b(?:within\s+(?:\d+|ten|fifteen|thirty|two)\s+(?:minutes|hours|seconds))\b",
            r"\b(?:immediately|right\s+now|last\s+warning|final\s+notice|urgent\s+action\s+required)\b",
            r"\b(?:before\s+tonight|cannot\s+wait|time\s+is\s+running\s+out|instant\s+suspension)\b",
        ],
    },
    {
        "id": "authority_government_spoofing",
        "name": "Government / Regulator / Telecom Impersonation",
        "weight": 16,
        "severity": "High",
        "color": "#F59E0B",
        "description": "Impersonating TRAI, Reserve Bank of India (RBI), Customs, Income Tax Department, or FedEx/DHL.",
        "patterns": [
            r"\b(?:telecom\s+regulatory\s+authority|trai\s+headquarters|department\s+of\s+telecommunications)\b",
            r"\b(?:reserve\s+bank\s+of\s+india|rbi\s+governor|income\s+tax\s+department|customs\s+department)\b",
            r"\b(?:fedex\s+international|dhl\s+express\s+customs|mumbai\s+crime\s+branch)\b",
        ],
    },
    {
        "id": "identity_document_phishing",
        "name": "Aadhaar / PAN / Identity Phishing",
        "weight": 15,
        "severity": "Moderate-High",
        "color": "#EAB308",
        "description": "Soliciting sensitive national identity numbers, full card numbers, or mother's maiden name/DOB.",
        "patterns": [
            r"\b(?:aadhaar\s+number|12[\s\-]?digit\s+aadhaar|pan\s+card\s+number|social\s+security\s+number)\b",
            r"\b(?:16[\s\-]?digit\s+card\s+number|expiry\s+date\s+and\s+cvv|date\s+of\s+birth\s+and\s+pan)\b",
        ],
    },
    {
        "id": "secrecy_isolation_coercion",
        "name": "Secrecy & Isolation Coercion",
        "weight": 18,
        "severity": "High",
        "color": "#EF4444",
        "description": "Instructing the victim not to hang up, stay on video/Skype call, or tell nobody about the investigation.",
        "patterns": [
            r"\b(?:do\s+not\s+(?:disconnect|hang\s+up|cut\s+the\s+call|inform\s+anyone|tell\s+your\s+family))\b",
            r"\b(?:stay\s+on\s+(?:the\s+line|video\s+call|skype|whatsapp\s+video)|national\s+security\s+confidentiality)\b",
            r"\b(?:under\s+camera\s+surveillance|lock\s+your\s+room)\b",
        ],
    },
    {
        "id": "lottery_prize_promotional_lure",
        "name": "Lottery / Unclaimed Prize / Loan Lure",
        "weight": 14,
        "severity": "Moderate",
        "color": "#F59E0B",
        "description": "Promises of lottery winnings, KBC lucky draws, zero-interest instant loans, or guaranteed returns.",
        "patterns": [
            r"\b(?:won\s+a\s+(?:lottery|prize|lucky\s+draw)|kbc\s+lucky\s+winner|bumper\s+prize)\b",
            r"\b(?:25\s*lakh|50\s*lakh|jackpot\s+reward|unclaimed\s+bonus|guaranteed\s+double\s+return)\b",
            r"\b(?:pre[\s\-]?approved\s+personal\s+loan|zero\s+cibil\s+check|instant\s+credit\s+limit\s+increase)\b",
        ],
    },
]


SAMPLE_TRANSCRIPTS: Dict[str, Dict[str, str]] = {
    "Digital Arrest / FedEx Customs Scam (Critical Scam)": {
        "caller_type": "Scam",
        "phone": "+91-92104-88319",
        "transcript": (
            "Hello, this is Inspector Vikram Rathore speaking from Mumbai Cyber Crime Cell and Customs Department. "
            "A FedEx international parcel booked using your Aadhaar number has been seized with illegal passports and MDMA contraband. "
            "An arrest warrant and FIR registered under Money Laundering Act is active against you. "
            "You are now placed under Digital Arrest. Do not disconnect the call or inform anyone in your family due to national security confidentiality. "
            "Stay on Skype video call and immediately transfer Rs 85,000 to the RBI supervision account within 15 minutes for asset verification."
        ),
    },
    "Bank KYC & OTP Phishing + AnyDesk (Critical Scam)": {
        "caller_type": "Scam",
        "phone": "+91-81309-44102",
        "transcript": (
            "Good afternoon sir, I am calling from the HDFC & SBI Central KYC Verification Desk. "
            "Your bank account and debit card will be blocked tonight because your PAN card number and KYC expired today. "
            "To stop instant suspension, please download our support app AnyDesk from Play Store and share the 9-digit address. "
            "Also read out the 6-digit OTP verification code just sent to your mobile number and confirm your UPI PIN immediately."
        ),
    },
    "Electricity Disconnection Tonight Scam (High Risk Scam)": {
        "caller_type": "Scam",
        "phone": "+91-79012-33910",
        "transcript": (
            "Urgent action required from State Electricity Billing Office. Your electricity supply connection will be disconnected tonight at 9:30 PM "
            "because your previous month bill update failed. Immediately call our officer and pay the ₹10 verification deposit via UPI transfer "
            "or scan this QR code within 30 minutes to avoid power cut."
        ),
    },
    "KBC Lottery & Processing Fee Fraud (High Risk Scam)": {
        "caller_type": "Scam",
        "phone": "+92-300-4918204",
        "transcript": (
            "Congratulations! Your mobile number has won a lottery bumper prize of 25 Lakh rupees in the KBC Lucky Winner draw! "
            "To claim your prize money right now, you must pay a refundable processing fee and tax penalty payment of Rs 12,500 "
            "via UPI transfer within two hours. Do not tell anyone before claiming."
        ),
    },
    "Pre-Approved Loan Telemarketing Call (Commercial Spam)": {
        "caller_type": "Spam",
        "phone": "+91-140-8834210",
        "transcript": (
            "Hello sir! Good morning, calling from Prime Finance Advisory Desk. You have a pre-approved personal loan offer up to Rs 5 Lakhs "
            "with zero CIBIL check and an instant credit limit increase on your existing card. Press 1 or let me know if we can process your "
            "application today before our festive promotional campaign closes."
        ),
    },
    "Legitimate Delivery & University Coordinator Call (Safe)": {
        "caller_type": "Safe",
        "phone": "+91-98104-52391",
        "transcript": (
            "Hi Silvia, this is Rohan from the Sharda University CSE project lab. Just calling to confirm that our PBL-1 presentation "
            "with Prof. Dharmendra Kumar is scheduled for 2:30 PM in Block 3 Room 204. Please bring your laptop with the Streamlit demo ready. "
            "See you in class!"
        ),
    },
}


def analyze_transcript(transcript_text: str) -> Dict[str, Any]:
    """
    Scans a transcript string against all 10 regex-based scam-indicator categories.
    Returns:
      - transcript_risk_score (0–100)
      - verdict_label ('Safe', 'Spam', 'Scam')
      - risk_tier ('Low Risk / Benign', 'Moderate Risk / Promotional Spam', 'High Risk / Scam Script', 'Critical Fraud Script')
      - matched_categories (list of category dicts with matched phrases & weights)
      - all_categories_status (all 10 categories with hit status for full transparency)
      - highlighted_spans (sorted character spans for UI highlighting)
      - summary_explanation (plain-language forensic synthesis)
    """
    if not transcript_text or not transcript_text.strip():
        return {
            "transcript_risk_score": 0.0,
            "verdict_label": "Safe",
            "risk_tier": "No Transcript Provided",
            "matched_count": 0,
            "total_categories_checked": len(SCAM_CATEGORIES),
            "matched_categories": [],
            "all_categories_status": [
                {
                    "id": c["id"],
                    "name": c["name"],
                    "weight": c["weight"],
                    "severity": c["severity"],
                    "matched": False,
                    "match_count": 0,
                    "matches": [],
                }
                for c in SCAM_CATEGORIES
            ],
            "highlighted_spans": [],
            "word_count": 0,
            "summary_explanation": "Enter or paste a call transcript to scan against the 10 scam-indicator regex categories.",
        }

    text = transcript_text.strip()
    words = text.split()
    word_count = len(words)

    matched_categories: List[Dict[str, Any]] = []
    all_categories_status: List[Dict[str, Any]] = []
    raw_spans: List[Dict[str, Any]] = []

    accumulated_points = 0.0

    for cat in SCAM_CATEGORIES:
        cat_matches: List[str] = []
        for pat in cat["patterns"]:
            for m in re.finditer(pat, text, flags=re.IGNORECASE):
                matched_str = m.group(0)
                if matched_str.lower() not in [x.lower() for x in cat_matches]:
                    cat_matches.append(matched_str)
                raw_spans.append(
                    {
                        "start": m.start(),
                        "end": m.end(),
                        "text": matched_str,
                        "category_id": cat["id"],
                        "category_name": cat["name"],
                        "severity": cat["severity"],
                        "color": cat["color"],
                    }
                )

        is_hit = len(cat_matches) > 0
        if is_hit:
            # Base category weight + bonus for multiple distinct pattern hits in the same category
            cat_score = cat["weight"] + min(8.0, (len(cat_matches) - 1) * 3.5)
            accumulated_points += cat_score
            matched_categories.append(
                {
                    "id": cat["id"],
                    "name": cat["name"],
                    "weight": cat["weight"],
                    "effective_points": round(cat_score, 1),
                    "severity": cat["severity"],
                    "color": cat["color"],
                    "description": cat["description"],
                    "match_count": len(cat_matches),
                    "matches": cat_matches,
                }
            )

        all_categories_status.append(
            {
                "id": cat["id"],
                "name": cat["name"],
                "weight": cat["weight"],
                "severity": cat["severity"],
                "description": cat["description"],
                "matched": is_hit,
                "match_count": len(cat_matches),
                "matches": cat_matches,
            }
        )

    # Nonlinear synergy boost: if OTP/Payment/RemoteAccess is combined with Urgency/Threats/Bank
    hit_ids = {c["id"] for c in matched_categories}
    critical_ids = {
        "otp_credential_harvesting",
        "legal_digital_arrest_threats",
        "payment_transfer_demands",
        "remote_access_coercion",
    }
    coercion_ids = {
        "urgency_time_pressure",
        "bank_kyc_account_freeze",
        "authority_government_spoofing",
        "secrecy_isolation_coercion",
    }

    if (hit_ids & critical_ids) and (hit_ids & coercion_ids):
        accumulated_points += 18.0

    risk_score = float(min(100.0, round(accumulated_points, 1)))

    # Merge overlapping spans for clean inline rendering
    raw_spans.sort(key=lambda s: (s["start"], -(s["end"] - s["start"])))
    merged_spans: List[Dict[str, Any]] = []
    for sp in raw_spans:
        if not merged_spans or sp["start"] >= merged_spans[-1]["end"]:
            merged_spans.append(sp)

    # Determine verdict
    if risk_score >= 65.0 or (len(hit_ids & critical_ids) >= 1 and risk_score >= 45.0):
        verdict_label = "Scam"
        risk_tier = "Critical Fraud / Scam Script" if risk_score >= 80 else "High-Risk Scam Script"
    elif risk_score >= 22.0 or "lottery_prize_promotional_lure" in hit_ids:
        verdict_label = "Spam"
        risk_tier = "Promotional / Suspicious Script"
    else:
        verdict_label = "Safe"
        risk_tier = "Benign Conversation"

    if matched_categories:
        top_names = ", ".join(c["name"] for c in matched_categories[:3])
        summary_explanation = (
            f"Detected {len(matched_categories)} of 10 scam-indicator categories "
            f"({top_names}), producing a weighted transcript risk score of {risk_score}/100 ({risk_tier})."
        )
    else:
        summary_explanation = (
            f"Scanned {word_count} words across all 10 scam-indicator regex categories. "
            "Zero coercive, phishing, or financial extortion patterns were detected."
        )

    return {
        "transcript_risk_score": risk_score,
        "verdict_label": verdict_label,
        "risk_tier": risk_tier,
        "matched_count": len(matched_categories),
        "total_categories_checked": len(SCAM_CATEGORIES),
        "matched_categories": matched_categories,
        "all_categories_status": all_categories_status,
        "highlighted_spans": merged_spans,
        "word_count": word_count,
        "summary_explanation": summary_explanation,
    }


if __name__ == "__main__":
    for title, item in SAMPLE_TRANSCRIPTS.items():
        res = analyze_transcript(item["transcript"])
        print(
            f"[{title}] -> Score: {res['transcript_risk_score']}/100 | "
            f"Verdict: {res['verdict_label']} | Matched: {res['matched_count']}/10 categories"
        )
