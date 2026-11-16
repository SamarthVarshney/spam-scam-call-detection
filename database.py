"""
Database Module (SQLite)
========================
Provides persistent SQLite storage for:
1. community_reports: User-submitted reports on phone numbers (Safe, Spam, Scam)
2. number_reputation: Per-number historical reputation scores, carrier metadata, and counters
3. call_logs: Audit log of all analyzed calls from the Prediction & Risk Engines

Authors: Silvia Noatia (2026279652), Fatima Iqbal (2026187337)
Mentor: Dharmendra Kumar | Sharda University (CSCR2600 PBL-1)
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional

from data_preprocessing import BASE_DIR, sanitize_phone_number

DB_DIR = BASE_DIR / "data"
DB_PATH = DB_DIR / "call_detection.db"


def get_connection(db_path: Path = DB_PATH) -> sqlite3.Connection:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_database(db_path: Path = DB_PATH) -> None:
    """
    Creates the SQLite schema for community_reports, number_reputation, and call_logs,
    and seeds realistic baseline records if the database is empty.
    """
    conn = get_connection(db_path)
    cur = conn.cursor()

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS community_reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            phone_number TEXT NOT NULL,
            reported_category TEXT NOT NULL,
            scam_subtype TEXT NOT NULL,
            claimed_identity TEXT,
            severity INTEGER DEFAULT 3,
            reporter_comment TEXT,
            reporter_region TEXT DEFAULT 'Delhi NCR',
            upvotes INTEGER DEFAULT 1,
            created_at TEXT NOT NULL
        )
        """
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS number_reputation (
            phone_number TEXT PRIMARY KEY,
            reputation_risk_score REAL NOT NULL,
            status_tag TEXT NOT NULL,
            carrier_name TEXT,
            origin_region TEXT,
            total_reports INTEGER DEFAULT 0,
            scam_reports INTEGER DEFAULT 0,
            spam_reports INTEGER DEFAULT 0,
            safe_votes INTEGER DEFAULT 0,
            total_analyses INTEGER DEFAULT 0,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL
        )
        """
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS call_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            phone_number TEXT NOT NULL,
            predicted_label TEXT NOT NULL,
            ml_risk_score REAL NOT NULL,
            community_risk_score REAL NOT NULL,
            reputation_risk_score REAL NOT NULL,
            final_risk_score REAL NOT NULL,
            risk_level TEXT NOT NULL,
            prob_safe REAL NOT NULL,
            prob_spam REAL NOT NULL,
            prob_scam REAL NOT NULL,
            top_reason TEXT,
            reasons_json TEXT,
            features_json TEXT,
            transcript_score REAL,
            analyzed_at TEXT NOT NULL
        )
        """
    )

    conn.commit()

    # Check if already seeded
    cur.execute("SELECT COUNT(*) as cnt FROM number_reputation")
    row = cur.fetchone()
    if row and row["cnt"] == 0:
        _seed_initial_data(conn)

    conn.close()


def _seed_initial_data(conn: sqlite3.Connection) -> None:
    """
    Seeds realistic Indian & International scam, spam, and verified safe numbers,
    community reports, and historical call logs so the Dashboard and Reputation
    Lookup work immediately on first launch.
    """
    now = datetime.now()

    def ts(hours_ago: float) -> str:
        return (now - timedelta(hours=hours_ago)).strftime("%Y-%m-%d %H:%M:%S")

    seed_reputations = [
        (
            "+91-92104-88319",
            94.5,
            "Blacklisted Scam Source",
            "Virtual VoIP Trunk (Spoofed)",
            "International Gateway / Mumbai",
            34,
            31,
            3,
            0,
            48,
            ts(320),
            ts(1.5),
        ),
        (
            "+92-300-4918204",
            98.0,
            "Critical Fraud Watchlist",
            "Cross-Border VoIP SIP",
            "International (Non-Domestic)",
            52,
            50,
            2,
            0,
            67,
            ts(480),
            ts(0.8),
        ),
        (
            "+91-140-8834210",
            68.0,
            "High-Volume Telemarketer",
            "Airtel Commercial PRI 140-Series",
            "Gurugram, Haryana",
            28,
            2,
            25,
            1,
            41,
            ts(600),
            ts(3.2),
        ),
        (
            "+91-81309-44102",
            89.0,
            "Confirmed KYC / OTP Phishing",
            "Unverified SIM Box Cluster",
            "Jamtara / Kolkata Routing",
            23,
            21,
            2,
            0,
            31,
            ts(210),
            ts(4.0),
        ),
        (
            "+91-160-4001290",
            62.5,
            "Promotional Robocall Trunk",
            "Jio Enterprise SIP Trunk",
            "Noida, UP",
            19,
            1,
            17,
            1,
            29,
            ts(410),
            ts(6.5),
        ),
        (
            "+44-20-7946-0823",
            91.5,
            "Spoofed Customs / Courier Scam",
            "International CLI Spoof",
            "UK Virtual DID",
            17,
            16,
            1,
            0,
            22,
            ts(190),
            ts(5.1),
        ),
        (
            "+91-98104-52391",
            8.0,
            "Verified Safe Subscriber",
            "Reliance Jio 5G True",
            "Greater Noida, UP",
            6,
            0,
            0,
            6,
            14,
            ts(900),
            ts(2.0),
        ),
        (
            "+91-1800-112-211",
            6.5,
            "Verified Institutional Toll-Free",
            "BSNL Enterprise Toll-Free",
            "New Delhi",
            11,
            0,
            1,
            10,
            25,
            ts(1200),
            ts(8.0),
        ),
        (
            "+91-99582-71044",
            12.0,
            "Trusted Delivery / Personal Line",
            "Vodafone Idea Mobile",
            "Delhi NCR",
            4,
            0,
            0,
            4,
            9,
            ts(500),
            ts(11.0),
        ),
        (
            "+1-800-555-0192",
            74.0,
            "Tech Support Robocall Relay",
            "US Toll-Free VoIP Bridge",
            "North America VoIP",
            15,
            6,
            9,
            0,
            19,
            ts(350),
            ts(9.4),
        ),
    ]

    cur = conn.cursor()
    cur.executemany(
        """
        INSERT OR IGNORE INTO number_reputation (
            phone_number, reputation_risk_score, status_tag, carrier_name,
            origin_region, total_reports, scam_reports, spam_reports,
            safe_votes, total_analyses, first_seen, last_seen
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        seed_reputations,
    )

    seed_reports = [
        (
            "+91-92104-88319",
            "Scam",
            "Digital Arrest / CBI & Customs Impersonation",
            "Mumbai Cyber Crime / FedEx Customs",
            5,
            "Caller claimed a parcel in my Aadhaar name contained illegal passports and demanded I stay on Skype video call for 'Digital Arrest' verification and transfer ₹85,000 to an RBI audit account.",
            "Greater Noida",
            29,
            ts(2.2),
        ),
        (
            "+91-92104-88319",
            "Scam",
            "Authority Spoofing & Extortion",
            "Narcotics Control Bureau Officer",
            5,
            "Threatened immediate arrest warrant unless security deposit was sent via UPI within 15 minutes. Heavy VoIP delay at start of call.",
            "New Delhi",
            18,
            ts(14.5),
        ),
        (
            "+92-300-4918204",
            "Scam",
            "Lottery / KBC Prize Fraud",
            "WhatsApp / KBC Lucky Draw Desk",
            5,
            "International +92 number demanding ₹12,500 processing tax to release a ₹25 Lakh lottery prize.",
            "Noida",
            41,
            ts(5.0),
        ),
        (
            "+91-81309-44102",
            "Scam",
            "Bank KYC / OTP Phishing",
            "SBI / HDFC Card Block Department",
            5,
            "Asked for the 6-digit OTP sent to my phone to prevent immediate PAN/KYC suspension and asked me to install AnyDesk.",
            "Ghaziabad",
            22,
            ts(7.8),
        ),
        (
            "+91-140-8834210",
            "Spam",
            "Unsolicited Loan & Credit Card Telemarketing",
            "Pre-Approved Personal Loan Desk",
            3,
            "Automated robocall followed by agent pushing pre-approved personal loans. Called 4 times today despite DND registration.",
            "Gurugram",
            15,
            ts(3.6),
        ),
        (
            "+91-160-4001290",
            "Spam",
            "Real Estate & Insurance Cold Call",
            "Commercial Property Advisory",
            2,
            "Persistent commercial spam calling during afternoon hours with automated IVR prompt.",
            "Delhi NCR",
            9,
            ts(12.0),
        ),
        (
            "+44-20-7946-0823",
            "Scam",
            "International Parcel / Customs Seizure Scam",
            "International DHL / UK Border Control",
            5,
            "Automated voice press-1 prompt connecting to a fake customs officer demanding customs clearance fee.",
            "Bengaluru",
            14,
            ts(8.4),
        ),
        (
            "+1-800-555-0192",
            "Spam",
            "Automated Warranty / Tech Support Robocall",
            "Windows / Amazon Refund Bot",
            4,
            "2.8 second dead-air delay before robotic voice claimed an unauthorized $499 charge on my account.",
            "Hyderabad",
            11,
            ts(18.0),
        ),
        (
            "+91-98104-52391",
            "Safe",
            "Verified Personal / Academic Contact",
            "Sharda University Student Coordinator",
            1,
            "Legitimate phone number belonging to university project team coordinator.",
            "Greater Noida",
            8,
            ts(24.0),
        ),
        (
            "+91-1800-112-211",
            "Safe",
            "Official Bank Customer Helpline",
            "Official Toll-Free Service Line",
            1,
            "Verified official customer support number; never asks for OTP or PIN.",
            "Mumbai",
            12,
            ts(36.0),
        ),
    ]

    cur.executemany(
        """
        INSERT INTO community_reports (
            phone_number, reported_category, scam_subtype, claimed_identity,
            severity, reporter_comment, reporter_region, upvotes, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        seed_reports,
    )

    seed_logs = [
        (
            "+91-92104-88319",
            "Scam",
            93.4,
            95.0,
            94.5,
            94.0,
            "Critical Scam Alert",
            0.012,
            0.068,
            0.920,
            "Unverified CLI with high complaint density (0.86) and 3.4s VoIP bridge delay",
            json.dumps([
                "Caller ID attestation is Unverified (high spoofing risk).",
                "Initial pickup silence of 3.40s strongly indicates a VoIP bridge or auto-dialer.",
                "31 community scam reports on record (Digital Arrest / Customs impersonation).",
            ]),
            json.dumps({"calls_last_24h": 38, "silence_initial_sec": 3.4, "prefix_type": "International_VoIP"}),
            92.0,
            ts(1.2),
        ),
        (
            "+91-140-8834210",
            "Spam",
            66.2,
            68.5,
            68.0,
            67.0,
            "Likely Telemarketing Spam",
            0.055,
            0.845,
            0.100,
            "Registered 140-series telemarketing prefix with 58 calls in last 24h and 78% short hang-ups",
            json.dumps([
                "Number uses a commercial 140-series telemarketing prefix.",
                "High outbound call velocity (58 calls in 24h) with 78% short hang-ups.",
                "25 community spam reports confirm unsolicited loan promotions.",
            ]),
            json.dumps({"calls_last_24h": 58, "short_call_ratio": 0.78, "prefix_type": "Telemarketing_140"}),
            38.0,
            ts(2.8),
        ),
        (
            "+91-98104-52391",
            "Safe",
            6.8,
            5.0,
            8.0,
            6.5,
            "Safe / Verified Caller",
            0.952,
            0.036,
            0.012,
            "STIR/SHAKEN Class-A attested domestic mobile in contact network with normal call cadence",
            json.dumps([
                "Cryptographic STIR/SHAKEN Level-A attestation verified by carrier.",
                "Caller is present in recipient contact network with 89% answer rate.",
                "Zero spam or scam complaints in community database.",
            ]),
            json.dumps({"calls_last_24h": 3, "answer_rate": 0.89, "prefix_type": "Domestic_Mobile"}),
            0.0,
            ts(4.1),
        ),
        (
            "+91-81309-44102",
            "Scam",
            88.5,
            91.0,
            89.0,
            89.2,
            "High Risk Scam",
            0.021,
            0.109,
            0.870,
            "Newly activated SIM (9 days old) dialing 94% unique recipients with KYC phishing reports",
            json.dumps([
                "Burner SIM signature: number activated only 9 days ago.",
                "94% of calls target unique uncontacted recipients.",
                "21 community scam reports flag SBI/HDFC KYC & OTP theft.",
            ]),
            json.dumps({"calls_last_24h": 34, "number_age_days": 9, "prefix_type": "Domestic_Mobile"}),
            88.0,
            ts(5.5),
        ),
        (
            "+92-300-4918204",
            "Scam",
            96.8,
            98.5,
            98.0,
            97.4,
            "Critical Scam Alert",
            0.005,
            0.032,
            0.963,
            "Cross-border VoIP origin (+92) with spoofed CLI and 50 confirmed fraud reports",
            json.dumps([
                "International cross-border VoIP prefix outside normal domestic calling graph.",
                "Caller line flagged as Spoofed CLI with 3.8s connection delay.",
                "Blacklisted by 50 community fraud reports (Lottery/WhatsApp advance-fee scam).",
            ]),
            json.dumps({"calls_last_24h": 42, "silence_initial_sec": 3.8, "prefix_type": "International_VoIP"}),
            95.0,
            ts(7.0),
        ),
        (
            "+91-160-4001290",
            "Spam",
            61.4,
            63.0,
            62.5,
            62.0,
            "Likely Telemarketing Spam",
            0.095,
            0.810,
            0.095,
            "PRI Trunk commercial dialer with 44 calls/24h and 2.4s auto-dialer handoff silence",
            json.dumps([
                "Originates from a commercial PRI trunk dialing 44 calls/day.",
                "2.4s initial silence indicates predictive dialer queue handoff.",
            ]),
            json.dumps({"calls_last_24h": 44, "silence_initial_sec": 2.4, "prefix_type": "Telemarketing_140"}),
            None,
            ts(9.2),
        ),
        (
            "+91-99582-71044",
            "Safe",
            11.2,
            8.0,
            12.0,
            10.5,
            "Safe / Verified Caller",
            0.918,
            0.062,
            0.020,
            "Long-standing mobile subscriber (1,420 days active) with natural conversation durations",
            json.dumps([
                "Number active for over 3.8 years with <1% complaint rate.",
                "Natural call duration (185s average) and zero auto-dialer delay.",
            ]),
            json.dumps({"calls_last_24h": 4, "number_age_days": 1420, "prefix_type": "Domestic_Mobile"}),
            None,
            ts(12.4),
        ),
    ]

    cur.executemany(
        """
        INSERT INTO call_logs (
            phone_number, predicted_label, ml_risk_score, community_risk_score,
            reputation_risk_score, final_risk_score, risk_level, prob_safe,
            prob_spam, prob_scam, top_reason, reasons_json, features_json,
            transcript_score, analyzed_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        seed_logs,
    )

    conn.commit()


def get_number_intelligence(phone_number: str, db_path: Path = DB_PATH) -> Dict[str, Any]:
    """
    Retrieves community report statistics and historical reputation for a phone number.
    If the number is not yet in the database, derives an initial baseline from its numbering plan prefix.
    """
    init_database(db_path)
    clean_num = sanitize_phone_number(phone_number)
    conn = get_connection(db_path)
    cur = conn.cursor()

    cur.execute(
        "SELECT * FROM number_reputation WHERE phone_number = ?",
        (clean_num,),
    )
    rep_row = cur.fetchone()

    cur.execute(
        """
        SELECT id, phone_number, reported_category, scam_subtype, claimed_identity,
               severity, reporter_comment, reporter_region, upvotes, created_at
        FROM community_reports
        WHERE phone_number = ?
        ORDER BY id DESC
        LIMIT 25
        """,
        (clean_num,),
    )
    reports = [dict(r) for r in cur.fetchall()]
    conn.close()

    if rep_row is not None:
        rep_dict = dict(rep_row)
        total_rep = max(rep_dict["total_reports"], 1)
        scam_cnt = rep_dict["scam_reports"]
        spam_cnt = rep_dict["spam_reports"]
        safe_cnt = rep_dict["safe_votes"]

        # Calculate community risk score (0-100) from report mix and volume confidence
        volume_factor = min(1.0, (scam_cnt + spam_cnt + safe_cnt) / 5.0)
        raw_comm = (
            (scam_cnt * 100.0 + spam_cnt * 65.0 + safe_cnt * 4.0) / total_rep
        )
        community_score = round(
            raw_comm * volume_factor + rep_dict["reputation_risk_score"] * (1.0 - volume_factor),
            1,
        )
        reputation_score = round(float(rep_dict["reputation_risk_score"]), 1)
        return {
            "phone_number": clean_num,
            "known_in_db": True,
            "community_risk_score": float(min(100.0, max(0.0, community_score))),
            "reputation_risk_score": float(min(100.0, max(0.0, reputation_score))),
            "status_tag": rep_dict["status_tag"],
            "carrier_name": rep_dict["carrier_name"],
            "origin_region": rep_dict["origin_region"],
            "total_reports": rep_dict["total_reports"],
            "scam_reports": scam_cnt,
            "spam_reports": spam_cnt,
            "safe_votes": safe_cnt,
            "total_analyses": rep_dict["total_analyses"],
            "first_seen": rep_dict["first_seen"],
            "last_seen": rep_dict["last_seen"],
            "reports": reports,
        }

    # Heuristic baseline for an unseen phone number based on prefix structure
    if clean_num.startswith("+91-140") or clean_num.startswith("+91-160"):
        base_rep = 58.0
        base_comm = 52.0
        tag = "Registered Telemarketing Prefix (Unreported Number)"
        carrier = "Commercial PRI 140/160 Series"
        region = "India Telecom Commercial Circle"
    elif clean_num.startswith("+92") or clean_num.startswith("+234") or clean_num.startswith("+855"):
        base_rep = 78.0
        base_comm = 70.0
        tag = "High-Risk Cross-Border Prefix"
        carrier = "International Gateway Trunk"
        region = "Foreign Origin Gateway"
    elif not clean_num.startswith("+91"):
        base_rep = 48.0
        base_comm = 42.0
        tag = "Unverified International Number"
        carrier = "International Carrier / VoIP"
        region = "International"
    else:
        base_rep = 22.0
        base_comm = 20.0
        tag = "No Prior Adverse History"
        carrier = "Domestic Mobile Subscriber"
        region = "India Domestic Circle"

    return {
        "phone_number": clean_num,
        "known_in_db": False,
        "community_risk_score": base_comm,
        "reputation_risk_score": base_rep,
        "status_tag": tag,
        "carrier_name": carrier,
        "origin_region": region,
        "total_reports": 0,
        "scam_reports": 0,
        "spam_reports": 0,
        "safe_votes": 0,
        "total_analyses": 0,
        "first_seen": "First Sighting",
        "last_seen": "Just Now",
        "reports": [],
    }


def submit_community_report(
    phone_number: str,
    reported_category: str,
    scam_subtype: str,
    claimed_identity: str = "",
    severity: int = 3,
    reporter_comment: str = "",
    reporter_region: str = "Delhi NCR",
    db_path: Path = DB_PATH,
) -> Dict[str, Any]:
    """
    Inserts a new community report into SQLite and dynamically updates the
    number's reputation record.
    """
    init_database(db_path)
    clean_num = sanitize_phone_number(phone_number)
    cat = reported_category if reported_category in ("Safe", "Spam", "Scam") else "Spam"
    sev = int(max(1, min(5, severity)))
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    conn = get_connection(db_path)
    cur = conn.cursor()

    cur.execute(
        """
        INSERT INTO community_reports (
            phone_number, reported_category, scam_subtype, claimed_identity,
            severity, reporter_comment, reporter_region, upvotes, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?)
        """,
        (
            clean_num,
            cat,
            scam_subtype.strip() or "General Report",
            claimed_identity.strip() or "Unspecified Caller",
            sev,
            reporter_comment.strip() or "Reported via Community Threat Portal.",
            reporter_region.strip() or "Delhi NCR",
            now_str,
        ),
    )

    cur.execute("SELECT * FROM number_reputation WHERE phone_number = ?", (clean_num,))
    existing = cur.fetchone()

    if existing:
        ex = dict(existing)
        tot = ex["total_reports"] + 1
        scam_c = ex["scam_reports"] + (1 if cat == "Scam" else 0)
        spam_c = ex["spam_reports"] + (1 if cat == "Spam" else 0)
        safe_c = ex["safe_votes"] + (1 if cat == "Safe" else 0)

        # Recalculate reputation score
        target_score = (scam_c * 96.0 + spam_c * 66.0 + safe_c * 5.0) / max(tot, 1)
        new_rep = round(0.35 * float(ex["reputation_risk_score"]) + 0.65 * target_score, 1)

        if scam_c >= 3 or new_rep >= 80:
            new_tag = "Community Flagged Scam Source"
        elif spam_c >= 3 or new_rep >= 50:
            new_tag = "Community Flagged Telemarketer"
        elif safe_c > (scam_c + spam_c):
            new_tag = "Community Verified Safe"
        else:
            new_tag = "Under Community Watch"

        cur.execute(
            """
            UPDATE number_reputation
            SET reputation_risk_score = ?,
                status_tag = ?,
                total_reports = ?,
                scam_reports = ?,
                spam_reports = ?,
                safe_votes = ?,
                last_seen = ?
            WHERE phone_number = ?
            """,
            (new_rep, new_tag, tot, scam_c, spam_c, safe_c, now_str, clean_num),
        )
    else:
        scam_c = 1 if cat == "Scam" else 0
        spam_c = 1 if cat == "Spam" else 0
        safe_c = 1 if cat == "Safe" else 0
        if cat == "Scam":
            new_rep = min(95.0, 72.0 + sev * 4.0)
            new_tag = "Newly Reported Scam Number"
        elif cat == "Spam":
            new_rep = min(80.0, 52.0 + sev * 3.0)
            new_tag = "Newly Reported Spam Number"
        else:
            new_rep = 10.0
            new_tag = "Community Reported Safe"

        cur.execute(
            """
            INSERT INTO number_reputation (
                phone_number, reputation_risk_score, status_tag, carrier_name,
                origin_region, total_reports, scam_reports, spam_reports,
                safe_votes, total_analyses, first_seen, last_seen
            ) VALUES (?, ?, ?, ?, ?, 1, ?, ?, ?, 1, ?, ?)
            """,
            (
                clean_num,
                new_rep,
                new_tag,
                "Community Submitted Line",
                reporter_region.strip() or "India",
                scam_c,
                spam_c,
                safe_c,
                now_str,
                now_str,
            ),
        )

    conn.commit()
    conn.close()
    return get_number_intelligence(clean_num, db_path)


def log_analyzed_call(
    phone_number: str,
    predicted_label: str,
    ml_risk_score: float,
    community_risk_score: float,
    reputation_risk_score: float,
    final_risk_score: float,
    risk_level: str,
    probabilities: Dict[str, float],
    reasons: List[str],
    features: Dict[str, Any],
    transcript_score: Optional[float] = None,
    db_path: Path = DB_PATH,
) -> int:
    """
    Appends an analyzed call record to call_logs and increments total_analyses
    in number_reputation.
    """
    init_database(db_path)
    clean_num = sanitize_phone_number(phone_number)
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    top_reason = reasons[0] if reasons else "Evaluated via multi-signal ML & Risk Engine."

    conn = get_connection(db_path)
    cur = conn.cursor()

    cur.execute(
        """
        INSERT INTO call_logs (
            phone_number, predicted_label, ml_risk_score, community_risk_score,
            reputation_risk_score, final_risk_score, risk_level, prob_safe,
            prob_spam, prob_scam, top_reason, reasons_json, features_json,
            transcript_score, analyzed_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            clean_num,
            predicted_label,
            round(float(ml_risk_score), 1),
            round(float(community_risk_score), 1),
            round(float(reputation_risk_score), 1),
            round(float(final_risk_score), 1),
            risk_level,
            round(float(probabilities.get("Safe", 0.0)), 4),
            round(float(probabilities.get("Spam", 0.0)), 4),
            round(float(probabilities.get("Scam", 0.0)), 4),
            top_reason,
            json.dumps(reasons),
            json.dumps(features),
            round(float(transcript_score), 1) if transcript_score is not None else None,
            now_str,
        ),
    )
    log_id = int(cur.lastrowid)

    cur.execute("SELECT total_analyses FROM number_reputation WHERE phone_number = ?", (clean_num,))
    rep_row = cur.fetchone()
    if rep_row:
        cur.execute(
            "UPDATE number_reputation SET total_analyses = total_analyses + 1, last_seen = ? WHERE phone_number = ?",
            (now_str, clean_num),
        )

    conn.commit()
    conn.close()
    return log_id


def get_dashboard_statistics(db_path: Path = DB_PATH) -> Dict[str, Any]:
    """
    Aggregates live telemetry from call_logs, community_reports, and number_reputation
    to power the Live Threat Intelligence Dashboard.
    """
    init_database(db_path)
    conn = get_connection(db_path)
    cur = conn.cursor()

    cur.execute("SELECT COUNT(*) as cnt FROM call_logs")
    total_logs = int(cur.fetchone()["cnt"])

    cur.execute(
        """
        SELECT predicted_label, COUNT(*) as cnt, AVG(final_risk_score) as avg_score
        FROM call_logs
        GROUP BY predicted_label
        """
    )
    by_label = {r["predicted_label"]: {"count": r["cnt"], "avg_score": round(r["avg_score"], 1)} for r in cur.fetchall()}

    cur.execute("SELECT COUNT(*) as cnt FROM community_reports")
    total_reports = int(cur.fetchone()["cnt"])

    cur.execute("SELECT COUNT(*) as cnt FROM number_reputation WHERE reputation_risk_score >= 70")
    high_risk_numbers = int(cur.fetchone()["cnt"])

    cur.execute(
        """
        SELECT * FROM call_logs
        ORDER BY id DESC
        LIMIT 30
        """
    )
    recent_logs = []
    for r in cur.fetchall():
        d = dict(r)
        try:
            d["reasons"] = json.loads(d.get("reasons_json") or "[]")
        except Exception:
            d["reasons"] = []
        recent_logs.append(d)

    cur.execute(
        """
        SELECT * FROM community_reports
        ORDER BY id DESC
        LIMIT 25
        """
    )
    recent_reports = [dict(r) for r in cur.fetchall()]

    cur.execute(
        """
        SELECT * FROM number_reputation
        ORDER BY reputation_risk_score DESC, total_reports DESC
        LIMIT 15
        """
    )
    watchlist = [dict(r) for r in cur.fetchall()]

    cur.execute(
        """
        SELECT scam_subtype, reported_category, COUNT(*) as count
        FROM community_reports
        GROUP BY scam_subtype, reported_category
        ORDER BY count DESC
        """
    )
    subtype_breakdown = [dict(r) for r in cur.fetchall()]

    conn.close()

    scam_count = by_label.get("Scam", {}).get("count", 0)
    spam_count = by_label.get("Spam", {}).get("count", 0)
    safe_count = by_label.get("Safe", {}).get("count", 0)

    return {
        "total_calls_analyzed": total_logs,
        "scam_calls_detected": scam_count,
        "spam_calls_detected": spam_count,
        "safe_calls_verified": safe_count,
        "total_community_reports": total_reports,
        "high_risk_watchlist_count": high_risk_numbers,
        "label_summary": by_label,
        "recent_logs": recent_logs,
        "recent_reports": recent_reports,
        "watchlist": watchlist,
        "subtype_breakdown": subtype_breakdown,
    }


def upvote_community_report(report_id: int, db_path: Path = DB_PATH) -> Optional[Dict[str, Any]]:
    """
    Increments the upvote counter on a community report and returns the updated
    intelligence for the associated phone number.
    """
    init_database(db_path)
    conn = get_connection(db_path)
    cur = conn.cursor()

    cur.execute("SELECT phone_number, reported_category FROM community_reports WHERE id = ?", (report_id,))
    row = cur.fetchone()
    if not row:
        conn.close()
        return None

    phone_num = row["phone_number"]
    cat = row["reported_category"]

    cur.execute("UPDATE community_reports SET upvotes = upvotes + 1 WHERE id = ?", (report_id,))

    # Slightly nudge reputation score if a Scam/Spam report receives community confirmation
    if cat == "Scam":
        cur.execute(
            "UPDATE number_reputation SET reputation_risk_score = MIN(99.5, ROUND(reputation_risk_score + 0.8, 1)) WHERE phone_number = ?",
            (phone_num,),
        )
    elif cat == "Spam":
        cur.execute(
            "UPDATE number_reputation SET reputation_risk_score = MIN(88.0, ROUND(reputation_risk_score + 0.5, 1)) WHERE phone_number = ?",
            (phone_num,),
        )
    elif cat == "Safe":
        cur.execute(
            "UPDATE number_reputation SET reputation_risk_score = MAX(2.0, ROUND(reputation_risk_score - 0.8, 1)) WHERE phone_number = ?",
            (phone_num,),
        )

    conn.commit()
    conn.close()
    return get_number_intelligence(phone_num, db_path)


def get_all_community_reports(
    category: str = "All",
    search: str = "",
    limit: int = 50,
    db_path: Path = DB_PATH,
) -> List[Dict[str, Any]]:
    """
    Returns filtered community reports for the global threat feed.
    """
    init_database(db_path)
    conn = get_connection(db_path)
    cur = conn.cursor()

    clauses = []
    params: List[Any] = []

    if category in ("Safe", "Spam", "Scam"):
        clauses.append("reported_category = ?")
        params.append(category)

    if search and search.strip():
        q = f"%{search.strip()}%"
        clauses.append(
            "(phone_number LIKE ? OR scam_subtype LIKE ? OR claimed_identity LIKE ? OR reporter_comment LIKE ? OR reporter_region LIKE ?)"
        )
        params.extend([q, q, q, q, q])

    where_sql = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    sql = f"""
        SELECT id, phone_number, reported_category, scam_subtype, claimed_identity,
               severity, reporter_comment, reporter_region, upvotes, created_at
        FROM community_reports
        {where_sql}
        ORDER BY id DESC
        LIMIT ?
    """
    params.append(int(limit))
    cur.execute(sql, tuple(params))
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows


def export_table_to_csv_string(table_name: str, db_path: Path = DB_PATH) -> str:
    """
    Exports call_logs, community_reports, or number_reputation to a CSV string.
    """
    import csv
    import io

    allowed = {"call_logs", "community_reports", "number_reputation"}
    if table_name not in allowed:
        table_name = "call_logs"

    init_database(db_path)
    conn = get_connection(db_path)
    cur = conn.cursor()
    cur.execute(f"SELECT * FROM {table_name} ORDER BY 1 DESC")
    rows = cur.fetchall()
    conn.close()

    output = io.StringIO()
    if not rows:
        return ""
    headers = list(rows[0].keys())
    writer = csv.DictWriter(output, fieldnames=headers)
    writer.writeheader()
    for r in rows:
        writer.writerow(dict(r))
    return output.getvalue()

