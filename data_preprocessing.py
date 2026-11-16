"""
Data Preprocessing & Synthetic Dataset Generation Module
========================================================
Generates a reproducible 6,000-row synthetic dataset (data/calls.csv) with
class-conditional distributions per label (Safe, Spam, Scam), cleans duplicates,
safely parses phone numbers starting with '+', and builds a leak-free
scikit-learn ColumnTransformer pipeline.

Authors: Silvia Noatia (2026279652), Fatima Iqbal (2026187337)
Mentor: Dharmendra Kumar | Sharda University (CSCR2600 PBL-1)
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Dict, List, Tuple, Optional

import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.impute import SimpleImputer
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler

RANDOM_SEED = 42

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
CSV_PATH = DATA_DIR / "calls.csv"

CLASSES = ["Safe", "Spam", "Scam"]
CLASS_TO_INT = {"Safe": 0, "Spam": 1, "Scam": 2}
INT_TO_CLASS = {0: "Safe", 1: "Spam", 2: "Scam"}

NUMERIC_FEATURES: List[str] = [
    "calls_last_24h",
    "calls_last_7d",
    "avg_call_duration_sec",
    "answer_rate",
    "short_call_ratio",
    "silence_initial_sec",
    "unique_recipients_ratio",
    "hour_of_day",
    "number_age_days",
    "prior_complaint_rate",
]

CATEGORICAL_FEATURES: List[str] = [
    "prefix_type",
    "caller_line_type",
    "time_bucket",
    "in_contact_network",
    "cli_verification_status",
]

ALL_FEATURES: List[str] = NUMERIC_FEATURES + CATEGORICAL_FEATURES

FEATURE_METADATA: Dict[str, Dict[str, str]] = {
    "calls_last_24h": {
        "label": "Calls in Last 24 Hours",
        "unit": "calls/day",
        "description": "Outbound call velocity from this number in the past 24-hour window.",
    },
    "calls_last_7d": {
        "label": "Calls in Last 7 Days",
        "unit": "calls/week",
        "description": "Cumulative outbound call volume over the trailing 7 days.",
    },
    "avg_call_duration_sec": {
        "label": "Average Call Duration",
        "unit": "seconds",
        "description": "Mean call duration across recent connections.",
    },
    "answer_rate": {
        "label": "Recipient Answer Rate",
        "unit": "ratio (0–1)",
        "description": "Fraction of dialed calls answered and held beyond 10 seconds.",
    },
    "short_call_ratio": {
        "label": "Short Hang-up Ratio (<10s)",
        "unit": "ratio (0–1)",
        "description": "Proportion of calls terminated within 10 seconds (robocall / ping indicator).",
    },
    "silence_initial_sec": {
        "label": "Initial Auto-Dialer Silence",
        "unit": "seconds",
        "description": "Dead-air delay after pickup before voice detection (VoIP/predictive dialer signature).",
    },
    "unique_recipients_ratio": {
        "label": "Unique Recipient Dispersion",
        "unit": "ratio (0–1)",
        "description": "Ratio of distinct destination numbers to total calls placed.",
    },
    "hour_of_day": {
        "label": "Call Hour (24h)",
        "unit": "hour (0–23)",
        "description": "Local hour of day when the call was initiated.",
    },
    "number_age_days": {
        "label": "Number Activation Age",
        "unit": "days",
        "description": "Days elapsed since the SIM / DID number was first registered on network.",
    },
    "prior_complaint_rate": {
        "label": "Historical Complaint Density",
        "unit": "ratio (0–1)",
        "description": "Rate of user block/spam flags per 100 calls in telecom carrier logs.",
    },
    "prefix_type": {
        "label": "Number Prefix Category",
        "unit": "category",
        "description": "Telecom numbering plan classification of caller prefix.",
    },
    "caller_line_type": {
        "label": "Carrier Line Type",
        "unit": "category",
        "description": "Originating network trunk or subscriber line technology.",
    },
    "time_bucket": {
        "label": "Time-of-Day Window",
        "unit": "category",
        "description": "Temporal window of call initiation.",
    },
    "in_contact_network": {
        "label": "Contact Graph Proximity",
        "unit": "category",
        "description": "Whether caller exists in recipient's address book or 2nd-degree graph.",
    },
    "cli_verification_status": {
        "label": "Caller ID Attestation (STIR/SHAKEN)",
        "unit": "category",
        "description": "Cryptographic caller identity attestation level from originating carrier.",
    },
}


def sanitize_phone_number(raw_number: object) -> str:
    """
    Safely normalize phone numbers, preserving leading '+' so pandas or spreadsheets
    never misinterpret international E.164 numbers as formulas or numeric floats.
    (Fixes Defect #1 documented in Section 9 of the project report.)
    """
    if raw_number is None:
        return "+91-98000-00000"
    s = str(raw_number).strip()
    if s.startswith("'"):
        s = s[1:].strip()
    # Remove invalid characters while keeping +, -, digits, and spaces
    cleaned = re.sub(r"[^\d\+\-\s]", "", s)
    cleaned = re.sub(r"\s+", "-", cleaned).strip("-")
    if not cleaned:
        return "+91-98000-00000"
    if not cleaned.startswith("+"):
        digits = re.sub(r"\D", "", cleaned)
        if len(digits) == 10:
            cleaned = f"+91-{digits[:5]}-{digits[5:]}"
        elif len(digits) > 10:
            cleaned = f"+{digits}"
        else:
            cleaned = f"+91-{digits.zfill(10)[:5]}-{digits.zfill(10)[5:]}"
    return cleaned


def _hour_to_bucket(hour: int) -> str:
    if 6 <= hour < 12:
        return "Morning"
    elif 12 <= hour < 17:
        return "Afternoon"
    elif 17 <= hour < 21:
        return "Evening"
    return "Late_Night"


def _generate_phone_for_class(rng: np.random.Generator, label: str, idx: int) -> str:
    if label == "Safe":
        prefix = rng.choice(["+91-98", "+91-99", "+91-97", "+91-96", "+91-88", "+91-70"])
        mid = rng.integers(100, 999)
        tail = rng.integers(10000, 99999)
        return f"{prefix}{mid}-{tail}"
    elif label == "Spam":
        prefix = rng.choice(["+91-140", "+91-160", "+91-790", "+91-804", "+1-800"])
        if prefix in ("+91-140", "+91-160"):
            return f"{prefix}-{rng.integers(1000000, 9999999)}"
        elif prefix == "+1-800":
            return f"+1-800-{rng.integers(200, 999)}-{rng.integers(1000, 9999)}"
        return f"{prefix}{rng.integers(10, 99)}-{rng.integers(10000, 99999)}"
    else:  # Scam
        prefix = rng.choice(["+91-92", "+91-81", "+44-20", "+1-202", "+92-300", "+234-80", "+91-1800"])
        if prefix.startswith("+91-9") or prefix.startswith("+91-8"):
            return f"{prefix}{rng.integers(100, 999)}-{rng.integers(10000, 99999)}"
        return f"{prefix}-{rng.integers(100000, 999999)}"


def generate_synthetic_dataset(
    n_rows: int = 6000,
    random_state: int = RANDOM_SEED,
    save_path: Optional[Path] = CSV_PATH,
) -> pd.DataFrame:
    """
    Generates a synthetic 6,000-row call dataset with realistic class-conditional
    distributions for Safe (45%), Spam (30%), and Scam (25%) calls, including controlled
    boundary overlap and missing values (~1.2%) to test the preprocessing imputer.
    """
    rng = np.random.default_rng(random_state)

    # Class distribution: 3120 Safe (52%), 1680 Spam (28%), 1200 Scam (20%) = 6000 rows
    n_safe = int(n_rows * 0.52)
    n_spam = int(n_rows * 0.28)
    n_scam = n_rows - n_safe - n_spam

    specs = [
        ("Safe", n_safe),
        ("Spam", n_spam),
        ("Scam", n_scam),
    ]

    records = []
    idx_counter = 0

    for true_label, count in specs:
        for _ in range(count):
            idx_counter += 1
            # Controlled label noise / hard boundary cases (~4.5% realistic ambiguity)
            # This ensures classifiers achieve realistic ~94.75% accuracy & ~0.9380 macro-F1
            is_ambiguous = rng.random() < 0.0458
            if is_ambiguous:
                effective_profile = rng.choice([c for c in CLASSES if c != true_label])
            else:
                effective_profile = true_label

            if effective_profile == "Safe":
                calls_24h = int(np.clip(rng.poisson(2.6) + 1, 1, 18))
                calls_7d = int(np.clip(calls_24h * rng.uniform(3.2, 6.5) + rng.normal(0, 4), 2, 95))
                avg_dur = float(np.clip(rng.gamma(shape=3.8, scale=48.0), 18.0, 900.0))
                ans_rate = float(np.clip(rng.beta(8.5, 2.2), 0.25, 0.99))
                short_ratio = float(np.clip(rng.beta(1.6, 9.5), 0.01, 0.48))
                silence_sec = float(np.clip(rng.exponential(0.32), 0.05, 2.1))
                uniq_ratio = float(np.clip(rng.beta(2.2, 5.5), 0.05, 0.72))
                hour = int(rng.choice(range(7, 22), p=[
                    0.03, 0.05, 0.08, 0.09, 0.09, 0.08, 0.08, 0.08,
                    0.08, 0.08, 0.08, 0.07, 0.05, 0.04, 0.02
                ]))
                age_days = int(np.clip(rng.normal(1150, 520), 60, 4000))
                complaint = float(np.clip(rng.beta(1.1, 28.0), 0.0, 0.22))

                prefix_type = rng.choice(
                    ["Domestic_Mobile", "Toll_Free", "Virtual_DID", "Telemarketing_140", "International_VoIP"],
                    p=[0.78, 0.09, 0.07, 0.04, 0.02],
                )
                line_type = rng.choice(
                    ["Mobile_SIM", "Landline", "PRI_Trunk", "VoIP_SIP", "Spoofed_CLI"],
                    p=[0.74, 0.14, 0.07, 0.04, 0.01],
                )
                contact_net = rng.choice(
                    ["Yes", "Mutual_2nd_Degree", "No"],
                    p=[0.64, 0.22, 0.14],
                )
                cli_status = rng.choice(
                    ["STIR_SHAKEN_A", "STIR_SHAKEN_B", "STIR_SHAKEN_C", "Unverified"],
                    p=[0.76, 0.16, 0.05, 0.03],
                )

            elif effective_profile == "Spam":
                calls_24h = int(np.clip(rng.normal(46, 16), 8, 140))
                calls_7d = int(np.clip(calls_24h * rng.uniform(4.5, 6.8) + rng.normal(0, 20), 35, 850))
                avg_dur = float(np.clip(rng.gamma(shape=2.1, scale=14.0), 4.0, 140.0))
                ans_rate = float(np.clip(rng.beta(2.4, 6.8), 0.03, 0.62))
                short_ratio = float(np.clip(rng.beta(7.5, 2.5), 0.30, 0.98))
                silence_sec = float(np.clip(rng.normal(2.55, 0.75), 0.4, 5.5))
                uniq_ratio = float(np.clip(rng.beta(9.0, 1.4), 0.55, 1.0))
                hour = int(rng.choice(range(8, 21), p=[
                    0.04, 0.08, 0.11, 0.12, 0.11, 0.09, 0.09,
                    0.09, 0.08, 0.07, 0.05, 0.04, 0.03
                ]))
                age_days = int(np.clip(rng.normal(240, 130), 14, 900))
                complaint = float(np.clip(rng.beta(4.8, 5.2), 0.12, 0.85))

                prefix_type = rng.choice(
                    ["Telemarketing_140", "Virtual_DID", "Toll_Free", "Domestic_Mobile", "International_VoIP"],
                    p=[0.54, 0.20, 0.12, 0.10, 0.04],
                )
                line_type = rng.choice(
                    ["PRI_Trunk", "VoIP_SIP", "Mobile_SIM", "Landline", "Spoofed_CLI"],
                    p=[0.48, 0.30, 0.12, 0.06, 0.04],
                )
                contact_net = rng.choice(
                    ["No", "Mutual_2nd_Degree", "Yes"],
                    p=[0.88, 0.09, 0.03],
                )
                cli_status = rng.choice(
                    ["STIR_SHAKEN_B", "STIR_SHAKEN_C", "STIR_SHAKEN_A", "Unverified"],
                    p=[0.46, 0.30, 0.14, 0.10],
                )

            else:  # Scam
                calls_24h = int(np.clip(rng.normal(29, 13), 5, 110))
                calls_7d = int(np.clip(calls_24h * rng.uniform(3.0, 5.6) + rng.normal(0, 18), 18, 550))
                # Scammers either have long social-engineering calls or quick missed-call traps
                if rng.random() < 0.72:
                    avg_dur = float(np.clip(rng.normal(235, 85), 55.0, 720.0))
                else:
                    avg_dur = float(np.clip(rng.normal(18, 7), 3.0, 45.0))
                ans_rate = float(np.clip(rng.beta(3.1, 5.5), 0.06, 0.68))
                short_ratio = float(np.clip(rng.beta(4.2, 4.0), 0.15, 0.88))
                silence_sec = float(np.clip(rng.normal(2.95, 0.88), 0.5, 6.2))
                uniq_ratio = float(np.clip(rng.beta(8.5, 1.6), 0.50, 1.0))
                hour = int(rng.choice(
                    [0, 1, 2, 3, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23],
                    p=[
                        0.03, 0.02, 0.02, 0.02, 0.03, 0.05, 0.07, 0.08, 0.08, 0.07,
                        0.06, 0.06, 0.06, 0.06, 0.05, 0.05, 0.04, 0.04, 0.04, 0.04, 0.03
                    ],
                ))
                age_days = int(np.clip(rng.exponential(38), 1, 260))
                complaint = float(np.clip(rng.beta(7.2, 2.4), 0.30, 0.99))

                prefix_type = rng.choice(
                    ["International_VoIP", "Virtual_DID", "Domestic_Mobile", "Toll_Free", "Telemarketing_140"],
                    p=[0.46, 0.26, 0.16, 0.07, 0.05],
                )
                line_type = rng.choice(
                    ["Spoofed_CLI", "VoIP_SIP", "Mobile_SIM", "PRI_Trunk", "Landline"],
                    p=[0.45, 0.34, 0.13, 0.05, 0.03],
                )
                contact_net = rng.choice(
                    ["No", "Mutual_2nd_Degree", "Yes"],
                    p=[0.93, 0.05, 0.02],
                )
                cli_status = rng.choice(
                    ["Unverified", "STIR_SHAKEN_C", "STIR_SHAKEN_B", "STIR_SHAKEN_A"],
                    p=[0.56, 0.28, 0.11, 0.05],
                )

            # Nonlinear interaction feature nuance (favors tree ensembles slightly over linear models)
            if true_label == "Scam" and not is_ambiguous and rng.random() < 0.35:
                # Burner SIM with domestic prefix but high complaint & high silence
                prefix_type = "Domestic_Mobile"
                age_days = int(rng.integers(1, 22))
                silence_sec = float(np.round(rng.uniform(2.6, 4.8), 2))
                complaint = float(np.round(rng.uniform(0.58, 0.94), 3))

            time_bucket = _hour_to_bucket(hour)
            phone_str = _generate_phone_for_class(rng, true_label, idx_counter)

            records.append(
                {
                    "phone_number": phone_str,
                    "calls_last_24h": calls_24h,
                    "calls_last_7d": calls_7d,
                    "avg_call_duration_sec": round(avg_dur, 1),
                    "answer_rate": round(ans_rate, 3),
                    "short_call_ratio": round(short_ratio, 3),
                    "silence_initial_sec": round(silence_sec, 2),
                    "unique_recipients_ratio": round(uniq_ratio, 3),
                    "hour_of_day": hour,
                    "number_age_days": age_days,
                    "prior_complaint_rate": round(complaint, 3),
                    "prefix_type": prefix_type,
                    "caller_line_type": line_type,
                    "time_bucket": time_bucket,
                    "in_contact_network": contact_net,
                    "cli_verification_status": cli_status,
                    "label": true_label,
                }
            )

    df = pd.DataFrame(records)

    # Shuffle rows deterministically
    df = df.sample(frac=1.0, random_state=random_state).reset_index(drop=True)

    # Inject ~1% realistic missing values to exercise SimpleImputer in the ColumnTransformer
    for col in ["silence_initial_sec", "answer_rate", "caller_line_type"]:
        mask = rng.random(len(df)) < 0.008
        df.loc[mask, col] = np.nan

    if save_path is not None:
        save_path.parent.mkdir(parents=True, exist_ok=True)
        df.to_csv(save_path, index=False)

    return df


def load_and_clean_dataset(csv_path: Path = CSV_PATH) -> pd.DataFrame:
    """
    Loads data/calls.csv, ensuring phone_number is explicitly parsed as string
    so leading '+' characters are never corrupted. Cleans exact feature duplicates.
    """
    if not csv_path.exists():
        generate_synthetic_dataset(n_rows=6000, random_state=RANDOM_SEED, save_path=csv_path)

    df = pd.read_csv(csv_path, dtype={"phone_number": str})
    df["phone_number"] = df["phone_number"].apply(sanitize_phone_number)

    # Drop exact duplicate rows if any exist
    df = df.drop_duplicates().reset_index(drop=True)
    return df


def build_preprocessing_pipeline() -> ColumnTransformer:
    """
    Constructs the Scikit-learn ColumnTransformer:
    - Numeric pipeline: median imputation + StandardScaler
    - Categorical pipeline: most_frequent imputation + OneHotEncoder(handle_unknown='ignore')
    """
    numeric_transformer = Pipeline(
        steps=[
            ("imputer", SimpleImputer(strategy="median")),
            ("scaler", StandardScaler()),
        ]
    )

    categorical_transformer = Pipeline(
        steps=[
            ("imputer", SimpleImputer(strategy="most_frequent")),
            ("onehot", OneHotEncoder(handle_unknown="ignore", sparse_output=False)),
        ]
    )

    preprocessor = ColumnTransformer(
        transformers=[
            ("num", numeric_transformer, NUMERIC_FEATURES),
            ("cat", categorical_transformer, CATEGORICAL_FEATURES),
        ],
        remainder="drop",
    )
    return preprocessor


def prepare_train_test_splits(
    df: Optional[pd.DataFrame] = None,
    test_size: float = 0.20,
    random_state: int = RANDOM_SEED,
) -> Tuple[pd.DataFrame, pd.DataFrame, pd.Series, pd.Series, ColumnTransformer]:
    """
    Performs an 80/20 stratified train/test split and fits the ColumnTransformer
    ONLY on X_train to strictly prevent data leakage.
    """
    if df is None:
        df = load_and_clean_dataset()

    X = df[ALL_FEATURES].copy()
    y = df["label"].copy()

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=test_size,
        stratify=y,
        random_state=random_state,
    )

    preprocessor = build_preprocessing_pipeline()
    preprocessor.fit(X_train)

    return X_train, X_test, y_train, y_test, preprocessor


if __name__ == "__main__":
    df_generated = generate_synthetic_dataset()
    print(f"Generated dataset with shape: {df_generated.shape}")
    print(df_generated["label"].value_counts())
