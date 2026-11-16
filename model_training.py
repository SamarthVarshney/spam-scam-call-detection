"""
Model Training & Evaluation Module
==================================
Splits synthetic dataset 80/20 (stratified), fits preprocessing pipeline ONLY on
the training split, trains 5 classifiers (Logistic Regression, Decision Tree,
Random Forest, Gradient Boosting, SVM), evaluates each on Accuracy, Precision,
Recall, Macro-F1, and ROC-AUC, selects the best model by Macro-F1, and persists
both the model and pipeline via joblib.

Authors: Silvia Noatia (2026279652), Fatima Iqbal (2026187337)
Mentor: Dharmendra Kumar | Sharda University (CSCR2600 PBL-1)
"""

from __future__ import annotations

import json
import time
import warnings
from pathlib import Path
from typing import Any, Dict, List

warnings.filterwarnings("ignore")

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import GradientBoostingClassifier, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.preprocessing import label_binarize
from sklearn.svm import SVC
from sklearn.tree import DecisionTreeClassifier

from data_preprocessing import (
    ALL_FEATURES,
    BASE_DIR,
    CLASSES,
    RANDOM_SEED,
    generate_synthetic_dataset,
    load_and_clean_dataset,
    prepare_train_test_splits,
)

MODELS_DIR = BASE_DIR / "models"
BEST_MODEL_PATH = MODELS_DIR / "best_model.pkl"
PREPROCESSOR_PATH = MODELS_DIR / "preprocessor.pkl"
ALL_MODELS_PATH = MODELS_DIR / "all_models.pkl"
METRICS_JSON_PATH = MODELS_DIR / "evaluation_metrics.json"


def get_candidate_models(random_state: int = RANDOM_SEED) -> Dict[str, Any]:
    """
    Returns the 5 candidate classifiers defined in the project specification.
    """
    return {
        "Random Forest": RandomForestClassifier(
            n_estimators=300,
            max_depth=16,
            min_samples_split=3,
            min_samples_leaf=1,
            max_features="sqrt",
            random_state=random_state,
            n_jobs=-1,
        ),
        "SVM": SVC(
            C=0.18,
            kernel="rbf",
            gamma="scale",
            probability=True,
            random_state=random_state,
        ),
        "Gradient Boosting": GradientBoostingClassifier(
            n_estimators=85,
            learning_rate=0.05,
            max_depth=3,
            subsample=0.80,
            random_state=random_state,
        ),
        "Logistic Regression": LogisticRegression(
            C=0.25,
            max_iter=1000,
            random_state=random_state,
        ),
        "Decision Tree": DecisionTreeClassifier(
            max_depth=7,
            min_samples_split=16,
            min_samples_leaf=8,
            random_state=random_state,
        ),
    }


def train_and_evaluate_all(force_regenerate_data: bool = False) -> Dict[str, Any]:
    """
    Executes the full training and evaluation workflow, saving artifacts to models/.
    """
    MODELS_DIR.mkdir(parents=True, exist_ok=True)

    if force_regenerate_data:
        generate_synthetic_dataset(n_rows=6000, random_state=RANDOM_SEED)

    df = load_and_clean_dataset()
    X_train, X_test, y_train, y_test, preprocessor = prepare_train_test_splits(df)

    X_train_transformed = preprocessor.transform(X_train)
    X_test_transformed = preprocessor.transform(X_test)

    feature_names_out = list(preprocessor.get_feature_names_out())

    y_test_bin = label_binarize(y_test, classes=CLASSES)

    candidate_models = get_candidate_models(RANDOM_SEED)
    results: List[Dict[str, Any]] = []
    trained_models: Dict[str, Any] = {}

    for name, clf in candidate_models.items():
        t0 = time.perf_counter()
        clf.fit(X_train_transformed, y_train)
        train_time_sec = round(time.perf_counter() - t0, 3)

        y_pred = clf.predict(X_test_transformed)
        y_proba = clf.predict_proba(X_test_transformed)

        # Ensure class order aligns with CLASSES
        cls_order = list(clf.classes_)
        col_indices = [cls_order.index(c) for c in CLASSES]
        y_proba_aligned = y_proba[:, col_indices]

        acc = float(accuracy_score(y_test, y_pred))
        prec_macro = float(precision_score(y_test, y_pred, average="macro", zero_division=0))
        rec_macro = float(recall_score(y_test, y_pred, average="macro", zero_division=0))
        f1_macro = float(f1_score(y_test, y_pred, average="macro", zero_division=0))
        f1_weighted = float(f1_score(y_test, y_pred, average="weighted", zero_division=0))
        roc_auc = float(
            roc_auc_score(y_test_bin, y_proba_aligned, average="macro", multi_class="ovr")
        )

        cm = confusion_matrix(y_test, y_pred, labels=CLASSES).tolist()

        # Per-class metrics
        per_class = {}
        for c in CLASSES:
            y_true_c = (y_test == c).astype(int)
            y_pred_c = (y_pred == c).astype(int)
            per_class[c] = {
                "precision": round(float(precision_score(y_true_c, y_pred_c, zero_division=0)), 4),
                "recall": round(float(recall_score(y_true_c, y_pred_c, zero_division=0)), 4),
                "f1": round(float(f1_score(y_true_c, y_pred_c, zero_division=0)), 4),
            }

        results.append(
            {
                "model_name": name,
                "accuracy": round(acc, 4),
                "precision_macro": round(prec_macro, 4),
                "recall_macro": round(rec_macro, 4),
                "f1_macro": round(f1_macro, 4),
                "f1_weighted": round(f1_weighted, 4),
                "roc_auc_macro": round(roc_auc, 4),
                "train_time_sec": train_time_sec,
                "confusion_matrix": cm,
                "per_class": per_class,
            }
        )
        trained_models[name] = clf

    # Sort by f1_macro descending, tie-breaking with accuracy and preferring Random Forest if tied
    results.sort(
        key=lambda r: (
            r["f1_macro"],
            r["accuracy"],
            1 if r["model_name"] == "Random Forest" else 0,
        ),
        reverse=True,
    )

    best_entry = results[0]
    best_model_name = best_entry["model_name"]
    best_model = trained_models[best_model_name]

    # Compute feature importances from Random Forest
    rf_model = trained_models["Random Forest"]
    raw_importances = rf_model.feature_importances_
    # Aggregate one-hot encoded categorical importances back to original feature names
    aggregated_importances: Dict[str, float] = {f: 0.0 for f in ALL_FEATURES}
    for feat_out, imp in zip(feature_names_out, raw_importances):
        clean_name = feat_out.split("__", 1)[-1]
        matched = False
        for orig_feat in ALL_FEATURES:
            if clean_name == orig_feat or clean_name.startswith(orig_feat + "_"):
                aggregated_importances[orig_feat] += float(imp)
                matched = True
                break
        if not matched:
            aggregated_importances[clean_name] = float(imp)

    sorted_importances = [
        {"feature": k, "importance": round(v, 4)}
        for k, v in sorted(aggregated_importances.items(), key=lambda x: x[1], reverse=True)
    ]

    # Save artifacts
    joblib.dump(best_model, BEST_MODEL_PATH)
    joblib.dump(preprocessor, PREPROCESSOR_PATH)
    joblib.dump(trained_models, ALL_MODELS_PATH)

    summary_payload = {
        "best_model_name": best_model_name,
        "best_accuracy": best_entry["accuracy"],
        "best_f1_macro": best_entry["f1_macro"],
        "best_roc_auc": best_entry["roc_auc_macro"],
        "dataset_rows": len(df),
        "train_rows": len(X_train),
        "test_rows": len(X_test),
        "class_distribution": df["label"].value_counts().to_dict(),
        "classes": CLASSES,
        "models": results,
        "feature_importances": sorted_importances,
    }

    with open(METRICS_JSON_PATH, "w", encoding="utf-8") as f:
        json.dump(summary_payload, f, indent=2)

    return summary_payload


def load_evaluation_metrics() -> Dict[str, Any]:
    if not METRICS_JSON_PATH.exists() or not BEST_MODEL_PATH.exists():
        return train_and_evaluate_all()
    with open(METRICS_JSON_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


if __name__ == "__main__":
    summary = train_and_evaluate_all()
    print(f"Best Model: {summary['best_model_name']}")
    for m in summary["models"]:
        print(
            f"  {m['model_name']:22s} | Acc: {m['accuracy']:.4f} | "
            f"F1 (macro): {m['f1_macro']:.4f} | ROC-AUC: {m['roc_auc_macro']:.4f}"
        )
