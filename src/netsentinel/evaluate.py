"""Model evaluation: SOC-appropriate metrics and diagnostic plots.

Accuracy alone is misleading on intrusion data because benign traffic
dominates. We report precision, recall, F1 and ROC-AUC, and persist a
confusion matrix, ROC curve, and feature-importance chart that can be
dropped straight into the README.
"""
from __future__ import annotations

from pathlib import Path

import matplotlib

matplotlib.use("Agg")  # headless backend for CI / servers
import matplotlib.pyplot as plt
import pandas as pd
from sklearn.metrics import (
    ConfusionMatrixDisplay,
    RocCurveDisplay,
    accuracy_score,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.pipeline import Pipeline


def compute_metrics(y_true, y_pred, y_proba) -> dict[str, float]:
    """Return the headline classification metrics as a dict."""
    return {
        "accuracy": accuracy_score(y_true, y_pred),
        "precision": precision_score(y_true, y_pred, zero_division=0),
        "recall": recall_score(y_true, y_pred, zero_division=0),
        "f1": f1_score(y_true, y_pred, zero_division=0),
        "roc_auc": roc_auc_score(y_true, y_proba),
    }


def save_confusion_matrix(y_true, y_pred, out_dir: Path) -> Path:
    """Render and save a confusion matrix; return its path."""
    fig, ax = plt.subplots(figsize=(5, 4))
    ConfusionMatrixDisplay.from_predictions(
        y_true, y_pred, display_labels=["Benign", "Attack"], ax=ax, cmap="Blues"
    )
    ax.set_title("Confusion Matrix")
    fig.tight_layout()
    path = out_dir / "confusion_matrix.png"
    fig.savefig(path, dpi=120)
    plt.close(fig)
    return path


def save_roc_curve(y_true, y_proba, out_dir: Path) -> Path:
    """Render and save the ROC curve; return its path."""
    fig, ax = plt.subplots(figsize=(5, 4))
    RocCurveDisplay.from_predictions(y_true, y_proba, ax=ax)
    ax.set_title("ROC Curve")
    fig.tight_layout()
    path = out_dir / "roc_curve.png"
    fig.savefig(path, dpi=120)
    plt.close(fig)
    return path


def save_feature_importances(
    pipeline: Pipeline, out_dir: Path, top_n: int = 15
) -> Path:
    """Plot the top feature importances from the fitted forest."""
    classifier = pipeline.named_steps["classifier"]
    feature_names = pipeline.named_steps["preprocess"].get_feature_names_out()
    importances = pd.Series(classifier.feature_importances_, index=feature_names)
    top = importances.sort_values(ascending=False).head(top_n)[::-1]

    fig, ax = plt.subplots(figsize=(7, 5))
    top.plot.barh(ax=ax, color="#2c7fb8")
    ax.set_title(f"Top {top_n} Feature Importances")
    ax.set_xlabel("Importance")
    fig.tight_layout()
    path = out_dir / "feature_importances.png"
    fig.savefig(path, dpi=120)
    plt.close(fig)
    return path
