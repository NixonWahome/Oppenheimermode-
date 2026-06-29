"""Tests for the model pipeline and metrics — train on a tiny synthetic set."""
from __future__ import annotations

import numpy as np
import pandas as pd

from netsentinel import data, evaluate
from netsentinel.model import build_pipeline


def _synthetic_dataset(n: int = 200) -> tuple[pd.DataFrame, pd.Series]:
    """Separable synthetic flows: attacks have larger src_bytes."""
    rng = np.random.default_rng(0)
    rows, labels = [], []
    for _ in range(n):
        attack = rng.random() < 0.5
        row = {c: 0 for c in data.COLUMNS}
        row["protocol_type"] = "tcp"
        row["service"] = "private" if attack else "http"
        row["flag"] = "S0" if attack else "SF"
        row["src_bytes"] = rng.normal(5000 if attack else 100, 10)
        row["count"] = rng.normal(400 if attack else 5, 1)
        row["label"] = "neptune" if attack else "normal"
        row["difficulty"] = 20
        rows.append(row)
        labels.append(int(attack))
    df = pd.DataFrame(rows, columns=data.COLUMNS)
    X, y = data.split_features_labels(df)
    return X, y


def test_pipeline_fits_and_predicts():
    X, y = _synthetic_dataset()
    pipe = build_pipeline(data.numeric_features(X), data.CATEGORICAL_FEATURES, n_estimators=20)
    pipe.fit(X, y)
    proba = pipe.predict_proba(X)[:, 1]
    assert proba.shape == (len(X),)
    assert ((proba >= 0) & (proba <= 1)).all()


def test_metrics_on_separable_data_are_high():
    X, y = _synthetic_dataset()
    pipe = build_pipeline(data.numeric_features(X), data.CATEGORICAL_FEATURES, n_estimators=20)
    pipe.fit(X, y)
    y_pred = pipe.predict(X)
    y_proba = pipe.predict_proba(X)[:, 1]
    metrics = evaluate.compute_metrics(y, y_pred, y_proba)
    assert set(metrics) == {"accuracy", "precision", "recall", "f1", "roc_auc"}
    assert metrics["f1"] > 0.9  # clearly separable -> strong fit
