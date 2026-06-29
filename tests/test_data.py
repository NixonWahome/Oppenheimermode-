"""Tests for the data-loading and label logic."""
from __future__ import annotations

import pandas as pd

from netsentinel import data


def _sample_df() -> pd.DataFrame:
    """Two synthetic NSL-KDD rows: one benign, one attack."""
    benign = [0, "tcp", "http", "SF"] + [0] * 37 + ["normal", 20]
    attack = [0, "tcp", "private", "S0"] + [1] * 37 + ["neptune", 18]
    return pd.DataFrame([benign, attack], columns=data.COLUMNS)


def test_columns_count():
    # 41 features + label + difficulty
    assert len(data.COLUMNS) == 43


def test_split_features_labels_binarizes_target():
    df = _sample_df()
    X, y = data.split_features_labels(df)
    assert list(y) == [0, 1]  # normal -> 0, neptune -> 1
    assert "label" not in X.columns and "difficulty" not in X.columns


def test_numeric_features_excludes_categoricals():
    df = _sample_df()
    X, _ = data.split_features_labels(df)
    num = data.numeric_features(X)
    assert all(c not in num for c in data.CATEGORICAL_FEATURES)
