"""Model definition: a preprocessing + Random Forest pipeline.

A single scikit-learn :class:`~sklearn.pipeline.Pipeline` bundles preprocessing
with the classifier so the exact same transformations are applied at train and
inference time — eliminating train/serve skew. A Random Forest is used because
network-flow data is tabular, the model trains in seconds, and it exposes
feature importances that are valuable for SOC analysts who need to explain
*why* a flow was flagged.
"""
from __future__ import annotations

from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler

from .config import RANDOM_SEED


def build_pipeline(
    numeric_features: list[str],
    categorical_features: list[str],
    n_estimators: int = 200,
) -> Pipeline:
    """Construct an unfitted preprocessing + classifier pipeline.

    Args:
        numeric_features: Names of numeric feature columns (standardized).
        categorical_features: Names of categorical columns (one-hot encoded).
        n_estimators: Number of trees in the forest.

    Returns:
        An unfitted :class:`~sklearn.pipeline.Pipeline`.
    """
    preprocessor = ColumnTransformer(
        transformers=[
            ("num", StandardScaler(), numeric_features),
            (
                "cat",
                OneHotEncoder(handle_unknown="ignore"),
                categorical_features,
            ),
        ]
    )

    classifier = RandomForestClassifier(
        n_estimators=n_estimators,
        class_weight="balanced",  # benign traffic vastly outnumbers attacks
        random_state=RANDOM_SEED,
        n_jobs=-1,
    )

    return Pipeline(steps=[("preprocess", preprocessor), ("classifier", classifier)])
