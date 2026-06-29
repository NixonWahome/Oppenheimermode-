"""Train and evaluate the intrusion-detection model.

Usage:
    python -m netsentinel.train

Loads NSL-KDD, fits the preprocessing + Random Forest pipeline, evaluates it
on the held-out test split, writes diagnostic plots to ``artifacts/``, and
persists the fitted pipeline to ``artifacts/ids_model.joblib``.
"""
from __future__ import annotations

import argparse
import json

import joblib

from . import config, data, evaluate
from .model import build_pipeline


def run(n_estimators: int = 200) -> dict[str, float]:
    """Train the model end to end and return test metrics."""
    config.ensure_dirs()

    print("Loading NSL-KDD ...")
    train_df = data.load_nsl_kdd(config.TRAIN_FILE)
    test_df = data.load_nsl_kdd(config.TEST_FILE)

    X_train, y_train = data.split_features_labels(train_df)
    X_test, y_test = data.split_features_labels(test_df)
    print(f"  train: {len(X_train):,} flows ({y_train.mean():.1%} attacks)")
    print(f"  test:  {len(X_test):,} flows ({y_test.mean():.1%} attacks)")

    pipeline = build_pipeline(
        numeric_features=data.numeric_features(X_train),
        categorical_features=data.CATEGORICAL_FEATURES,
        n_estimators=n_estimators,
    )

    print("Training Random Forest ...")
    pipeline.fit(X_train, y_train)

    y_pred = pipeline.predict(X_test)
    y_proba = pipeline.predict_proba(X_test)[:, 1]
    metrics = evaluate.compute_metrics(y_test, y_pred, y_proba)

    print("\nTest-set performance:")
    for name, value in metrics.items():
        print(f"  {name:>10}: {value:.4f}")

    evaluate.save_confusion_matrix(y_test, y_pred, config.ARTIFACTS_DIR)
    evaluate.save_roc_curve(y_test, y_proba, config.ARTIFACTS_DIR)
    evaluate.save_feature_importances(pipeline, config.ARTIFACTS_DIR)

    joblib.dump(pipeline, config.MODEL_PATH)
    (config.ARTIFACTS_DIR / "metrics.json").write_text(json.dumps(metrics, indent=2))
    print(f"\nModel saved to {config.MODEL_PATH}")
    print(f"Plots and metrics saved to {config.ARTIFACTS_DIR}")
    return metrics


def main() -> None:
    parser = argparse.ArgumentParser(description="Train the NetSentinel IDS model.")
    parser.add_argument(
        "--n-estimators", type=int, default=200, help="Number of trees (default: 200)."
    )
    args = parser.parse_args()
    run(n_estimators=args.n_estimators)


if __name__ == "__main__":
    main()
