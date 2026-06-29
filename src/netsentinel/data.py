"""Loading and preparing the NSL-KDD intrusion-detection dataset.

NSL-KDD is the de-facto benchmark for IDS research. Each row is a connection
record with 41 features and a label that is either ``normal`` or the name of
an attack (e.g. ``neptune``, ``portsweep``). We collapse the label into a
binary target: 0 = benign, 1 = attack.

Reference: https://www.unb.ca/cic/datasets/nsl.html
"""
from __future__ import annotations

from pathlib import Path

import pandas as pd

# The 41 NSL-KDD features in order, plus the label and a "difficulty" column
# that ships with the dataset and is dropped before training.
COLUMNS: list[str] = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes",
    "land", "wrong_fragment", "urgent", "hot", "num_failed_logins",
    "logged_in", "num_compromised", "root_shell", "su_attempted", "num_root",
    "num_file_creations", "num_shells", "num_access_files",
    "num_outbound_cmds", "is_host_login", "is_guest_login", "count",
    "srv_count", "serror_rate", "srv_serror_rate", "rerror_rate",
    "srv_rerror_rate", "same_srv_rate", "diff_srv_rate", "srv_diff_host_rate",
    "dst_host_count", "dst_host_srv_count", "dst_host_same_srv_rate",
    "dst_host_diff_srv_rate", "dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate", "dst_host_serror_rate",
    "dst_host_srv_serror_rate", "dst_host_rerror_rate",
    "dst_host_srv_rerror_rate", "label", "difficulty",
]

# Features the model treats as categorical (everything else is numeric).
CATEGORICAL_FEATURES: list[str] = ["protocol_type", "service", "flag"]

# Columns that are not predictive features.
NON_FEATURE_COLUMNS: list[str] = ["label", "difficulty"]


def load_nsl_kdd(path: str | Path) -> pd.DataFrame:
    """Read an NSL-KDD ``.txt`` file into a labeled DataFrame.

    Args:
        path: Path to ``KDDTrain+.txt`` or ``KDDTest+.txt``.

    Returns:
        DataFrame with named columns.

    Raises:
        FileNotFoundError: If the dataset file is missing (with a hint to run
            the download script).
    """
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(
            f"Dataset not found at {path}. Run `python scripts/download_data.py` first."
        )
    return pd.read_csv(path, names=COLUMNS, header=None)


def split_features_labels(df: pd.DataFrame) -> tuple[pd.DataFrame, pd.Series]:
    """Separate the feature matrix from a binary attack/benign target.

    Args:
        df: A DataFrame produced by :func:`load_nsl_kdd`.

    Returns:
        ``(X, y)`` where ``y`` is 1 for any attack and 0 for ``normal``.
    """
    y = (df["label"] != "normal").astype(int)
    X = df.drop(columns=NON_FEATURE_COLUMNS)
    return X, y


def numeric_features(X: pd.DataFrame) -> list[str]:
    """Return the numeric (non-categorical) feature column names."""
    return [c for c in X.columns if c not in CATEGORICAL_FEATURES]
