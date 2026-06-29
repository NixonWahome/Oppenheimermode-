"""Central configuration: paths and tunable constants.

Values can be overridden with environment variables so the same code runs
locally, in CI, and in Docker without edits.
"""
from __future__ import annotations

import os
from pathlib import Path

# Project layout -------------------------------------------------------------
PROJECT_ROOT = Path(__file__).resolve().parents[2]
DATA_DIR = Path(os.getenv("NETSENTINEL_DATA_DIR", PROJECT_ROOT / "data"))
ARTIFACTS_DIR = Path(os.getenv("NETSENTINEL_ARTIFACTS_DIR", PROJECT_ROOT / "artifacts"))

# Trained pipeline (preprocessing + classifier) is persisted here.
MODEL_PATH = ARTIFACTS_DIR / "ids_model.joblib"

# NSL-KDD dataset files (downloaded by scripts/download_data.py).
TRAIN_FILE = DATA_DIR / "KDDTrain+.txt"
TEST_FILE = DATA_DIR / "KDDTest+.txt"

# Detection -----------------------------------------------------------------
# Probability above which a flow is treated as an active threat.
THREAT_THRESHOLD = float(os.getenv("NETSENTINEL_THREAT_THRESHOLD", "0.90"))

# SIEM ----------------------------------------------------------------------
ELASTICSEARCH_URL = os.getenv("NETSENTINEL_ES_URL", "http://localhost:9200")
ELASTICSEARCH_INDEX = os.getenv("NETSENTINEL_ES_INDEX", "netsentinel-threats")

# Reproducibility -----------------------------------------------------------
RANDOM_SEED = 42


def ensure_dirs() -> None:
    """Create data/ and artifacts/ directories if they don't exist."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)
