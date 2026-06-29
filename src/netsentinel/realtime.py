"""Detection runtime: score flow records and trigger automated response.

The detector consumes connection/flow records (the same schema the model was
trained on) and acts on anything above the configured threat threshold.

A "source" of flows can be either:

* a CSV/NSL-KDD file replayed record by record (``--source replay``), which
  runs anywhere with no special privileges and is used for the demo and CI; or
* live capture via :mod:`netsentinel.packet_analyzer` (requires admin/root and
  raw-socket access).

Usage:
    python -m netsentinel.detector --source replay --limit 50
"""
from __future__ import annotations

import argparse
import logging

import joblib

from . import config, data
from .firewall_manager import FirewallManager

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("netsentinel")


class ThreatDetector:
    """Loads the trained pipeline and scores flow records."""

    def __init__(self, model_path=None, threshold: float | None = None) -> None:
        model_path = model_path or config.MODEL_PATH
        if not model_path.exists():
            raise FileNotFoundError(
                f"No trained model at {model_path}. Run `python -m netsentinel.train` first."
            )
        self.pipeline = joblib.load(model_path)
        self.threshold = threshold if threshold is not None else config.THREAT_THRESHOLD

    def score(self, flows) -> list[float]:
        """Return attack probabilities for a batch of flow records (DataFrame)."""
        return self.pipeline.predict_proba(flows)[:, 1].tolist()


def replay(limit: int = 50, dry_run: bool = True, enable_siem: bool = False) -> None:
    """Replay flows from the NSL-KDD test set through the detector + firewall."""
    detector = ThreatDetector()
    firewall = FirewallManager(dry_run=dry_run, enable_siem=enable_siem)

    df = data.load_nsl_kdd(config.TEST_FILE).head(limit)
    X, _ = data.split_features_labels(df)
    scores = detector.score(X)

    threats = 0
    for i, score in enumerate(scores):
        if score >= detector.threshold:
            threats += 1
            # NSL-KDD has no source IP; synthesize a stable placeholder for demo.
            ip = f"10.0.0.{i % 254 + 1}"
            firewall.block_ip(ip, reason=f"threat score {score:.2f}")

    logger.info(
        "Scored %d flows, flagged %d as threats (threshold %.2f)",
        len(scores), threats, detector.threshold,
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the NetSentinel detector.")
    parser.add_argument("--source", choices=["replay"], default="replay")
    parser.add_argument("--limit", type=int, default=50, help="Flows to replay.")
    parser.add_argument(
        "--enforce",
        action="store_true",
        help="Actually modify the host firewall (default is dry-run).",
    )
    parser.add_argument("--siem", action="store_true", help="Log events to Elasticsearch.")
    args = parser.parse_args()

    if args.source == "replay":
        replay(limit=args.limit, dry_run=not args.enforce, enable_siem=args.siem)


if __name__ == "__main__":
    main()
