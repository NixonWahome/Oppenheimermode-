# NetSentinel — AI Network Intrusion Detection & Automated Response

[![CI](https://github.com/NixonWahome/netsentinel/actions/workflows/ci.yml/badge.svg)](../../actions)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

A SOC-oriented intrusion detection system that learns to distinguish malicious
network flows from benign traffic, then **automatically responds** to threats by
blocking source IPs and logging events to a SIEM. Built on the **NSL-KDD**
benchmark dataset with a reproducible, tested ML pipeline.

> **Why this exists:** demonstrate an end-to-end security ML workflow — labeled
> data → preprocessing → model training & honest evaluation → automated
> detection & response → SIEM logging — the same loop a real SOC detection
> engineer builds and operates.

---

## Architecture

```
                 ┌──────────────┐     ┌──────────────────┐     ┌───────────────┐
 NSL-KDD flows ─▶│ Preprocessing │ ─▶ │  Random Forest    │ ─▶ │  Threat score  │
 (train/test)    │ scale+one-hot │     │   classifier      │     │   (0.0–1.0)   │
                 └──────────────┘     └──────────────────┘     └───────┬───────┘
                                                                        │ score ≥ threshold
                                          ┌─────────────────────────────┴───────┐
                                          ▼                                       ▼
                                  ┌───────────────┐                     ┌──────────────────┐
                                  │ FirewallManager│  block src IP       │  SIEM (Elastic)  │
                                  │ iptables/netsh │ ───────────────────▶│  threat events   │
                                  └───────────────┘                     └──────────────────┘
```

Preprocessing and the classifier are bundled in a single scikit-learn
`Pipeline`, so the exact transformations used in training are reused at
inference time — no train/serve skew.

## Results

Trained on `KDDTrain+` and evaluated on the held-out `KDDTest+` split.
Metrics and plots are regenerated on every training run into `artifacts/`.

| Metric | Score |
|--------|-------|
| Precision | _populated after training_ |
| Recall | _populated after training_ |
| F1 | _populated after training_ |
| ROC-AUC | _populated after training_ |

<p>
  <img src="artifacts/confusion_matrix.png" width="320">
  <img src="artifacts/roc_curve.png" width="320">
  <img src="artifacts/feature_importances.png" width="320">
</p>

> Accuracy is intentionally **not** the headline metric: benign traffic
> dominates intrusion datasets, so precision/recall/F1 and ROC-AUC tell the
> real story. The class imbalance is handled with `class_weight="balanced"`.

## Quickstart

```bash
# 1. Install
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt

# 2. Get the dataset (NSL-KDD, ~6 MB)
python scripts/download_data.py

# 3. Train + evaluate (writes model and plots to artifacts/)
python -m netsentinel.train

# 4. Run detection on replayed flows (dry-run: nothing touches your firewall)
python -m netsentinel.realtime --source replay --limit 50
```

To actually enforce blocks and log to Elasticsearch:

```bash
python -m netsentinel.realtime --source replay --enforce --siem
```

### Docker

```bash
docker build -t netsentinel .
docker run --rm netsentinel
```

## How it works

| Module | Responsibility |
|--------|----------------|
| `data.py` | Load NSL-KDD, binarize labels (benign vs. attack), split features |
| `model.py` | Preprocessing + Random Forest pipeline |
| `train.py` | Fit, evaluate, persist model + plots + `metrics.json` |
| `evaluate.py` | Precision/recall/F1/ROC-AUC, confusion matrix, ROC, feature importances |
| `realtime.py` | Score flows and drive automated response |
| `firewall_manager.py` | Cross-platform IP blocking (dry-run by default) + SIEM logging |
| `packet_analyzer.py` | Optional live capture via scapy |

## Testing & CI

```bash
pip install -r requirements-dev.txt
ruff check src tests   # lint
pytest -q              # unit tests (synthetic data, no network needed)
```

GitHub Actions runs lint + tests on every push and pull request.

## Safety & design notes

- **Dry-run by default.** The firewall never modifies the host unless you pass
  `--enforce`. A tool that takes automated action should fail safe.
- **Reproducible.** Fixed random seed; data fetched by script, never committed.
- **Honest evaluation.** Reported on a held-out split with imbalance-aware
  metrics.

## Limitations & roadmap

- The model is trained on NSL-KDD's **flow-level** features. Reconstructing all
  41 features from live packet capture requires flow aggregation that is out of
  scope here, so the live demo replays flow records. **Next step:** a flow-feature
  extractor (e.g. CICFlowMeter-style) to close the gap to true live detection.
- Add gradient-boosted trees (XGBoost/LightGBM) as a comparison baseline.
- Train on a more modern dataset (CIC-IDS2017) with contemporary attack types.
- Stream events to a Grafana/Kibana dashboard.

## License

MIT
