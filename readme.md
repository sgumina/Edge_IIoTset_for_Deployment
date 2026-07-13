# Edge-IIoT SmartNIC Deployment Strategy

**Version:** 1.0 (Draft)

**Author:** Sharon Gumina

---

# 1. Purpose

This document defines the engineering strategy for deploying machine learning
models for Edge-IIoT intrusion detection from research prototypes into an
efficient SmartNIC-compatible runtime.

Rather than treating feature engineering, model training, and deployment as
independent activities, this project defines a single deployment-oriented
feature contract that remains fixed throughout the entire machine learning
pipeline.

The objective is to create a reproducible workflow where the same feature
definitions are used during:

- PCAP processing
- Dataset generation
- Model training
- Model evaluation
- ONNX export
- SmartNIC inference

This eliminates inconsistencies between offline experimentation and production
deployment while simplifying long-term maintenance.

---

# 2. Design Philosophy

Therefore this project adopts a deployment-first philosophy.

Each feature must satisfy multiple requirements:

- Predictive usefulness
- Low computational cost
- Runtime stability
- Ease of implementation
- Reproducibility
- Compatibility with ONNX inference
- Compatibility with C implementations

---

# 3. System Architecture

The complete workflow is illustrated below.

                    +----------------+
                    |     PCAP       |
                    +----------------+
                            |
                            |
                    Packet Processing
                            |
                            |
                    +----------------+
                    | Window Builder |
                    +----------------+
                            |
                            |
                    Feature Extraction
                            |
                            |
              +-----------------------------+
              | Edge-IIoT Feature Contract  |
              +-----------------------------+
                            |
           -----------------------------------------
           |                  |                    |
           |                  |                    |
      Training           Validation           Statistics
           |                  |                    |
           -----------------------------------------
                            |
                      Trained MLP
                            |
                     skl2onnx Export
                            |
                     ONNX Model File
                            |
                  SmartNIC C Inference
                            |
                    Detection Decision

The feature contract is intentionally placed at the center of the architecture.

Every component consumes the same feature definitions.

---

# 4. The Feature Contract

The feature contract is the most important component of the system.

It defines:

- feature names
- ordering
- data types
- computation methods
- expected ranges
- deployment cost

Every model must consume features in exactly this order.

Changing feature order invalidates all trained models.

---

## Version 1.0 Proposed Features

| Feature | Purpose | Runtime Cost | Status |
|----------|----------|--------------|--------|
| total_bytes | Total bytes observed in window | Low | Required |
| avg_pkt_size | Mean packet size | Low | Required |
| duration | Window duration | Low | Required |
| total_pkts | Number of packets | Low | Required |
| mean_iat | Mean inter-arrival time | Medium | Required |
| pkts_per_sec | Packet rate | Low | Required |
| ack_count | TCP ACK counter | Low | Required |
| orig_bytes | Source bytes | Low | Required |
| burstiness_cv | Burstiness coefficient of variation | Medium | Candidate |
| max_pkt_size | Largest packet observed | Low | Candidate |

---

# 5. Why These Features?

Feature selection is based on multiple criteria rather than importance scores
alone.

Each feature is evaluated according to

- Random Forest importance
- MLP importance
- Runtime computational cost
- Existing implementation availability
- Deployment complexity
- Long-term maintainability

The goal is to maximize deployment efficiency rather than maximizing benchmark
accuracy alone.

---

# 6. Feature Stability

Once Version 1.0 of the feature contract is finalized:

No feature additions are permitted.

No feature deletions are permitted.

No feature reordering is permitted.

Any modification requires a new contract version.

Example

Feature Contract v1.0

↓

All trained models

↓

ONNX exports

↓

SmartNIC runtime

Future work becomes

Feature Contract v2.0

instead of modifying v1.0.

---

# 7. Window Sizes

This project evaluates multiple temporal aggregation windows.

Current planned windows:

- 4 packets
- 8 packets
- 16 packets
- 32 packets
- 64 packets

Importantly:

The feature vector never changes.

Only the aggregation window changes.

This allows a direct comparison between temporal resolutions while keeping the
learning problem identical.

---

# 8. Model Training Strategy

Each window size receives an independently trained MLP.

Example

Window 4

↓

Feature Contract v1.0

↓

MLP

↓

edgeiiot_window4.onnx

Window 8

↓

Feature Contract v1.0

↓

MLP

↓

edgeiiot_window8.onnx

...

Window 64

↓

Feature Contract v1.0

↓

MLP

↓

edgeiiot_window64.onnx

This produces a family of comparable models.

---

# 9. Repository Organization

Recommended repository structure

```
edge-iiot/

│

├── data/

├── datasets/

├── docs/

│      EDGE_IIOT_DEPLOYMENT_STRATEGY.md

│      FEATURE_CONTRACT.md

│      MODEL_CARD_TEMPLATE.md

│

├── edgeiiot/

│      feature_contract.py

│      features.py

│      windows.py

│      preprocessing.py

│      train.py

│      evaluate.py

│      export_onnx.py

│

├── models/

│      window4/

│      window8/

│      window16/

│      window32/

│      window64/

│

├── onnx/

├── runtime/

└── tests/
```

---

# 10. Deployment Strategy

Deployment consists of four stages.

Stage 1

Extract deployment features from packet windows.

Stage 2

Normalize features using training parameters.

Stage 3

Execute ONNX inference.

Stage 4

Return predicted attack class.

The deployment runtime should never compute features not included in the
feature contract.

---

# 11. Future SmartNIC Integration

The long-term deployment target is a SmartNIC-compatible runtime.

The runtime is expected to perform:

Packet Reception

↓

Window Aggregation

↓

Feature Extraction

↓

Feature Normalization

↓

MLP Inference

↓

Detection Output

Because every feature has already been selected with deployment cost in mind,
the SmartNIC implementation can remain lightweight.

---

# 12. Research Contributions

The proposed framework contributes more than a trained classifier.

It introduces a deployment-oriented methodology for Edge-IIoT intrusion
detection by:

- defining a stable deployment feature contract;
- integrating feature engineering with deployment constraints;
- evaluating multiple temporal aggregation windows using a fixed feature space;
- exporting interoperable ONNX models; and
- enabling SmartNIC-compatible inference using a common runtime architecture.

This approach bridges the gap between machine learning experimentation and
real-world deployment by treating feature definition as a versioned interface
rather than a temporary artifact of model development.

---

# 13. Development Roadmap

Phase 1

✔ Finalize Feature Contract v1.0

Phase 2

✔ Implement feature extraction

Phase 3

✔ Train MLPs for each window size

Phase 4

✔ Evaluate performance

Phase 5

✔ Export ONNX models

Phase 6

✔ Integrate with SmartNIC runtime

Phase 7

✔ Performance benchmarking

Phase 8

✔ Evaluation

---

# 14. Guiding Principle

The central design principle of this project is:

> **Models may change. Window sizes may change. Hyperparameters may change. Deployment targets may change. The Feature Contract does not.**

The feature contract serves as the stable interface between research and deployment, ensuring reproducibility, maintainability, and interoperability across the entire Edge-IIoT machine learning pipeline.
