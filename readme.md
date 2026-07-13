# Defense-Oriented Machine Learning for Edge-IIoT Intrusion Detection

> **A deployment-oriented framework for developing, evaluating, and operationalizing machine learning-based intrusion detection for Edge-IIoT environments.**

---

## Overview

The objective of this project is to develop a reproducible, deployment-oriented workflow that transforms raw network traffic into portable defensive intelligence capable of executing efficiently in operational environments.

This repository documents the complete research workflow from packet capture through SmartNIC-compatible deployment.

---

## Research Objectives

The project investigates several related research questions:

- How should defensive observations be extracted from network traffic to support operational intrusion detection?
- How do packet aggregation windows influence intrusion detection performance?
- How can Multi-Layer Perceptron (MLP) models be optimized for deployment in constrained Edge-IIoT environments?
- How can ONNX provide a portable representation of trained machine learning models?
- How can SmartNIC-compatible inference support operational cyber defense?

Rather than optimizing solely for classification accuracy, this work emphasizes reproducibility, deployment readiness, and operational fidelity.

---

## Technical Approach

The proposed workflow consists of six major stages.

```
               PCAP Files
                    │
                    ▼
          Packet Processing
                    │
                    ▼
         Window Aggregation
                    │
                    ▼
 Defensive Observation Extraction
                    │
                    ▼
         Dataset Generation
                    │
                    ▼
           MLP Training
                    │
                    ▼
          Model Evaluation
                    │
                    ▼
            skl2onnx Export
                    │
                    ▼
              ONNX Model
                    │
                    ▼
      SmartNIC-Compatible Runtime
                    │
                    ▼
      Intrusion Detection Decision
```

Each stage is designed to preserve the defensive observations used during experimentation while supporting efficient operational deployment.

---

## Defensive Observations

Intrusion detection begins with observable characteristics of network behavior rather than with machine learning itself.

The project evaluates deployment-oriented defensive observations such as:

| Observation | Defensive Purpose |
|------------|-------------------|
| Total Bytes | Communication volume |
| Packet Count | Traffic intensity |
| Average Packet Size | Payload characteristics |
| Duration | Session persistence |
| Mean Inter-arrival Time | Timing behavior |
| Packet Rate | Burst activity |
| TCP ACK Count | Transport protocol behavior |
| Source Bytes | Endpoint communication behavior |
| Burstiness | Traffic volatility |
| Maximum Packet Size | Communication characteristics |

These observations represent the initial candidate observation set.

As the research progresses, observations may be refined based on:

- detection effectiveness
- computational cost
- deployment feasibility
- operational reproducibility

A formal **Defensive Observation Specification** will document the current version of the observation set.

---

## Packet Window Evaluation

The project evaluates multiple packet aggregation windows while maintaining a consistent observation methodology.

Current planned window sizes include:

- 4 packets
- 8 packets
- 16 packets
- 32 packets
- 64 packets

Maintaining comparable observations across window sizes allows the effect of temporal aggregation to be evaluated independently of observation engineering.

---

## Why Multi-Layer Perceptrons?

MLPs were selected as the initial deployment model because they provide an effective balance between:

- detection capability
- computational efficiency
- memory requirements
- deterministic inference
- compatibility with ONNX Runtime

Although future work may investigate additional models, the initial implementation focuses on MLPs to establish a reproducible deployment pipeline.

---

## ONNX-Based Deployment

Rather than coupling machine learning models directly to Python implementations, trained models are exported using the Open Neural Network Exchange (ONNX) format.

The deployment workflow is therefore:

```
Python

    │

Scapy

    │

Observation Extraction

    │

scikit-learn MLP

    │

skl2onnx

    │

ONNX Model

    │

ONNX Runtime

    │

C Runtime

    │

SmartNIC Deployment
```

Separating model development from model execution provides a portable deployment strategy while enabling future hardware-specific optimizations.

---

## Repository Organization

```
Edge-IIoT-Defense/

│

├── README.md

├── docs/

├── data/

├── models/

├── notebooks/

├── runtime/

├── scripts/

├── src/

└── tests/
```

### Repository Structure

| Directory | Purpose |
|-----------|---------|
| docs | Research methodology, architecture, and technical documentation |
| data | Dataset organization and preprocessing outputs |
| src | Core Python implementation |
| scripts | Processing and training entry points |
| models | Trained models, ONNX exports, and evaluation artifacts |
| runtime | C runtime, ONNX Runtime integration, and SmartNIC implementation |
| notebooks | Exploratory analysis |
| tests | Unit and integration testing |

---

## Documentation

Project documentation will evolve alongside the implementation.

Planned documentation includes:

- Defense-Oriented Strategy
- System Architecture
- Defensive Observation Specification
- Experimental Methodology
- Dataset Preparation
- Model Training
- ONNX Deployment
- SmartNIC Runtime

---

## Technology Stack

### Machine Learning

- Python
- scikit-learn
- NumPy
- Pandas

### Network Processing

- Scapy
- PCAP datasets

### Deployment

- ONNX
- skl2onnx
- ONNX Runtime

### Runtime

- C/C++
- SmartNIC-compatible inference

---

## Current Development Roadmap

### Phase 1 — Research Framework

- Repository organization
- System architecture
- Defensive observation design
- Experimental methodology

### Phase 2 — Data Processing

- PCAP processing
- Observation extraction
- Dataset generation
- Data validation

### Phase 3 — Model Development

- Train MLP models
- Evaluate packet window strategies
- Hyperparameter optimization

### Phase 4 — Deployment

- Export ONNX models
- Validate ONNX inference
- Runtime integration

### Phase 5 — Operational Evaluation

- SmartNIC-compatible deployment
- Runtime benchmarking
- Detection performance evaluation

---

## Long-Term Vision

The long-term goal of this research is to establish a reproducible methodology for transitioning machine learning-based intrusion detection from laboratory experimentation to operational cyber defense.

The framework seeks to preserve defensive observations throughout the complete machine learning lifecycle while supporting portable model deployment and efficient runtime execution in Edge-IIoT environments.

---

## Project Status

**Current Status:** Research framework and architecture development.

Upcoming milestones include:

- Finalize the Defensive Observation Specification
- Process Edge-IIoT PCAP datasets
- Train baseline MLP models
- Export ONNX models
- Integrate with the SmartNIC-compatible runtime

---

## Citation

Citation information will be added upon publication.

---

## License

License information will be added prior to public release.
