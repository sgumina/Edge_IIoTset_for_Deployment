# Defensive Observation Design Rationale

**Version:** 0.1 (Draft)

---

# 1. Purpose

The objective of this document is to explain the rationale behind the selection of defensive observations used throughout the Edge-IIoT intrusion detection framework.

Unlike traditional feature selection approaches that prioritize statistical importance alone, this research adopts a deployment-oriented methodology in which each observation is evaluated according to both its contribution to cyber defense and its suitability for operational deployment.

This document records the reasoning behind each observation and serves as the basis for future revisions to the Defensive Observation Specification.

---

# 2. Design Philosophy

The primary objective of the observation layer is to preserve meaningful defensive telemetry from network traffic while minimizing computational overhead.

Each observation should satisfy as many of the following criteria as possible:

- Provide useful information for distinguishing benign and malicious traffic.
- Be computationally inexpensive to calculate.
- Be reproducible during operational deployment.
- Be compatible with packet-window aggregation.
- Be independent of any specific machine learning model.
- Support efficient implementation within a SmartNIC-compatible runtime.
- Remain interpretable from a cyber defense perspective.

Consequently, observation selection is guided by operational utility rather than machine learning performance alone.

---

# 3. Relationship to Previous Work

This research builds upon the deployment-oriented packet processing framework developed by Sergio Maffeis and colleagues.

Their SmartNIC implementation demonstrated that lightweight packet statistics can support efficient machine learning inference within constrained execution environments.

Rather than replacing that approach, this work extends it by introducing additional defensive observations that improve operational interpretability while maintaining low computational overhead.

Several observations proposed in this project are directly compatible with the existing runtime, while others require only minor extensions to the packet aggregation logic.

---

# 4. Observation Evaluation Criteria

Candidate observations are evaluated according to multiple dimensions.

| Criterion | Description |
|------------|-------------|
| Defensive Value | Ability to characterize malicious network behavior |
| Runtime Cost | Computational effort required during packet processing |
| Operational Reproducibility | Can the observation be reproduced during deployment? |
| Existing Runtime Support | Availability within the current SmartNIC implementation |
| Interpretability | Ease of explaining the observation from a cyber defense perspective |
| Deployment Complexity | Additional implementation effort required |

No single criterion determines inclusion.

Instead, observations are selected using a balanced engineering and cyber defense perspective.

---

# 5. Candidate Defensive Observations

| Observation | Defensive Value | Runtime Cost | Sergio Runtime | Status |
|-------------|-----------------|--------------|----------------|--------|
| Total Bytes | Communication volume | Low | ✓ | Candidate |
| Average Packet Size | Payload characteristics | Low | ✓ | Candidate |
| Maximum Packet Size | Communication characteristics | Low | ✓ | Candidate |
| Duration | Session persistence | Low | Derived | Candidate |
| Total Packets | Traffic intensity | Low | Derived | Candidate |
| Mean Inter-arrival Time | Timing behaviour | Low | ✓ | Candidate |
| Packet Rate | Burst activity | Low | Derived | Candidate |
| ACK Count | TCP protocol behaviour | Low | Partial | Candidate |
| Burstiness (Coefficient of Variation) | Traffic volatility | Medium | No | Candidate |
| Originator Bytes | Endpoint communication behaviour | Medium | No | Candidate |

This table represents the initial observation set and is expected to evolve during experimental evaluation.

---

# 6. Observation Discussion

## Total Bytes

Total transmitted bytes provide a coarse measure of communication volume and are frequently used in network traffic analysis.

This observation already exists within the SmartNIC runtime and incurs negligible computational overhead.

---

## Average Packet Size

Average packet size characterizes communication behaviour while remaining computationally inexpensive.

It provides similar information to the existing mean packet length implementation.

---

## Maximum Packet Size

Maximum packet size captures large payload transmissions that may distinguish certain attack classes.

This observation already exists in the SmartNIC implementation.

---

## Duration

Communication duration provides context regarding session persistence.

Because packet timestamps are already maintained during aggregation, duration can be calculated with minimal additional cost.

---

## Total Packets

Packet count measures communication intensity.

The runtime already maintains packet counts for aggregation windows.

---

## Mean Inter-arrival Time

Inter-arrival statistics characterize temporal communication behaviour.

Timing information has consistently demonstrated usefulness in intrusion detection research and already exists within the SmartNIC implementation.

---

## Packet Rate

Packet rate combines duration and packet count to describe communication intensity over time.

Since both values already exist, packet rate is effectively a derived observation.

---

## ACK Count

Rather than combining all TCP flags into a single aggregate value, explicit ACK counting provides greater interpretability for cyber defense analysis while remaining inexpensive to compute.

---

## Burstiness

Burstiness measures variability in traffic arrival patterns.

Although more computationally expensive than simple averages, it may improve detection of attacks characterized by irregular traffic generation.

Its deployment suitability will be evaluated experimentally.

---

## Originator Bytes

Directional byte counts provide additional insight into endpoint communication behaviour.

Supporting this observation requires maintaining directional statistics within packet windows and therefore represents one of the few observations requiring additional runtime support.

---

# 7. Design Trade-offs

Observation selection represents a balance between competing objectives.

Increasing the number of observations may improve detection performance but also increases computational cost, memory usage, and deployment complexity.

The goal is therefore not to maximize the number of observations but to maximize defensive value per unit of computational effort.

---

# 8. Future Refinement

As experiments progress, candidate observations may be:

- retained,
- refined,
- replaced,
- or removed.

However, changes should occur through versioned updates to the Defensive Observation Specification to preserve reproducibility across experimental results.

---

# 9. Summary

The proposed observation layer extends existing deployment-oriented packet processing by emphasizing observations that possess both operational cyber defense value and practical deployment characteristics.

Rather than relying exclusively on statistical feature importance, the methodology balances predictive performance, interpretability, computational efficiency, and deployment feasibility.

This design philosophy forms the foundation upon which the remainder of the machine learning pipeline—including training, ONNX export, and SmartNIC deployment—is constructed.
