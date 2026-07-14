# Defensive Observation Specification

**Version:** 0.1 (Draft)  
**Status:** Working specification for the Edge-IIoT intrusion detection pipeline

---

## 1. Purpose

This document defines the defensive observations used by the Edge-IIoT intrusion detection workflow.

The goal is to provide a stable, implementation-facing specification for the observations extracted from packet windows so that the same values can be reproduced during:

- PCAP processing
- dataset generation
- model training
- model evaluation
- ONNX export
- runtime inference

This specification is intentionally aligned with the deployment-oriented design used in Sergio's SmartNIC repository, but it extends that baseline with additional observations that improve defensive interpretability and operational usefulness.

---

## 2. Scope

This specification applies to packet-window based observations derived from IPv4/TCP traffic.

It does **not** define:

- model architecture
- training hyperparameters
- class labels
- preprocessing strategy beyond observation-level normalization
- deployment mechanics in C or ONNX Runtime

Those topics are covered in separate repository documents.

---

## 3. Design principles

The observation set is selected using four criteria.

1. **Defensive value**  
   The observation should help distinguish benign from malicious traffic or improve explanation of traffic behavior.

2. **Low runtime cost**  
   The observation should be inexpensive to compute during packet processing.

3. **Operational reproducibility**  
   The observation must be computable in both offline preprocessing and deployment-time inference.

4. **Implementation clarity**  
   The observation should be easy to define, validate, and map to code.

The goal is not to maximize the number of observations. The goal is to maximize defensive value per unit of runtime cost.

---

## 4. Relationship to Sergio's repository

Sergio's SmartNIC-oriented repository uses an efficient 8-feature IoT profile with the following core values:

- minimum packet length
- maximum packet length
- mean packet length
- minimum inter-arrival time
- maximum inter-arrival time
- mean inter-arrival time
- total bytes
- TCP flag summary

This specification keeps the same general design direction, but formalizes the observations in a more deployment-oriented and defense-oriented way.

The current project treats Sergio's work as the engineering baseline and extends it with observations such as:

- total packet count
- duration
- packet rate
- originator bytes
- ACK count
- burstiness coefficient of variation

These additions are intended to improve interpretability and alignment with the cyber defense objective while remaining lightweight enough for future deployment.

---

## 5. Canonical observation set

The table below defines the current working observation set. Some items are direct equivalents of Sergio's existing values, while others are extensions.

| Observation | Definition | Formula / Computation | Type | Unit | Runtime Cost | Sergio Equivalent | Status |
|---|---|---|---|---|---|---|---|
| `total_bytes` | Total bytes observed in the packet window | `sum(packet_length_i)` | float | bytes | Low | `total_bytes` | Required |
| `avg_pkt_size` | Average packet size in the window | `total_bytes / total_pkts` | float | bytes | Low | `mean_len` | Required |
| `max_pkt_size` | Maximum packet size in the window | `max(packet_length_i)` | float | bytes | Low | `len_max` | Required |
| `duration` | Time span of the packet window | `last_ts - first_ts` | float | seconds | Low | Derived | Required |
| `total_pkts` | Packet count in the window | `count(packet_i)` | integer | packets | Low | `pkt_count` | Required |
| `mean_iat` | Mean inter-arrival time | `mean(ts[i] - ts[i-1])` | float | seconds | Low | `mean_iat` | Required |
| `pkts_per_sec` | Packet rate per second | `total_pkts / duration` | float | packets/sec | Low | Derived | Required |
| `ack_count` | Number of TCP packets carrying ACK | `count(TCP packets with ACK flag set)` | integer | packets | Low | Partial (`tcp_flag_bits_sum`) | Required |
| `orig_bytes` | Bytes sent by the originator side of the flow | `sum(packet_length_i for originator-direction packets)` | float | bytes | Medium | `orig_bytes` in flow-aware pipelines | Candidate |
| `burstiness_cv` | Variability of inter-arrival times | `std(iat) / mean(iat)` | float | unitless | Medium | Not explicit | Candidate |

---

## 6. Notes on each observation

### 6.1 `total_bytes`

This is a core traffic-volume observation and is already present in Sergio's IOT profile. It is inexpensive to compute and provides a strong baseline measure of communication intensity.

### 6.2 `avg_pkt_size`

This observation captures the mean packet size in a window. It is conceptually identical to Sergio's mean packet length and remains inexpensive to compute.

### 6.3 `max_pkt_size`

This observation captures unusually large packets and is useful for characterizing certain attack patterns or payload-heavy exchanges.

### 6.4 `duration`

Duration provides context for traffic persistence. It is derived from timestamps already available during packet aggregation.

### 6.5 `total_pkts`

Packet count is a direct measure of traffic intensity and is cheap to maintain during aggregation.

### 6.6 `mean_iat`

Mean inter-arrival time captures timing behavior and is already aligned with Sergio's implementation. It is one of the most useful low-cost timing features.

### 6.7 `pkts_per_sec`

Packet rate is a normalized intensity measure derived from packet count and duration. It is useful for comparing windows of different lengths.

### 6.8 `ack_count`

Explicit ACK counting is more interpretable for defensive analysis than a generic TCP flag sum. It is also easy to compute from the parsed TCP header.

### 6.9 `orig_bytes`

Originator bytes are useful when the runtime distinguishes directionality within a flow. This is a useful extension because it exposes asymmetry in communication behavior.

### 6.10 `burstiness_cv`

The coefficient of variation of inter-arrival times is a compact measure of traffic variability. It is more expensive than simple counts or sums, but still feasible for deployment if profiling shows acceptable cost.

---

## 7. Formal computation rules

### 7.1 Packet window

A packet window is an ordered sequence of packets belonging to the same flow or aggregation unit.

For a window of size `N`:

- `packet_length_i` is the length of packet `i`
- `ts_i` is the timestamp of packet `i`
- `iat_i = ts_i - ts_(i-1)` for `i > 0`

### 7.2 Safe ratio rule

Any division must use a safe ratio rule:

- if the denominator is `0`, return `0.0`
- otherwise return the quotient as a float

This is especially important for `duration`, `pkts_per_sec`, and any future normalized observations.

### 7.3 Timestamp unit

Timestamps should be represented in seconds at the specification level.

If the runtime stores timestamps in hardware ticks or another unit, conversion must occur before observation values are emitted.

### 7.4 Missing or invalid values

Observations must be finite and non-negative unless the definition explicitly allows another range.

Invalid or missing packets should be excluded from the window rather than forcing invalid values into the observation vector.

---

## 8. Recommended canonical ordering

The current working order for the observation vector is:

1. `total_bytes`
2. `avg_pkt_size`
3. `max_pkt_size`
4. `duration`
5. `total_pkts`
6. `mean_iat`
7. `pkts_per_sec`
8. `ack_count`
9. `orig_bytes`
10. `burstiness_cv`

This ordering should be treated as the current versioned interface for model training and runtime validation.

If the observation set changes, a new specification version must be created rather than silently reordering fields.

---

## 9. Data type guidance

- Count-like observations should be stored as integers during extraction and may be converted to float for model input.
- Ratio and timing observations should be stored as floats.
- Model input vectors should use a consistent numeric type across training and inference.

The implementation may use `float32` for model input compatibility, even when the original observation is naturally an integer.

---

## 10. Validation expectations

The runtime and preprocessing pipeline should validate the following conditions when feasible:

- `total_bytes >= 0`
- `avg_pkt_size >= 0`
- `max_pkt_size >= 0`
- `duration >= 0`
- `total_pkts >= 1`
- `mean_iat >= 0`
- `pkts_per_sec >= 0`
- `ack_count >= 0`
- `orig_bytes >= 0`
- `burstiness_cv >= 0`

Additional logical checks may also be applied, such as:

- `avg_pkt_size` should not exceed `max_pkt_size`
- `pkts_per_sec` should be derived from `total_pkts` and `duration`
- `burstiness_cv` should be finite

---

## 11. Implementation mapping

This specification should map directly to the following implementation areas:

- `src/edgeiiot/observations.py` for Python extraction
- `scripts/process_pcaps.py` for dataset generation
- `docs/Defensive_Observation_Design_Rationale.md` for the reasoning behind each observation
- `runtime/` for deployment-time consumption
- ONNX input preparation for model inference

Each implementation should use the same observation names and ordering defined here.

---

## 12. Versioning policy

This document is versioned because observations are part of the project interface.

Minor updates may be made as the implementation matures, but any change that affects:

- feature names
- observation order
- computation method
- runtime meaning

should be treated as a new specification version.

---

## 13. Summary

This specification defines a compact, deployment-oriented observation set for Edge-IIoT intrusion detection.

It preserves the engineering strengths of Sergio's repository while adding a small number of observations that better support defensive interpretation, deployment analysis, and future SmartNIC integration.

The observation set is intentionally practical: it is large enough to support meaningful cyber defense modeling, but small enough to remain compatible with constrained runtime environments.
