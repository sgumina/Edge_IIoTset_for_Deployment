"""Defensive observation extraction for Edge-IIoT packet windows.

This module is intentionally small and dependency-light so it can be reused in:
- offline PCAP processing
- dataset generation
- training/evaluation notebooks
- eventual runtime validation tests

The functions below operate on a *window* of packet-like records. A packet-like
record may be any mapping or object that exposes the fields used by the
observation functions:

Required fields
---------------
- ts: float timestamp in seconds
- pkt_len: packet length in bytes (or `len` if pkt_len is absent)
- src_bytes: bytes attributed to the originating side, if directional metrics
  are desired
- tcp_ack: TCP ACK value or a truthy ACK indicator (optional)
- ack: ACK flag indicator (optional)

The extractor assumes that the calling code has already grouped packets into a
window and, when applicable, into a directional flow.

Notes on labels
---------------
The Edge-IIoTset PCAPs are grouped at the capture level: attack traffic is
organized by attack type, while normal traffic is organized by device.
That means the *dataset builder* should infer labels from the capture path or
capture metadata, not from packet content.

This module therefore focuses only on observation computation.
"""

from __future__ import annotations

from dataclasses import dataclass
from math import sqrt
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

Number = float | int


@dataclass(frozen=True)
class ObservationSpec:
    """Metadata describing a single defensive observation."""

    name: str
    description: str
    runtime_cost: str
    note: str = ""


CANONICAL_OBSERVATIONS: tuple[str, ...] = (
    "total_bytes",
    "avg_pkt_size",
    "duration",
    "packet_count",
    "mean_iat",
    "packet_rate",
    "ack_count",
    "orig_bytes",
    "burstiness_cv",
    "max_pkt_size",
)

OBSERVATION_SPECS: tuple[ObservationSpec, ...] = (
    ObservationSpec("total_bytes", "Total bytes observed in the window.", "Low"),
    ObservationSpec("avg_pkt_size", "Mean packet size within the window.", "Low"),
    ObservationSpec("duration", "Window duration in seconds.", "Low"),
    ObservationSpec("packet_count", "Number of packets in the window.", "Low"),
    ObservationSpec("mean_iat", "Mean inter-arrival time in seconds.", "Medium"),
    ObservationSpec("packet_rate", "Packets per second in the window.", "Low"),
    ObservationSpec("ack_count", "Count of packets with the TCP ACK flag set.", "Low"),
    ObservationSpec("orig_bytes", "Directional bytes attributed to the originator side.", "Low"),
    ObservationSpec("burstiness_cv", "Coefficient of variation of inter-arrival times.", "Higher"),
    ObservationSpec("max_pkt_size", "Largest packet size in the window.", "Low"),
)


def _get_value(pkt: Any, key: str, default: Any = 0) -> Any:
    if isinstance(pkt, Mapping):
        return pkt.get(key, default)
    return getattr(pkt, key, default)


def _as_float(value: Any, default: float = 0.0) -> float:
    try:
        if value is None:
            return default
        return float(value)
    except (TypeError, ValueError):
        return default


def _pkt_len(pkt: Any) -> float:
    """Return packet length in bytes using common field names."""

    for key in ("pkt_len", "len", "packet_length", "frame_len", "ip_len"):
        value = _get_value(pkt, key, None)
        if value is not None:
            return _as_float(value, 0.0)
    return 0.0


def _timestamp(pkt: Any) -> float:
    for key in ("ts", "timestamp", "time", "pkt_time"):
        value = _get_value(pkt, key, None)
        if value is not None:
            return _as_float(value, 0.0)
    return 0.0


def _sorted_window(window: Iterable[Any]) -> list[Any]:
    items = list(window)
    items.sort(key=_timestamp)
    return items


def _iat_values(window: Sequence[Any]) -> list[float]:
    if len(window) < 2:
        return []
    ts = [_timestamp(pkt) for pkt in window]
    return [max(0.0, ts[i] - ts[i - 1]) for i in range(1, len(ts))]


def total_bytes(window: Iterable[Any]) -> float:
    """Sum of packet lengths in the window."""

    return float(sum(_pkt_len(pkt) for pkt in window))


def packet_count(window: Iterable[Any]) -> int:
    """Number of packets in the window."""

    return sum(1 for _ in window)


def duration(window: Iterable[Any]) -> float:
    """Return the elapsed time between the first and last packet timestamps."""

    items = _sorted_window(window)
    if len(items) < 2:
        return 0.0
    return max(0.0, _timestamp(items[-1]) - _timestamp(items[0]))


def mean_iat(window: Iterable[Any]) -> float:
    """Mean inter-arrival time (seconds)."""

    items = _sorted_window(window)
    iats = _iat_values(items)
    return float(sum(iats) / len(iats)) if iats else 0.0


def avg_pkt_size(window: Iterable[Any]) -> float:
    """Mean packet size in bytes."""

    items = list(window)
    return float(total_bytes(items) / len(items)) if items else 0.0


def packet_rate(window: Iterable[Any]) -> float:
    """Packets per second.

    Defined as packet_count / duration when duration > 0.
    For windows with a single packet or zero duration, returns packet_count.
    """

    items = list(window)
    if not items:
        return 0.0
    dur = duration(items)
    count = len(items)
    return float(count / dur) if dur > 0 else float(count)


def ack_count(window: Iterable[Any]) -> int:
    """Count packets with an ACK indicator.

    Supports either:
    - an explicit integer/boolean `ack` field
    - a boolean-like `tcp_ack` field
    - a string flags field containing 'A'
    """

    count = 0
    for pkt in window:
        ack_field = _get_value(pkt, "ack", None)
        if ack_field is not None:
            count += int(bool(ack_field))
            continue

        tcp_ack = _get_value(pkt, "tcp_ack", None)
        if tcp_ack is not None:
            count += int(bool(tcp_ack))
            continue

        flags = _get_value(pkt, "tcp_flags_raw", None)
        if flags is not None:
            count += int("A" in str(flags))
    return count


def orig_bytes(window: Iterable[Any]) -> float:
    """Bytes attributed to the originator/original side of the flow.

    If packets provide an `is_originator` flag, only packets marked True are
    counted. Otherwise this falls back to total_bytes.
    """

    total = 0.0
    saw_originator_flag = False
    for pkt in window:
        flag = _get_value(pkt, "is_originator", None)
        if flag is None:
            continue
        saw_originator_flag = True
        if bool(flag):
            total += _pkt_len(pkt)
    return total if saw_originator_flag else total_bytes(window)


def max_pkt_size(window: Iterable[Any]) -> float:
    """Largest packet length in the window."""

    items = list(window)
    return float(max((_pkt_len(pkt) for pkt in items), default=0.0))


def burstiness_cv(window: Iterable[Any]) -> float:
    """Coefficient of variation of inter-arrival times.

    Returns 0.0 when the window has fewer than 2 packets or the mean IAT is 0.
    """

    items = _sorted_window(window)
    iats = _iat_values(items)
    if len(iats) < 2:
        return 0.0
    mean = sum(iats) / len(iats)
    if mean <= 0:
        return 0.0
    variance = sum((x - mean) ** 2 for x in iats) / len(iats)
    return float(sqrt(variance) / mean)


def summarize_window(window: Iterable[Any]) -> dict[str, float]:
    """Return the canonical observation vector as a dict.

    The column ordering is intentionally stable and matches
    CANONICAL_OBSERVATIONS.
    """

    items = list(window)
    return {
        "total_bytes": total_bytes(items),
        "avg_pkt_size": avg_pkt_size(items),
        "duration": duration(items),
        "packet_count": float(packet_count(items)),
        "mean_iat": mean_iat(items),
        "packet_rate": packet_rate(items),
        "ack_count": float(ack_count(items)),
        "orig_bytes": orig_bytes(items),
        "burstiness_cv": burstiness_cv(items),
        "max_pkt_size": max_pkt_size(items),
    }


# ----------------------------------------------------------------------------
# Label helpers
# ----------------------------------------------------------------------------

NORMAL_HINTS = {"normal", "benign", "device", "devices"}
ATTACK_HINTS = {
    "attack", "ddos", "dos", "scan", "probe", "spoof", "injection",
    "backdoor", "mitm", "password", "ransom", "worm", "xss", "sqli",
}


def infer_label_from_path(pcap_path: str | Path, *, normal_hints: set[str] | None = None) -> str:
    """Infer a coarse label from capture path metadata.

    This helper is intentionally conservative. It does **not** try to guess the
    specific attack subtype; it only returns a coarse top-level label:
    ``normal`` or ``attack``.

    Because the Edge-IIoTset organizes normal traffic by device and attack
    traffic by attack type, the dataset builder can use the capture path to
    derive labels consistently.
    """

    hints = normal_hints or NORMAL_HINTS
    parts = {part.lower() for part in Path(pcap_path).parts}

    if parts & hints:
        return "normal"
    if parts & ATTACK_HINTS:
        return "attack"
    stem = Path(pcap_path).stem.lower()
    if any(h in stem for h in hints):
        return "normal"
    if any(h in stem for h in ATTACK_HINTS):
        return "attack"
    return "unknown"


__all__ = [
    "CANONICAL_OBSERVATIONS",
    "OBSERVATION_SPECS",
    "ObservationSpec",
    "summarize_window",
    "total_bytes",
    "avg_pkt_size",
    "duration",
    "packet_count",
    "mean_iat",
    "packet_rate",
    "ack_count",
    "orig_bytes",
    "burstiness_cv",
    "max_pkt_size",
    "infer_label_from_path",
]
