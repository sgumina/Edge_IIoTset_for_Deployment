#!/usr/bin/env python3
"""Quick smoke test for the observation layer.

Usage:
    python scripts/validate_observations.py --pcap /path/to/file.pcap
"""

from __future__ import annotations

import argparse
from pathlib import Path
import sys

from scapy.all import PcapReader

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from edgeiiot.observations import CANONICAL_OBSERVATIONS, infer_label_from_path, summarize_window


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--pcap", required=True, help="Path to a PCAP file")
    parser.add_argument("--window-size", type=int, default=8, help="Number of packets per window")
    args = parser.parse_args()

    pcap_path = Path(args.pcap)
    if not pcap_path.exists():
        raise FileNotFoundError(pcap_path)

    packets = []
    with PcapReader(str(pcap_path)) as reader:
        for pkt in reader:
            if hasattr(pkt, "time"):
                # Store only the minimal packet info needed by observations.
                pkt_len = len(pkt)
                ts = float(pkt.time)
                ack = 0
                tcp_flags = None
                try:
                    from scapy.all import TCP
                    if TCP in pkt:
                        tcp = pkt[TCP]
                        ack = int(bool(int(getattr(tcp, "ack", 0))))
                        tcp_flags = str(getattr(tcp, "flags", ""))
                except Exception:
                    pass
                packets.append({"ts": ts, "pkt_len": pkt_len, "ack": ack, "tcp_flags_raw": tcp_flags})

    label = infer_label_from_path(pcap_path)
    print(f"Capture label: {label}")
    print(f"Packets loaded: {len(packets)}")
    if len(packets) < args.window_size:
        print("Not enough packets for one full window.")
        return 0

    window = packets[: args.window_size]
    summary = summarize_window(window)
    print("\nCanonical observations:")
    for name in CANONICAL_OBSERVATIONS:
        print(f"  {name:>14}: {summary[name]}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
