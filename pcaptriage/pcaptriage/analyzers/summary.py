"""Capture-wide summary: packet counts, protocol breakdown, duration."""

from __future__ import annotations

from collections import Counter
from typing import List, Sequence

from scapy.layers.dns import DNS
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.packet import Packet

from pcaptriage.analyzers.base import AnalyzerBase
from pcaptriage.core.evidence import Evidence, Severity
from pcaptriage.core.hashing import sha256_bytes


class SummaryAnalyzer(AnalyzerBase):
    """Emit one INFO evidence with overall capture statistics."""

    name = "summary"
    description = "Overall packet count, protocol breakdown, duration"

    def run(self, packets: Sequence[Packet]) -> List[Evidence]:
        if not packets:
            return [
                Evidence(
                    type="capture_summary",
                    severity=Severity.INFO,
                    payload_hash=sha256_bytes(b"empty"),
                    details={"packets": 0, "note": "empty capture"},
                )
            ]

        proto_counter: Counter = Counter()
        l4_counter: Counter = Counter()
        total_bytes = 0

        for pkt in packets:
            total_bytes += len(bytes(pkt))
            if pkt.haslayer(TCP):
                l4_counter["TCP"] += 1
            elif pkt.haslayer(UDP):
                l4_counter["UDP"] += 1
            elif pkt.haslayer(ICMP):
                l4_counter["ICMP"] += 1
            else:
                l4_counter["OTHER"] += 1

            if pkt.haslayer(DNS):
                proto_counter["DNS"] += 1
            if pkt.haslayer(IP):
                proto_counter["IPv4"] += 1
            if pkt.haslayer(IPv6):
                proto_counter["IPv6"] += 1
            if pkt.haslayer(TCP):
                try:
                    dport = int(pkt[TCP].dport)
                    sport = int(pkt[TCP].sport)
                    if 80 in (dport, sport) or 8080 in (dport, sport):
                        proto_counter["HTTP"] += 1
                    if 443 in (dport, sport):
                        proto_counter["TLS"] += 1
                    if 22 in (dport, sport):
                        proto_counter["SSH"] += 1
                except (AttributeError, ValueError):
                    pass

        first_ts = float(packets[0].time)
        last_ts = float(packets[-1].time)
        duration = max(0.0, last_ts - first_ts)

        details = {
            "packet_count": len(packets),
            "total_bytes": total_bytes,
            "duration_seconds": round(duration, 3),
            "first_timestamp": first_ts,
            "last_timestamp": last_ts,
            "l4_breakdown": dict(l4_counter),
            "protocol_breakdown": dict(proto_counter),
        }
        return [
            Evidence(
                type="capture_summary",
                severity=Severity.INFO,
                packet_offset=0,
                timestamp=first_ts,
                payload_hash=sha256_bytes(str(details).encode("utf-8")),
                details=details,
            )
        ]
