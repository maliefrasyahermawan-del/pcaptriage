"""Top talkers analyzer: rank source/dest IPs and ports by traffic."""

from __future__ import annotations

from collections import Counter
from typing import List, Sequence

from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.packet import Packet

from pcaptriage.analyzers.base import AnalyzerBase
from pcaptriage.core.evidence import Evidence, Severity
from pcaptriage.core.hashing import sha256_bytes


TOP_N = 10


class TalkersAnalyzer(AnalyzerBase):
    """Aggregate per-IP and per-port traffic and emit top talkers."""

    name = "talkers"
    description = "Top source/destination IPs and ports"

    def run(self, packets: Sequence[Packet]) -> List[Evidence]:
        src_ip: Counter = Counter()
        dst_ip: Counter = Counter()
        port_pairs: Counter = Counter()

        for pkt in packets:
            ip_layer = None
            if pkt.haslayer(IP):
                ip_layer = pkt[IP]
            elif pkt.haslayer(IPv6):
                ip_layer = pkt[IPv6]
            if ip_layer is None:
                continue
            src_ip[str(ip_layer.src)] += 1
            dst_ip[str(ip_layer.dst)] += 1

            if pkt.haslayer(TCP):
                t = pkt[TCP]
                port_pairs[f"TCP/{int(t.dport)}"] += 1
            elif pkt.haslayer(UDP):
                u = pkt[UDP]
                port_pairs[f"UDP/{int(u.dport)}"] += 1

        details = {
            "top_source_ips": src_ip.most_common(TOP_N),
            "top_dest_ips": dst_ip.most_common(TOP_N),
            "top_ports": port_pairs.most_common(TOP_N),
        }
        return [
            Evidence(
                type="top_talkers",
                severity=Severity.INFO,
                payload_hash=sha256_bytes(str(details).encode("utf-8")),
                details=details,
            )
        ]
