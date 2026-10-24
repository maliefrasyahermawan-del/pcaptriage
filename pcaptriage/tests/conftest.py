"""Generate a sample PCAP fixture for smoke tests."""

from __future__ import annotations

from pathlib import Path

import pytest
from scapy.all import wrpcap
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, TCP, UDP
from scapy.packet import Raw

FIXTURE_DIR = Path(__file__).parent / "fixtures"
SAMPLE_PCAP = FIXTURE_DIR / "sample.pcap"


def _build_packets():
    pkts = []
    client = "10.0.0.5"
    server = "93.184.216.34"
    for i in range(25):
        req = (IP(src=client, dst=server) /
               TCP(sport=40000 + i, dport=80, flags="PA", seq=1, ack=1) /
               Raw(load=(f"GET /page{i} HTTP/1.1\r\nHost: example.com\r\n"
                         f"User-Agent: pcaptriage-test\r\n\r\n").encode()))
        pkts.append(req)
        body = (b"<html><body><p>hello world</p></body></html>"
                if i != 7 else
                b"<html><body>flag is CTF{test_flag_12345}</body></html>")
        resp = (IP(src=server, dst=client) /
                TCP(sport=80, dport=40000 + i, flags="PA", seq=1, ack=1) /
                Raw(load=(b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n"
                          b"Content-Length: " +
                          str(len(body)).encode() + b"\r\n\r\n" + body)))
        pkts.append(resp)
    for i in range(10):
        q = (IP(src=client, dst="8.8.8.8") /
             UDP(sport=50000 + i, dport=53) /
             DNS(rd=1, qd=DNSQR(qname=f"host{i}.example.com")))
        pkts.append(q)
    return pkts


@pytest.fixture(scope="session")
def sample_pcap() -> Path:
    FIXTURE_DIR.mkdir(parents=True, exist_ok=True)
    if not SAMPLE_PCAP.exists():
        wrpcap(str(SAMPLE_PCAP), _build_packets())
    return SAMPLE_PCAP
