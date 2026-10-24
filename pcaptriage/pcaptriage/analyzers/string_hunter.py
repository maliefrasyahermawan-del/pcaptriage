"""Hunt for CTF flags, base64 blobs, JWTs and high-entropy strings."""

from __future__ import annotations

import base64
import math
import re
from typing import List, Optional, Sequence

from scapy.layers.inet import IP, TCP, UDP
from scapy.packet import Packet, Raw

from pcaptriage.analyzers.base import AnalyzerBase
from pcaptriage.core.evidence import Evidence, Severity
from pcaptriage.core.hashing import sha256_bytes


CTF_FLAG_RE = re.compile(
    rb"(?:CTF|FLAG|flag|picoCTF|HTB|THM|MBC)\{[^}\r\n]{1,256}\}"
)
BASE64_RE = re.compile(rb"[A-Za-z0-9+/]{20,}={0,2}")
JWT_RE = re.compile(rb"eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+")
HEX_RE = re.compile(rb"\b[a-fA-F0-9]{32,}\b")


def _shannon_entropy(data: bytes) -> float:
    """Compute Shannon entropy (bits/byte) of ``data``. Used to filter junk."""
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in freq if c)


def _payload(pkt: Packet) -> bytes:
    if pkt.haslayer(Raw):
        return bytes(pkt[Raw].load)
    return b""


def _src_dst(pkt: Packet) -> tuple[Optional[str], Optional[str]]:
    if pkt.haslayer(IP):
        return str(pkt[IP].src), str(pkt[IP].dst)
    return None, None


class StringHunterAnalyzer(AnalyzerBase):
    """Find embedded secrets and CTF flags in TCP/UDP payloads."""

    name = "string_hunter"
    description = "CTF flag / base64 / JWT / hex pattern scan"

    def run(self, packets: Sequence[Packet]) -> List[Evidence]:
        findings: List[Evidence] = []
        for idx, pkt in enumerate(packets):
            if not (pkt.haslayer(TCP) or pkt.haslayer(UDP)):
                continue
            data = _payload(pkt)
            if not data:
                continue
            src, dst = _src_dst(pkt)
            ts = float(pkt.time) if hasattr(pkt, "time") else None

            for match in CTF_FLAG_RE.finditer(data):
                flag = match.group(0).decode("utf-8", errors="replace")
                findings.append(
                    Evidence(
                        type="ctf_flag",
                        severity=Severity.CRITICAL,
                        packet_offset=idx,
                        timestamp=ts,
                        source_ip=src,
                        dest_ip=dst,
                        payload_hash=sha256_bytes(match.group(0)),
                        details={"flag": flag, "offset_in_payload": match.start()},
                    )
                )

            for match in JWT_RE.finditer(data):
                tok = match.group(0).decode("ascii", errors="replace")
                findings.append(
                    Evidence(
                        type="jwt_token",
                        severity=Severity.HIGH,
                        packet_offset=idx,
                        timestamp=ts,
                        source_ip=src,
                        dest_ip=dst,
                        payload_hash=sha256_bytes(match.group(0)),
                        details={"token_preview": tok[:96]},
                    )
                )

            for match in BASE64_RE.finditer(data):
                blob = match.group(0)
                if len(blob) < 24:
                    continue
                entropy = _shannon_entropy(blob)
                if entropy < 4.0:
                    continue
                decoded_preview = ""
                try:
                    decoded = base64.b64decode(blob + b"==" * (4 - len(blob) % 4),
                                               validate=False)
                    if any(32 <= b < 127 for b in decoded[:16]):
                        decoded_preview = decoded[:80].decode(
                            "utf-8", errors="replace"
                        )
                except Exception:
                    pass
                findings.append(
                    Evidence(
                        type="base64_blob",
                        severity=Severity.LOW,
                        packet_offset=idx,
                        timestamp=ts,
                        source_ip=src,
                        dest_ip=dst,
                        payload_hash=sha256_bytes(blob),
                        details={
                            "length": len(blob),
                            "entropy": round(entropy, 2),
                            "decoded_preview": decoded_preview,
                        },
                    )
                )

            for match in HEX_RE.finditer(data):
                hx = match.group(0)
                if len(hx) > 256:
                    continue
                findings.append(
                    Evidence(
                        type="hex_blob",
                        severity=Severity.LOW,
                        packet_offset=idx,
                        timestamp=ts,
                        source_ip=src,
                        dest_ip=dst,
                        payload_hash=sha256_bytes(hx),
                        details={"length": len(hx),
                                 "preview": hx[:64].decode("ascii", "replace")},
                    )
                )
        return findings
