"""Artifact search: emails, URLs, credentials, cloud keys."""

from __future__ import annotations

import re
from typing import List, Optional, Sequence

from scapy.layers.inet import IP, TCP, UDP
from scapy.packet import Packet, Raw

from pcaptriage.analyzers.base import AnalyzerBase
from pcaptriage.core.evidence import Evidence, Severity
from pcaptriage.core.hashing import sha256_bytes


EMAIL_RE = re.compile(rb"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,24}")
URL_RE = re.compile(rb"https?://[A-Za-z0-9._\-/%?&=:#~+@,;!$'()*]{4,512}")
AWS_KEY_RE = re.compile(rb"AKIA[0-9A-Z]{16}")
AWS_SECRET_RE = re.compile(rb"(?i)aws.{0,20}(secret|sk)[\"' :=]+([A-Za-z0-9/+]{40})")
BASIC_AUTH_RE = re.compile(rb"(?i)authorization:\s*basic\s+([A-Za-z0-9+/=]{8,})")
COOKIE_RE = re.compile(rb"(?i)set-cookie:\s*([^\r\n]+)")
PASS_PARAM_RE = re.compile(
    rb"(?i)(?:passwd|password|pwd|pass)=([^&\s\r\n\"']{3,128})"
)


def _src_dst(pkt: Packet) -> tuple[Optional[str], Optional[str]]:
    if pkt.haslayer(IP):
        return str(pkt[IP].src), str(pkt[IP].dst)
    return None, None


class ArtifactSearchAnalyzer(AnalyzerBase):
    """Surface common IR artifacts in cleartext payloads."""

    name = "artifact_search"
    description = "Email/URL/credential/cloud-key scan"

    PATTERNS = [
        ("email", EMAIL_RE, Severity.INFO),
        ("url", URL_RE, Severity.INFO),
        ("aws_access_key", AWS_KEY_RE, Severity.HIGH),
        ("aws_secret_key", AWS_SECRET_RE, Severity.CRITICAL),
        ("http_basic_auth", BASIC_AUTH_RE, Severity.HIGH),
        ("cookie", COOKIE_RE, Severity.MEDIUM),
        ("password_param", PASS_PARAM_RE, Severity.HIGH),
    ]

    def run(self, packets: Sequence[Packet]) -> List[Evidence]:
        findings: List[Evidence] = []
        for idx, pkt in enumerate(packets):
            if not (pkt.haslayer(TCP) or pkt.haslayer(UDP)):
                continue
            if not pkt.haslayer(Raw):
                continue
            data = bytes(pkt[Raw].load)
            src, dst = _src_dst(pkt)
            ts = float(pkt.time) if hasattr(pkt, "time") else None

            for name, pattern, sev in self.PATTERNS:
                for m in pattern.finditer(data):
                    blob = m.group(0)
                    findings.append(
                        Evidence(
                            type=name,
                            severity=sev,
                            packet_offset=idx,
                            timestamp=ts,
                            source_ip=src,
                            dest_ip=dst,
                            payload_hash=sha256_bytes(blob),
                            details={
                                "match": blob[:256].decode(
                                    "utf-8", errors="replace"
                                )
                            },
                        )
                    )
        return findings
