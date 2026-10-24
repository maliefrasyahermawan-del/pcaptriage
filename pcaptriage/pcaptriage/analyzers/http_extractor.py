"""Extract HTTP objects (request/response bodies) from TCP streams."""

from __future__ import annotations

import gzip
import re
import zlib
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

from scapy.layers.inet import IP, TCP
from scapy.packet import Packet, Raw

from pcaptriage.analyzers.base import AnalyzerBase
from pcaptriage.core.evidence import Evidence, Severity
from pcaptriage.core.hashing import sha256_bytes


RESPONSE_RE = re.compile(rb"^HTTP/\d\.\d\s+(\d{3})\s+([^\r\n]*)\r\n")
REQUEST_RE = re.compile(
    rb"^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+([^\s]+)\s+HTTP/\d\.\d\r\n"
)


_MAGICS: List[Tuple[bytes, str]] = [
    (b"\x89PNG\r\n\x1a\n", ".png"),
    (b"\xff\xd8\xff", ".jpg"),
    (b"GIF87a", ".gif"),
    (b"GIF89a", ".gif"),
    (b"%PDF-", ".pdf"),
    (b"PK\x03\x04", ".zip"),
    (b"\x1f\x8b\x08", ".gz"),
    (b"<!DOCTYPE", ".html"),
    (b"<html", ".html"),
    (b"{", ".json"),
    (b"<?xml", ".xml"),
]


def _guess_ext(data: bytes) -> str:
    head = data[:16]
    for magic, ext in _MAGICS:
        if head.startswith(magic):
            return ext
    return ".bin"


def _decode_body(body: bytes, content_encoding: str) -> bytes:
    enc = content_encoding.lower().strip()
    try:
        if enc == "gzip":
            return gzip.decompress(body)
        if enc == "deflate":
            return zlib.decompress(body)
    except Exception:
        return body
    return body


def _parse_headers(blob: bytes) -> Tuple[Dict[str, str], bytes]:
    sep = blob.find(b"\r\n\r\n")
    if sep == -1:
        return {}, blob
    head, body = blob[:sep], blob[sep + 4 :]
    headers: Dict[str, str] = {}
    for line in head.split(b"\r\n")[1:]:
        if b":" in line:
            k, _, v = line.partition(b":")
            headers[k.strip().decode("latin1").lower()] = v.strip().decode(
                "latin1", errors="replace"
            )
    return headers, body


def _dechunk(body: bytes) -> bytes:
    out = bytearray()
    i = 0
    while i < len(body):
        nl = body.find(b"\r\n", i)
        if nl == -1:
            break
        try:
            size = int(body[i:nl].split(b";")[0], 16)
        except ValueError:
            break
        i = nl + 2
        if size == 0:
            break
        out.extend(body[i : i + size])
        i += size + 2
    return bytes(out)


def _stream_key(pkt: Packet) -> Optional[Tuple[str, int, str, int]]:
    if not (pkt.haslayer(IP) and pkt.haslayer(TCP)):
        return None
    ip = pkt[IP]
    t = pkt[TCP]
    a = (str(ip.src), int(t.sport), str(ip.dst), int(t.dport))
    b = (str(ip.dst), int(t.dport), str(ip.src), int(t.sport))
    return a if a < b else b


class HttpExtractorAnalyzer(AnalyzerBase):
    """Reassemble TCP streams and extract HTTP response bodies to disk."""

    name = "http_extractor"
    description = "Extract HTTP objects from cleartext streams"

    def run(self, packets: Sequence[Packet]) -> List[Evidence]:
        streams: Dict[Tuple, bytearray] = defaultdict(bytearray)
        first_idx: Dict[Tuple, int] = {}
        first_ep: Dict[Tuple, Tuple[str, str]] = {}

        for idx, pkt in enumerate(packets):
            key = _stream_key(pkt)
            if key is None or not pkt.haslayer(Raw):
                continue
            data = bytes(pkt[Raw].load)
            if not data:
                continue
            if key not in first_idx:
                first_idx[key] = idx
                first_ep[key] = (str(pkt[IP].src), str(pkt[IP].dst))
            streams[key].extend(data)

        findings: List[Evidence] = []
        out_root: Optional[Path] = None
        if self.ctx is not None:
            out_root = Path(self.ctx.output_dir) / "objects" / "http"
            out_root.mkdir(parents=True, exist_ok=True)

        for key, buf in streams.items():
            blob = bytes(buf)
            findings.extend(self._extract(blob, key, first_idx[key],
                                          first_ep[key], out_root))
        return findings

    def _extract(self, blob: bytes, key: Tuple,
                 packet_idx: int, ep: Tuple[str, str],
                 out_root: Optional[Path]) -> List[Evidence]:
        results: List[Evidence] = []
        src, dst = ep

        pos = 0
        while pos < len(blob):
            m_resp = RESPONSE_RE.search(blob, pos)
            m_req = REQUEST_RE.search(blob, pos)
            candidates = [m for m in (m_resp, m_req) if m is not None]
            if not candidates:
                break
            m = min(candidates, key=lambda x: x.start())
            start = m.start()
            next_m = None
            for cand in (RESPONSE_RE.search(blob, m.end()),
                         REQUEST_RE.search(blob, m.end())):
                if cand is not None:
                    next_m = cand if next_m is None or cand.start() < next_m.start() else next_m
            end = next_m.start() if next_m else len(blob)
            chunk = blob[start:end]
            pos = end

            headers, body = _parse_headers(chunk)
            te = headers.get("transfer-encoding", "")
            ce = headers.get("content-encoding", "")
            if "chunked" in te.lower():
                body = _dechunk(body)
            if ce:
                body = _decode_body(body, ce)
            if not body:
                continue

            digest = sha256_bytes(body)
            ext = _guess_ext(body)
            saved_path = ""
            if out_root is not None:
                saved_path = str(out_root / f"{digest[:16]}{ext}")
                try:
                    with open(saved_path, "wb") as fp:
                        fp.write(body)
                except OSError:
                    saved_path = ""

            ctype = headers.get("content-type", "")
            results.append(
                Evidence(
                    type="http_object",
                    severity=Severity.MEDIUM,
                    packet_offset=packet_idx,
                    source_ip=src,
                    dest_ip=dst,
                    payload_hash=digest,
                    details={
                        "size_bytes": len(body),
                        "content_type": ctype,
                        "content_encoding": ce,
                        "transfer_encoding": te,
                        "saved_to": saved_path,
                        "extension": ext,
                        "preview": body[:120].decode("utf-8", errors="replace"),
                    },
                )
            )
        return results
