"""Extract files transferred over TFTP (UDP/69)."""

from __future__ import annotations

import struct
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

from scapy.layers.inet import IP, UDP
from scapy.packet import Packet, Raw

from pcaptriage.analyzers.base import AnalyzerBase
from pcaptriage.core.evidence import Evidence, Severity
from pcaptriage.core.hashing import sha256_bytes


OP_RRQ = 1
OP_WRQ = 2
OP_DATA = 3


def _parse_rwq(data: bytes) -> Optional[str]:
    parts = data[2:].split(b"\x00")
    if not parts:
        return None
    return parts[0].decode("utf-8", errors="replace")


class TftpExtractorAnalyzer(AnalyzerBase):
    """Reassemble TFTP DATA opcodes into the original files."""

    name = "tftp_extractor"
    description = "Reassemble TFTP transfers"

    def run(self, packets: Sequence[Packet]) -> List[Evidence]:
        # key: (src_ip, dst_ip) of transfer; value: ordered chunks
        transfers: Dict[Tuple[str, str], Dict[int, bytes]] = defaultdict(dict)
        filenames: Dict[Tuple[str, str], str] = {}
        first_idx: Dict[Tuple[str, str], int] = {}

        for idx, pkt in enumerate(packets):
            if not (pkt.haslayer(UDP) and pkt.haslayer(IP) and pkt.haslayer(Raw)):
                continue
            u = pkt[UDP]
            if 69 not in (int(u.sport), int(u.dport)):
                continue
            data = bytes(pkt[Raw].load)
            if len(data) < 4:
                continue
            opcode = struct.unpack("!H", data[:2])[0]
            ip = pkt[IP]
            pair = tuple(sorted([str(ip.src), str(ip.dst)]))  # canonical key
            first_idx.setdefault(pair, idx)

            if opcode in (OP_RRQ, OP_WRQ):
                name = _parse_rwq(data)
                if name:
                    filenames[pair] = name
            elif opcode == OP_DATA:
                block = struct.unpack("!H", data[2:4])[0]
                payload = data[4:]
                transfers[pair][block] = payload

        findings: List[Evidence] = []
        out_root: Optional[Path] = None
        if self.ctx is not None:
            out_root = Path(self.ctx.output_dir) / "objects" / "tftp"
            out_root.mkdir(parents=True, exist_ok=True)

        for pair, chunks in transfers.items():
            ordered = b"".join(chunks[k] for k in sorted(chunks))
            if not ordered:
                continue
            digest = sha256_bytes(ordered)
            saved_path = ""
            name = filenames.get(pair, f"{digest[:16]}.bin")
            safe_name = name.replace("/", "_").replace("\\", "_")
            if out_root is not None:
                saved_path = str(out_root / f"{digest[:16]}_{safe_name}")
                try:
                    with open(saved_path, "wb") as fp:
                        fp.write(ordered)
                except OSError:
                    saved_path = ""

            findings.append(
                Evidence(
                    type="tftp_object",
                    severity=Severity.MEDIUM,
                    packet_offset=first_idx.get(pair, -1),
                    source_ip=pair[0],
                    dest_ip=pair[1],
                    payload_hash=digest,
                    details={
                        "filename": name,
                        "size_bytes": len(ordered),
                        "saved_to": saved_path,
                        "block_count": len(chunks),
                    },
                )
            )
        return findings
