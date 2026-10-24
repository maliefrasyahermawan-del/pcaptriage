"""PCAP/PCAPNG loader with magic-byte validation."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, List, Optional, Union

from scapy.all import PcapReader, rdpcap
from scapy.packet import Packet

from pcaptriage.core.hashing import sha256_file


PCAP_MAGIC = {b"\xa1\xb2\xc3\xd4", b"\xd4\xc3\xb2\xa1",
              b"\xa1\xb2\x3c\x4d", b"\x4d\x3c\xb2\xa1"}
PCAPNG_MAGIC = {b"\x0a\x0d\x0d\x0a"}


@dataclass
class PcapMetadata:
    """Metadata about the loaded capture file."""

    path: str
    size_bytes: int
    sha256: str
    format: str  # "pcap" | "pcapng"
    packet_count: int = 0
    duration_seconds: float = 0.0
    first_timestamp: Optional[float] = None
    last_timestamp: Optional[float] = None


class PcapLoader:
    """Validate, hash and load a capture file into memory.

    Heavy captures should call :meth:`stream` to iterate without loading
    everything; :meth:`load_all` is convenient for small captures and tests.
    """

    def __init__(self, path: Union[str, Path]) -> None:
        self.path = Path(path)
        if not self.path.exists():
            raise FileNotFoundError(f"PCAP not found: {self.path}")
        if not self.path.is_file():
            raise ValueError(f"Not a regular file: {self.path}")
        self._meta: Optional[PcapMetadata] = None

    def validate(self) -> str:
        """Check magic bytes and return capture format.

        Returns:
            ``"pcap"`` or ``"pcapng"``.

        Raises:
            ValueError: If the file's header does not look like a capture.
        """
        with open(self.path, "rb") as fp:
            head = fp.read(4)
        if head in PCAP_MAGIC:
            return "pcap"
        if head in PCAPNG_MAGIC:
            return "pcapng"
        raise ValueError(
            f"Unrecognized capture magic bytes {head!r} in {self.path}"
        )

    def metadata(self) -> PcapMetadata:
        """Compute metadata (hash, format, size). Cached after first call."""
        if self._meta is not None:
            return self._meta
        fmt = self.validate()
        self._meta = PcapMetadata(
            path=str(self.path.resolve()),
            size_bytes=self.path.stat().st_size,
            sha256=sha256_file(self.path),
            format=fmt,
        )
        return self._meta

    def load_all(self) -> List[Packet]:
        """Load every packet into a Python list (uses scapy.rdpcap)."""
        pkts: List[Packet] = list(rdpcap(str(self.path)))
        meta = self.metadata()
        meta.packet_count = len(pkts)
        if pkts:
            ts_first = float(pkts[0].time)
            ts_last = float(pkts[-1].time)
            meta.first_timestamp = ts_first
            meta.last_timestamp = ts_last
            meta.duration_seconds = max(0.0, ts_last - ts_first)
        return pkts

    def stream(self) -> Iterator[Packet]:
        """Yield packets one by one using scapy.PcapReader."""
        with PcapReader(str(self.path)) as rdr:
            for pkt in rdr:
                yield pkt
