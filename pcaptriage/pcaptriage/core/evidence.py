"""Evidence record dataclass and in-memory store."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Dict, Iterable, List, Optional


class Severity(str, Enum):
    """Severity ranking for a finding."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def rank(self) -> int:
        order = {
            "CRITICAL": 5,
            "HIGH": 4,
            "MEDIUM": 3,
            "LOW": 2,
            "INFO": 1,
        }
        return order[self.value]


@dataclass
class Evidence:
    """Single triage finding.

    Attributes:
        type: Short machine slug, e.g. ``"ctf_flag"`` or ``"http_object"``.
        severity: One of :class:`Severity`.
        packet_offset: Zero-based packet index in the capture, or ``-1`` if N/A.
        timestamp: Epoch seconds of the source packet, or ``None``.
        source_ip: Source IP of the packet, or ``None``.
        dest_ip: Destination IP of the packet, or ``None``.
        payload_hash: SHA-256 of the artifact bytes (used for dedup).
        details: Free-form per-finding metadata.
    """

    type: str
    severity: Severity
    packet_offset: int = -1
    timestamp: Optional[float] = None
    source_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    payload_hash: str = ""
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize for JSON / template rendering."""
        out = asdict(self)
        out["severity"] = self.severity.value
        return out


class EvidenceStore:
    """In-memory collection of :class:`Evidence` with dedup + sort helpers."""

    def __init__(self) -> None:
        self._items: List[Evidence] = []
        self._seen_hashes: set[str] = set()

    def add(self, evidence: Evidence) -> bool:
        """Append an evidence record.

        Args:
            evidence: The record to add.

        Returns:
            ``True`` if added, ``False`` if a duplicate ``payload_hash`` was
            already present.
        """
        h = evidence.payload_hash
        if h and h in self._seen_hashes:
            return False
        if h:
            self._seen_hashes.add(h)
        self._items.append(evidence)
        return True

    def extend(self, items: Iterable[Evidence]) -> int:
        """Bulk-add records. Returns the number actually inserted."""
        count = 0
        for ev in items:
            if self.add(ev):
                count += 1
        return count

    def all(self) -> List[Evidence]:
        """Return all stored evidence sorted by severity then offset."""
        return sorted(
            self._items,
            key=lambda e: (-e.severity.rank, e.packet_offset),
        )

    def by_severity(self) -> Dict[str, int]:
        """Return a count of findings per severity bucket."""
        buckets = {s.value: 0 for s in Severity}
        for ev in self._items:
            buckets[ev.severity.value] += 1
        return buckets

    def __len__(self) -> int:
        return len(self._items)
