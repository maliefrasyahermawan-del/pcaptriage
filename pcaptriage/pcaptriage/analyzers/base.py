"""Abstract base class for all analyzers."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Sequence

from scapy.packet import Packet

from pcaptriage.core.evidence import Evidence


@dataclass
class AnalyzerContext:
    """Shared state passed to every analyzer.

    Attributes:
        output_dir: Working directory for extracted artifacts.
        pcap_path: Path to the source capture (for logging).
    """

    output_dir: Path
    pcap_path: Path
    extras: dict = field(default_factory=dict)


class AnalyzerBase(ABC):
    """Contract: each analyzer consumes packets and produces evidence."""

    name: str = "base"
    description: str = ""

    def __init__(self, ctx: Optional[AnalyzerContext] = None) -> None:
        self.ctx = ctx

    @abstractmethod
    def run(self, packets: Sequence[Packet]) -> List[Evidence]:
        """Analyze ``packets`` and return findings.

        Args:
            packets: All loaded packets, ordered by capture index.

        Returns:
            A list of :class:`Evidence`. May be empty.
        """
        raise NotImplementedError
