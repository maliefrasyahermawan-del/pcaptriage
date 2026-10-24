"""Render findings as a flat CSV."""

from __future__ import annotations

import csv
import json
from pathlib import Path

from pcaptriage.core.evidence import EvidenceStore
from pcaptriage.core.loader import PcapMetadata


class CsvReporter:
    """CSV output reporter (one row per finding)."""

    extension = "csv"

    def render(self, store: EvidenceStore, meta: PcapMetadata,
               out_dir: Path) -> Path:
        out_path = out_dir / "report.csv"
        with open(out_path, "w", encoding="utf-8", newline="") as fp:
            w = csv.writer(fp)
            w.writerow([
                "type", "severity", "packet_offset", "timestamp",
                "source_ip", "dest_ip", "payload_hash", "details_json",
            ])
            for e in store.all():
                w.writerow([
                    e.type,
                    e.severity.value,
                    e.packet_offset,
                    e.timestamp or "",
                    e.source_ip or "",
                    e.dest_ip or "",
                    e.payload_hash,
                    json.dumps(e.details, default=str),
                ])
        return out_path
