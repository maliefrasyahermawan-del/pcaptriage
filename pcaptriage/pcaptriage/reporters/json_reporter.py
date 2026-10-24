"""Render the case file as machine-readable JSON."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict

from pcaptriage.core.evidence import EvidenceStore
from pcaptriage.core.loader import PcapMetadata


class JsonReporter:
    """JSON output reporter (SIEM-friendly)."""

    extension = "json"

    def render(self, store: EvidenceStore, meta: PcapMetadata,
               out_dir: Path) -> Path:
        """Write ``report.json`` and return its path."""
        payload: Dict[str, Any] = {
            "schema": "pcaptriage/v1",
            "capture": {
                "path": meta.path,
                "size_bytes": meta.size_bytes,
                "sha256": meta.sha256,
                "format": meta.format,
                "packet_count": meta.packet_count,
                "duration_seconds": meta.duration_seconds,
                "first_timestamp": meta.first_timestamp,
                "last_timestamp": meta.last_timestamp,
            },
            "severity_counts": store.by_severity(),
            "findings_total": len(store),
            "findings": [e.to_dict() for e in store.all()],
        }
        out_path = out_dir / "report.json"
        out_path.write_text(json.dumps(payload, indent=2, default=str),
                            encoding="utf-8")
        return out_path
