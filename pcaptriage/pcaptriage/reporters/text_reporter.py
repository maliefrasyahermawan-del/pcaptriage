"""Render findings as plain text."""

from __future__ import annotations

import json
from pathlib import Path

from pcaptriage.core.evidence import EvidenceStore
from pcaptriage.core.loader import PcapMetadata


class TextReporter:
    """Plain-text reporter for log redirection."""

    extension = "txt"

    def render(self, store: EvidenceStore, meta: PcapMetadata,
               out_dir: Path) -> Path:
        out_path = out_dir / "report.txt"
        lines = []
        lines.append(f"PCAPTriage Report - {Path(meta.path).name}")
        lines.append("=" * 60)
        lines.append(f"Path     : {meta.path}")
        lines.append(f"Size     : {meta.size_bytes} bytes")
        lines.append(f"SHA-256  : {meta.sha256}")
        lines.append(f"Format   : {meta.format}")
        lines.append(f"Packets  : {meta.packet_count}")
        lines.append(f"Duration : {meta.duration_seconds:.3f}s")
        lines.append("")
        lines.append("Severity counts:")
        for sev, count in store.by_severity().items():
            lines.append(f"  {sev:<10}: {count}")
        lines.append("")
        lines.append("Findings:")
        lines.append("-" * 60)
        for ev in store.all():
            lines.append(f"[{ev.severity.value:<8}] {ev.type} "
                         f"@pkt={ev.packet_offset} "
                         f"{ev.source_ip or '-'} -> {ev.dest_ip or '-'}")
            lines.append(f"  sha256: {ev.payload_hash}")
            lines.append("  details: " + json.dumps(ev.details, default=str))
            lines.append("")
        out_path.write_text("\n".join(lines), encoding="utf-8")
        return out_path
