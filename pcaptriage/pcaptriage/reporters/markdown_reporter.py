"""Render findings as a Markdown IR report."""

from __future__ import annotations

import json
from pathlib import Path

from pcaptriage.core.evidence import EvidenceStore
from pcaptriage.core.loader import PcapMetadata


class MarkdownReporter:
    """Markdown reporter, suitable for embedding in IR tickets."""

    extension = "md"

    def render(self, store: EvidenceStore, meta: PcapMetadata,
               out_dir: Path) -> Path:
        out_path = out_dir / "report.md"
        lines = []
        lines.append(f"# PCAPTriage Report — `{Path(meta.path).name}`\n")
        lines.append("## Capture\n")
        lines.append(f"- **Path**: `{meta.path}`")
        lines.append(f"- **Size**: {meta.size_bytes:,} bytes")
        lines.append(f"- **SHA-256**: `{meta.sha256}`")
        lines.append(f"- **Format**: {meta.format}")
        lines.append(f"- **Packets**: {meta.packet_count}")
        lines.append(f"- **Duration**: {meta.duration_seconds:.3f} s\n")

        lines.append("## Severity counts\n")
        for sev, count in store.by_severity().items():
            lines.append(f"- **{sev}**: {count}")
        lines.append("")

        lines.append("## Findings\n")
        for ev in store.all():
            lines.append(f"### `{ev.type}` — {ev.severity.value}")
            lines.append(f"- packet_offset: {ev.packet_offset}")
            if ev.source_ip or ev.dest_ip:
                lines.append(f"- {ev.source_ip} → {ev.dest_ip}")
            if ev.payload_hash:
                lines.append(f"- sha256: `{ev.payload_hash}`")
            lines.append("```json")
            lines.append(json.dumps(ev.details, indent=2, default=str))
            lines.append("```")
            lines.append("")

        out_path.write_text("\n".join(lines), encoding="utf-8")
        return out_path
