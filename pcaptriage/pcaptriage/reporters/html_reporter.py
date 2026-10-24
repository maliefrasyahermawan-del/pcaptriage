"""Render an interactive HTML report via Jinja2."""

from __future__ import annotations

import json
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from pcaptriage.core.evidence import EvidenceStore
from pcaptriage.core.loader import PcapMetadata


_TEMPLATE_DIR = Path(__file__).resolve().parent.parent / "templates"


class HtmlReporter:
    """Standalone HTML report with client-side search and severity filter."""

    extension = "html"

    def __init__(self) -> None:
        self._env = Environment(
            loader=FileSystemLoader(str(_TEMPLATE_DIR)),
            autoescape=select_autoescape(["html", "j2"]),
        )

    def render(self, store: EvidenceStore, meta: PcapMetadata,
               out_dir: Path) -> Path:
        tpl = self._env.get_template("report.html.j2")
        findings = [e.to_dict() for e in store.all()]
        html = tpl.render(
            meta=meta,
            findings=findings,
            severity_counts=store.by_severity(),
            findings_json=json.dumps(findings, default=str),
        )
        out_path = out_dir / "report.html"
        out_path.write_text(html, encoding="utf-8")
        return out_path
