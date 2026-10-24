"""Smoke tests: load sample PCAP, run analyzers, verify CTF flag detected."""

from __future__ import annotations

from pathlib import Path

from pcaptriage.analyzers import (DEFAULT_ANALYZERS, StringHunterAnalyzer)
from pcaptriage.analyzers.base import AnalyzerContext
from pcaptriage.core.evidence import EvidenceStore
from pcaptriage.core.loader import PcapLoader
from pcaptriage.reporters import REPORTERS


def test_loader_metadata(sample_pcap: Path):
    loader = PcapLoader(sample_pcap)
    meta = loader.metadata()
    assert meta.format == "pcap"
    assert meta.sha256 and len(meta.sha256) == 64


def test_string_hunter_finds_flag(sample_pcap: Path, tmp_path: Path):
    loader = PcapLoader(sample_pcap)
    packets = loader.load_all()
    ctx = AnalyzerContext(output_dir=tmp_path, pcap_path=sample_pcap)
    hunter = StringHunterAnalyzer(ctx=ctx)
    findings = hunter.run(packets)
    flags = [f for f in findings if f.type == "ctf_flag"]
    assert flags, "expected at least one CTF flag finding"
    assert "CTF{test_flag_12345}" in flags[0].details["flag"]


def test_full_pipeline_writes_reports(sample_pcap: Path, tmp_path: Path):
    loader = PcapLoader(sample_pcap)
    meta = loader.metadata()
    packets = loader.load_all()
    ctx = AnalyzerContext(output_dir=tmp_path, pcap_path=sample_pcap)
    store = EvidenceStore()
    for cls in DEFAULT_ANALYZERS:
        items = cls(ctx=ctx).run(packets)
        assert isinstance(items, list)
        store.extend(items)
    assert len(store) > 0

    for name, cls in REPORTERS.items():
        path = cls().render(store, meta, tmp_path)
        assert path.exists()
        assert path.stat().st_size > 0
