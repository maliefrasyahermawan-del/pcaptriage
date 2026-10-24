"""Click-based command-line interface for pcaptriage."""

from __future__ import annotations

import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import List, Sequence, Type

import click
from rich.console import Console
from rich.progress import (BarColumn, Progress, SpinnerColumn, TextColumn,
                           TimeElapsedColumn)
from rich.table import Table
from scapy.packet import Packet

from pcaptriage import __version__
from pcaptriage.analyzers import (DEFAULT_ANALYZERS, ArtifactSearchAnalyzer,
                                  HttpExtractorAnalyzer, StringHunterAnalyzer,
                                  TftpExtractorAnalyzer)
from pcaptriage.analyzers.base import AnalyzerBase, AnalyzerContext
from pcaptriage.core.evidence import EvidenceStore, Severity
from pcaptriage.core.loader import PcapLoader
from pcaptriage.reporters import REPORTERS


console = Console()


SEV_STYLE = {
    "CRITICAL": "bold white on red",
    "HIGH": "bold red",
    "MEDIUM": "yellow",
    "LOW": "cyan",
    "INFO": "dim",
}


def _run_analyzers(analyzers: Sequence[AnalyzerBase],
                   packets: Sequence[Packet]) -> EvidenceStore:
    store = EvidenceStore()
    with Progress(
        SpinnerColumn(),
        TextColumn("[bold]{task.description}"),
        BarColumn(),
        TextColumn("{task.completed}/{task.total}"),
        TimeElapsedColumn(),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task("Running analyzers", total=len(analyzers))
        with ThreadPoolExecutor(max_workers=min(8, len(analyzers))) as pool:
            futures = {pool.submit(a.run, packets): a for a in analyzers}
            for fut in as_completed(futures):
                analyzer = futures[fut]
                try:
                    items = fut.result()
                    store.extend(items)
                except Exception as exc:  # noqa: BLE001
                    console.print(
                        f"[red]Analyzer {analyzer.name} failed:[/red] {exc}"
                    )
                progress.advance(task)
    return store


def _print_summary(store: EvidenceStore) -> None:
    counts = store.by_severity()
    table = Table(title="Findings summary", show_header=True,
                  header_style="bold cyan")
    table.add_column("Severity")
    table.add_column("Count", justify="right")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        table.add_row(f"[{SEV_STYLE[sev]}]{sev}[/]", str(counts[sev]))
    console.print(table)

    findings = store.all()
    if findings:
        ftable = Table(title="Top findings", show_header=True,
                       header_style="bold cyan")
        ftable.add_column("Sev")
        ftable.add_column("Type")
        ftable.add_column("Pkt", justify="right")
        ftable.add_column("Src")
        ftable.add_column("Dst")
        ftable.add_column("Preview", overflow="fold")
        for ev in findings[:15]:
            preview = str(ev.details).replace("\n", " ")
            if len(preview) > 80:
                preview = preview[:77] + "..."
            ftable.add_row(
                f"[{SEV_STYLE[ev.severity.value]}]{ev.severity.value}[/]",
                ev.type,
                str(ev.packet_offset),
                ev.source_ip or "-",
                ev.dest_ip or "-",
                preview,
            )
        console.print(ftable)


def _instantiate(classes: Sequence[Type[AnalyzerBase]],
                 ctx: AnalyzerContext) -> List[AnalyzerBase]:
    return [cls(ctx=ctx) for cls in classes]


@click.group()
@click.version_option(__version__, prog_name="pcaptriage")
def main() -> None:
    """PCAPTriage — offline triage assistant for PCAP/PCAPNG."""


@main.command()
@click.argument("pcap_file", type=click.Path(exists=True, dir_okay=False))
@click.option("--output", "-o", required=True,
              type=click.Path(file_okay=False),
              help="Output directory.")
@click.option("--format", "-f", "fmt",
              type=click.Choice(["json", "csv", "html", "md", "txt", "all"]),
              default="all", show_default=True,
              help="Report format(s).")
def analyze(pcap_file: str, output: str, fmt: str) -> None:
    """Run all analyzers and emit reports for PCAP_FILE."""
    out_dir = Path(output)
    out_dir.mkdir(parents=True, exist_ok=True)

    loader = PcapLoader(pcap_file)
    meta = loader.metadata()
    console.print(f"[cyan]Loading[/cyan] {pcap_file} ({meta.format}, "
                  f"{meta.size_bytes:,} bytes)")
    packets = loader.load_all()
    console.print(f"[green]Loaded[/green] {len(packets)} packets")

    ctx = AnalyzerContext(output_dir=out_dir, pcap_path=Path(pcap_file))
    analyzers = _instantiate(DEFAULT_ANALYZERS, ctx)
    store = _run_analyzers(analyzers, packets)

    formats = ["json", "csv", "html", "md", "txt"] if fmt == "all" else [fmt]
    for f in formats:
        reporter = REPORTERS[f]()
        path = reporter.render(store, meta, out_dir)
        console.print(f"[green]Wrote[/green] {path}")

    _print_summary(store)

    counts = store.by_severity()
    has_finding = any(
        counts[s] > 0 for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
    )
    sys.exit(1 if has_finding else 0)


@main.command()
@click.argument("pcap_file", type=click.Path(exists=True, dir_okay=False))
@click.option("--type", "-t", "kind",
              type=click.Choice(["http", "tftp", "all"]),
              default="all", show_default=True)
@click.option("--output", "-o", required=True,
              type=click.Path(file_okay=False))
def extract(pcap_file: str, kind: str, output: str) -> None:
    """Extract HTTP/TFTP transferred objects from PCAP_FILE."""
    out_dir = Path(output)
    out_dir.mkdir(parents=True, exist_ok=True)
    loader = PcapLoader(pcap_file)
    meta = loader.metadata()
    packets = loader.load_all()

    ctx = AnalyzerContext(output_dir=out_dir, pcap_path=Path(pcap_file))
    selected: List[Type[AnalyzerBase]] = []
    if kind in ("http", "all"):
        selected.append(HttpExtractorAnalyzer)
    if kind in ("tftp", "all"):
        selected.append(TftpExtractorAnalyzer)

    store = _run_analyzers(_instantiate(selected, ctx), packets)
    REPORTERS["json"]().render(store, meta, out_dir)
    console.print(f"[green]Extracted[/green] {len(store)} objects to {out_dir}")
    sys.exit(0 if len(store) else 1)


@main.command()
@click.argument("pcap_file", type=click.Path(exists=True, dir_okay=False))
@click.option("--pattern", "-p",
              type=click.Choice(["ctf", "creds", "all"]),
              default="all", show_default=True)
@click.option("--output", "-o",
              type=click.Path(file_okay=False),
              default="./pcap_hunt_out", show_default=True)
def hunt(pcap_file: str, pattern: str, output: str) -> None:
    """Hunt for CTF flags, credentials and embedded secrets."""
    out_dir = Path(output)
    out_dir.mkdir(parents=True, exist_ok=True)
    loader = PcapLoader(pcap_file)
    meta = loader.metadata()
    packets = loader.load_all()

    ctx = AnalyzerContext(output_dir=out_dir, pcap_path=Path(pcap_file))
    selected: List[Type[AnalyzerBase]] = []
    if pattern in ("ctf", "all"):
        selected.append(StringHunterAnalyzer)
    if pattern in ("creds", "all"):
        selected.append(ArtifactSearchAnalyzer)

    store = _run_analyzers(_instantiate(selected, ctx), packets)
    REPORTERS["json"]().render(store, meta, out_dir)
    REPORTERS["txt"]().render(store, meta, out_dir)
    _print_summary(store)
    sys.exit(1 if len(store) else 0)


if __name__ == "__main__":
    main()
