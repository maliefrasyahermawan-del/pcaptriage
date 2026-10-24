"""Analyzer plugins."""

from pcaptriage.analyzers.artifact_search import ArtifactSearchAnalyzer
from pcaptriage.analyzers.base import AnalyzerBase, AnalyzerContext
from pcaptriage.analyzers.http_extractor import HttpExtractorAnalyzer
from pcaptriage.analyzers.string_hunter import StringHunterAnalyzer
from pcaptriage.analyzers.summary import SummaryAnalyzer
from pcaptriage.analyzers.talkers import TalkersAnalyzer
from pcaptriage.analyzers.tftp_extractor import TftpExtractorAnalyzer

__all__ = [
    "AnalyzerBase",
    "AnalyzerContext",
    "SummaryAnalyzer",
    "TalkersAnalyzer",
    "HttpExtractorAnalyzer",
    "TftpExtractorAnalyzer",
    "StringHunterAnalyzer",
    "ArtifactSearchAnalyzer",
    "DEFAULT_ANALYZERS",
]


DEFAULT_ANALYZERS = [
    SummaryAnalyzer,
    TalkersAnalyzer,
    StringHunterAnalyzer,
    ArtifactSearchAnalyzer,
    HttpExtractorAnalyzer,
    TftpExtractorAnalyzer,
]
