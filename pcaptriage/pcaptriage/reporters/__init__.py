"""Multi-format reporters."""

from pcaptriage.reporters.csv_reporter import CsvReporter
from pcaptriage.reporters.html_reporter import HtmlReporter
from pcaptriage.reporters.json_reporter import JsonReporter
from pcaptriage.reporters.markdown_reporter import MarkdownReporter
from pcaptriage.reporters.text_reporter import TextReporter

__all__ = [
    "JsonReporter",
    "CsvReporter",
    "HtmlReporter",
    "MarkdownReporter",
    "TextReporter",
    "REPORTERS",
]


REPORTERS = {
    "json": JsonReporter,
    "csv": CsvReporter,
    "html": HtmlReporter,
    "md": MarkdownReporter,
    "txt": TextReporter,
}
