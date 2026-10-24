# PCAPTriage

> Offline CLI for fast forensic triage of PCAP/PCAPNG captures.
> Built for **MBC Telkom University Lab** — SOC analysts, CTF players, and
> network forensics researchers.

`pcaptriage` answers the question *"what is in this capture?"* without making
you click through Wireshark. It runs a pipeline of pluggable analyzers, builds
a case-file of evidence with SHA-256 chain-of-custody, and writes a report in
JSON, CSV, HTML, Markdown or plain text.

---

## Features

- **Auto-summary** — packet count, protocol breakdown, top talkers, duration
- **Evidence records** — every finding has timestamp, packet offset, SHA-256
- **CTF helper** — built-in patterns for `CTF{}`, `FLAG{}`, `picoCTF{}`,
  `HTB{}`, `THM{}`, `MBC{}`
- **Object extraction** — reassemble HTTP responses (chunked + gzip/deflate)
  and TFTP transfers to disk
- **Artifact search** — emails, URLs, JWTs, HTTP basic auth, password params,
  AWS keys, cookies
- **Multi-format report** — JSON, CSV, interactive HTML (search + filter),
  Markdown, plain text
- **Forensics-friendly exit codes** — 0 = clean, 1 = findings, 2 = error

---

## Install

```bash
python -m venv .venv
.venv\Scripts\activate            # Windows
# source .venv/bin/activate       # macOS/Linux
pip install -e .
```

Python 3.10+ required.

---

## Commands

```bash
# Full triage with every reporter
pcaptriage analyze capture.pcap --output ./report --format all

# Extract HTTP and TFTP objects only
pcaptriage extract capture.pcap --type all --output ./objects

# Hunt CTF flags and credentials
pcaptriage hunt capture.pcap --pattern all --output ./hunt
```

### `analyze` output layout

```
report/
├── report.json     # SIEM-friendly
├── report.csv      # one row per finding
├── report.html     # interactive (open in any browser)
├── report.md       # paste-ready IR note
├── report.txt      # plain text
└── objects/
    ├── http/<sha16>.{html,jpg,bin,...}
    └── tftp/<sha16>_<filename>
```

---

## Sample output

```text
                   Findings summary
┏━━━━━━━━━━━━┳━━━━━━━┓
┃ Severity   ┃ Count ┃
┡━━━━━━━━━━━━╇━━━━━━━┩
│ CRITICAL   │     1 │
│ HIGH       │     0 │
│ MEDIUM     │    25 │
│ LOW        │     3 │
│ INFO       │     2 │
└────────────┴───────┘
```

*(screenshot placeholder — replace with real terminal capture for paper/demo)*

---

## Test

```bash
pip install -e ".[dev]"
pytest
```

`tests/conftest.py` generates `tests/fixtures/sample.pcap` (50 HTTP packets +
10 DNS, with an embedded `CTF{test_flag_12345}` planted in response #7).

---

## Roadmap

| Phase | Target                                                            |
| ----- | ----------------------------------------------------------------- |
| 1     | MVP (this repo)                                                   |
| 2     | ML anomaly scoring on per-flow features                           |
| 3     | Optional MISP / OpenCTI enrichment                                |
| 4     | Paper draft for Jurnal Sinta 3/2 + sample PCAP corpus for Telkom  |

---

## License

MIT — see `pyproject.toml`.
