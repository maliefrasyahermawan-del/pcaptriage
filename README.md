# PCAPTriage

> An offline command-line assistant for rapid forensic triage of PCAP and PCAPNG network captures.

## What this project does

PCAPTriage helps SOC analysts, incident responders, CTF players, and network-forensics learners answer a first-response question: **what is inside this network capture?** It analyzes traffic locally, records evidence, identifies suspicious artifacts, extracts transferable objects, and produces reports without requiring a GUI packet-analysis workflow.

## Core functions

- Summarize packets, protocols, top talkers, and capture duration.
- Search for indicators such as URLs, email addresses, JWTs, HTTP basic authentication, credentials, cookies, and CTF flags.
- Extract HTTP responses and TFTP transfers.
- Record findings with timestamps, packet offsets, and SHA-256 evidence data.
- Export results as CLI output, JSON, CSV, HTML, Markdown, or plain text.

## Architecture

```text
PCAP / PCAPNG
  │
  ▼
CLI command layer
  │
  ▼
Capture loader and evidence layer
  │
  ├── Summary and protocol analyzers
  ├── Talker, string, and artifact analyzers
  ├── HTTP and TFTP extractors
  └── Finding/evidence normalization
  │
  ▼
Reporters → CLI | JSON | CSV | HTML | Markdown | text
```

## Technology

- Python 3.10+
- Scapy and dpkt for packet analysis
- Click and Rich for the command-line experience
- Jinja2 for HTML reporting

## Run locally

```bash
cd pcaptriage
python -m venv .venv
.venv\Scripts\activate
pip install -e .

pcaptriage analyze capture.pcap --output ./report --format all
pcaptriage extract capture.pcap --type all --output ./objects
pcaptriage hunt capture.pcap --pattern all --output ./hunt
```

## Repository layout

```text
pcaptriage/
├── pcaptriage/        # CLI, analyzers, evidence core, and reporters
├── tests/             # Automated tests and generated fixtures
├── examples/          # Usage material
└── pyproject.toml     # Package metadata and dependencies
```

## Safety note

Use only packet captures you are authorized to inspect. Captures may contain personal data, credentials, or other sensitive content; this repository intentionally ignores raw capture files and generated reports by default.
