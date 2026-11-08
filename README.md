
🛡️ SentinelX

Modular Security Assessment Platform

Scan → Normalize → Aggregate → Prioritize → Report

A Python CLI framework that brings Nmap, Nikto, and Nuclei into one unified security assessment workflow.








📌 Overview

SentinelX is a modular command-line security assessment framework designed to orchestrate multiple security tools through a common workflow.

It currently integrates:

🔍 Nmap — network and service discovery

🕸️ Nikto — web server security testing

🧬 Nuclei — template-based vulnerability detection

SentinelX converts scanner-specific output into a common Finding model, aggregates results, performs exact-key deduplication, normalizes severity, prioritizes findings, and generates TXT/JSON reports.

One target. Multiple scanners. One unified result.

🎯 Why SentinelX?

Security scanners are powerful, but they do not produce identical data.

Each tool has its own:

command-line interface

output format

target requirements

finding identifiers

severity terminology

SentinelX provides a lightweight orchestration and normalization layer above these tools.

       Nmap             Nikto             Nuclei
         │                 │                 │
         └─────────────────┼─────────────────┘
                           │
                           ▼
                    Finding Conversion
                           │
                           ▼
                  Unified Finding Model
                           │
                           ▼
                    Result Aggregation
                           │
                           ▼
                 Severity + Prioritization
                           │
                           ▼
                     TXT / JSON Reports

The objective is not to replace the underlying security tools.

The objective is to make their results easier to orchestrate, standardize, process, and report.

🚀 Current Capabilities

Capability

Status

Nmap integration

✅ Implemented

Nikto integration

✅ Implemented

Nuclei integration

✅ Implemented

Nmap scan profiles

✅ Implemented

Nikto scan profiles

✅ Implemented

Full Security Scan

✅ Implemented

Target normalization

✅ Implemented

Common Finding model

✅ Implemented

Finding conversion

✅ Implemented

Multi-scanner aggregation

✅ Implemented

Exact-key deduplication

✅ Implemented

Severity normalization

✅ Implemented

Severity-based prioritization

✅ Implemented

TXT reporting

✅ Implemented

JSON reporting

✅ Implemented

Scan history

✅ Implemented

Operational logging

✅ Implemented

Automated test suite

🚧 Planned

Web dashboard

🚧 Planned

PDF / HTML reporting

🚧 Planned

Cross-scanner correlation

🚧 Planned

Parallel scanner execution

🚧 Planned

OWASP ZAP integration

🚧 Planned

🔍 Scanner Integrations

Scanner

Primary Purpose

SentinelX Usage

Status

Nmap

Network and service discovery

Host, port, service/version and OS scanning

✅

Nikto

Web server security testing

Web server assessment against URLs

✅

Nuclei

Template-based vulnerability detection

Template-based vulnerability scanning against URLs

✅

Nmap Profiles

quick
service
os
aggressive
full

Nikto Profiles

basic
ssl
redirects
info
injection

Nuclei

Nuclei currently runs through the integrated JSON Lines workflow:

nuclei -u <target> -jsonl

🏗️ Architecture

SentinelX has two execution paths.

Single-Scanner Mode

Menu options 1, 2, and 3 run one scanner directly against the user-supplied target.

User
 │
 ├──► Nmap
 ├──► Nikto
 └──► Nuclei

Full Security Scan

Menu option 4 runs the complete multi-scanner workflow.

                         ┌───────────────┐
                         │     Target    │
                         └───────┬───────┘
                                 │
                                 ▼
                     ┌─────────────────────┐
                     │  Target Normalizer  │
                     │                     │
                     │ nmap_target         │
                     │ web_target          │
                     └──────────┬──────────┘
                                │
                                ▼
                     ┌─────────────────────┐
                     │  Scan Orchestrator  │
                     └──────────┬──────────┘
                                │
                 ┌──────────────┼──────────────┐
                 │              │              │
                 ▼              ▼              ▼
             ┌───────┐      ┌───────┐      ┌────────┐
             │ Nmap  │      │ Nikto │      │ Nuclei │
             └───┬───┘      └───┬───┘      └───┬────┘
                 │              │              │
                 └──────────────┼──────────────┘
                                ▼
                    Parser + Finding Converter
                                │
                                ▼
                     ┌─────────────────────┐
                     │  Result Aggregator  │
                     └──────────┬──────────┘
                                │
                                ▼
                     ┌─────────────────────┐
                     │   Finding Manager   │
                     │  Exact-key dedup    │
                     └──────────┬──────────┘
                                │
                                ▼
                     ┌─────────────────────┐
                     │   Finding Summary   │
                     │ Counts + Priority   │
                     └──────────┬──────────┘
                                │
                         ┌──────┴──────┐
                         ▼             ▼
                    JSON Report    TXT Report
                         │             │
                         └──────┬──────┘
                                ▼
                    History + Operational Log

Execution model: the three scanners currently execute sequentially during a Full Security Scan. No threading or asynchronous scanner execution is currently implemented.

🧩 Core Components

Component

Location

Responsibility

Target Normalizer

core/target_normalizer.py

Converts raw input into an Nmap-friendly host and normalized web URL

Scanner Manager

core/scanner_manager.py

Registers scanner instances and dispatches scan requests

Scan Orchestrator

core/scan_orchestrator.py

Coordinates the Full Security Scan and executes scanners in sequence

Finding

core/finding.py

Defines the standardized security finding model

Finding Manager

core/finding_manager.py

Stores findings and performs exact-key deduplication

Result Aggregator

core/result_aggregator.py

Combines results from multiple scanners

Severity Normalizer

core/severity_normalizer.py

Maps raw severity values into SentinelX's five-level scale

Finding Summary

core/finding_summary.py

Calculates severity counts and prioritizes findings

JSON Reporter

reporter/json_report.py

Writes machine-readable JSON reports

TXT Reporter

reporter/txt_report.py

Writes human-readable scanner/full-scan reports

Scan History

history/scan_history.py

Persists scan summaries across sessions

Scan Logger

logger/scan_logger.py

Records operational scan information

CLI Formatter

formatter/cli_formatter.py

Handles menus and formatted CLI output

📋 Finding Model

SentinelX uses a common Finding dataclass so scanner-specific output can be processed consistently.

Finding(
    scanner,
    target,
    finding_id,
    title,
    severity,
    description,
    evidence,
    recommendation
)

Field

Purpose

scanner

Scanner that produced the finding

target

Target associated with the finding

finding_id

Scanner-specific identifier

title

Short finding title

severity

Normalized severity

description

Finding description

evidence

Supporting scan evidence

recommendation

Suggested remediation

This common representation prevents the aggregation and reporting layers from needing separate data structures for every scanner.

🔄 Finding Processing Pipeline

Raw Scanner Output
        │
        ▼
Tool-Specific Parser
        │
        ▼
Finding Converter
        │
        ▼
Severity Normalization
        │
        ▼
Standard Finding
        │
        ▼
Result Aggregation
        │
        ▼
Exact-Key Deduplication
        │
        ▼
Severity-Based Prioritization
        │
        ▼
Finding Summary
        │
        ├──────────────┐
        ▼              ▼
     JSON             TXT

⚖️ Severity Model

SentinelX standardizes findings into:

Critical
High
Medium
Low
Info

The severity normalizer handles common severity representations and falls back to Info when a severity is missing, empty, or unknown.

Current Scanner Behavior

Scanner

Current Severity Behavior

Nmap

Findings currently normalize to Info

Nikto

Findings currently normalize to Info

Nuclei

Uses severity supplied by Nuclei templates

Improving scanner-specific severity mapping is planned future work.

🧹 Deduplication vs. Correlation

SentinelX currently performs exact-key deduplication, not advanced cross-scanner correlation.

The current deduplication key is:

(scanner, target, finding_id)

If the same scanner reports the same finding ID for the same target, SentinelX can identify the repeated finding as a duplicate.

This is different from cross-scanner correlation.

For example:

Nmap
  └── Port 443 detected
          +
Nuclei
  └── HTTPS vulnerability detected
          ↓
Cross-scanner correlation

SentinelX does not currently infer that these findings describe the same underlying exposure.

Cross-scanner correlation is planned.

📊 Reporting

SentinelX currently supports two report formats.

JSON Reports

Machine-readable output containing the combined result structure.

reports/
└── sentinalx_scan_report_<timestamp>.json

TXT Reports

Human-readable output with scanner-specific layouts and a combined SentinelX report.

reports/
└── sentinalx_report_<timestamp>.txt

The reporting layer is intentionally separated from scanner execution so that additional output formats can be added later without changing scanner implementations.

PDF and HTML reporting are not currently implemented.

🗂️ Project Structure

SentinelX/
│
├── .github/
├── backend/
│
├── core/
│   ├── finding.py
│   ├── finding_manager.py
│   ├── finding_summary.py
│   ├── result_aggregator.py
│   ├── scanner_manager.py
│   ├── scan_orchestrator.py
│   ├── severity_normalizer.py
│   └── target_normalizer.py
│
├── docs/
│   └── engineering_journal.md
│
├── formatter/
│   └── cli_formatter.py
│
├── history/
│   └── scan_history.py
│
├── logger/
│   ├── scan_logger.py
│   └── __init__.py
│
├── reporter/
│   ├── json_report.py
│   ├── txt_report.py
│   └── init__.py
│
├── scanners/
│   ├── nmap/
│   │   ├── finding_converter.py
│   │   ├── nmap_scanner.py
│   │   └── parser.py
│   │
│   ├── Nikto/
│   │   ├── finding_converter.py
│   │   ├── nikto_scanner.py
│   │   ├── parser.py
│   │   └── __init__.py
│   │
│   └── nuclei/
│       ├── finding_converter.py
│       ├── nuclei_scanner.py
│       ├── parser.py
│       └── __init__.py
│
├── scripts/
│   └── test_nmap.py
│
├── tests/
├── logs/
├── reports/
│
├── main.py
├── test.py
├── .gitignore
├── README.md
└── LICENSE

🛠️ Technologies & Tools

Language

Python 3.11+

Security Tools

Nmap

Nikto

Nuclei

Python Dependencies

SentinelX currently relies on the Python standard library.

Examples include:

subprocess
json
os
re
time
datetime
dataclasses
urllib.parse
typing

There is currently no requirements.txt, setup.py, or pyproject.toml.

External security tools must be installed separately and available through the system PATH.

⚙️ Installation

Requirements

Python 3.11+

Nmap

Nikto

Nuclei

Verify the tools from your terminal:

python --version
nmap --version
nikto -Version
nuclei -version

Setup

git clone <repository-url>
cd SentinelX
python main.py

SentinelX currently does not require a Python package installation step.

Installation commands for Nmap, Nikto, and Nuclei vary by operating system.

🖥️ Usage

Start SentinelX:

python main.py

The current interactive CLI provides:

1. Nmap Scanner
2. Nikto
3. Nuclei
4. Full Security Scan
5. Scan History
0. Exit

Individual Scanners

Options 1–3 allow you to run Nmap, Nikto, or Nuclei independently.

Full Security Scan

Option 4 runs:

Target
  ↓
Nmap
  ↓
Nikto
  ↓
Nuclei
  ↓
Aggregation
  ↓
Prioritization
  ↓
TXT + JSON Reports

The scanners currently execute sequentially.

Scan History

Option 5 displays previously recorded scan history.

Exit

Option 0 exits the application.

🧪 Testing

SentinelX does not yet have an automated test suite.

The repository currently contains manual development/smoke-test scripts:

test.py
scripts/test_nmap.py

These scripts are used for development verification and are not a replacement for formal automated test coverage.

Automated testing is part of the roadmap.

⚠️ Known Limitations

Current limitations include:

Nmap findings currently default to Info severity.

Nikto findings currently default to Info severity.

Nuclei scans can be long-running depending on target and template set.

Full Security Scan executes scanners sequentially.

No automated test suite yet.

No web dashboard.

No PDF/HTML reporting.

No OWASP ZAP integration.

Deduplication is exact-key based.

Cross-scanner correlation is not implemented.

TXT report paths are not completely standardized.

No formal Python packaging metadata.

These limitations are documented because SentinelX is an actively evolving engineering project.

🧠 Engineering Decisions

Modular Scanner Design

Scanner implementations are isolated under scanners/.

This keeps tool-specific command construction and parsing away from the core workflow.

Parser / Converter Separation

Each scanner follows the general pattern:

Raw Tool Output
      ↓
Parser
      ↓
Parsed Data
      ↓
Finding Converter
      ↓
Standard Finding

This prevents scanner-specific output formats from leaking into the rest of the application.

Common Finding Contract

All scanner findings are converted into the same Finding structure.

This makes aggregation, deduplication, prioritization, and reporting scanner-independent.

Scanner Manager vs. Orchestrator

ScannerManager handles scanner registration and dispatch.

ScanOrchestrator handles the complete multi-scanner workflow.

This keeps scanner management separate from workflow coordination.

Aggregation vs. Finding Management

ResultAggregator combines results.

FindingManager handles finding storage and duplicate detection.

This separation keeps data aggregation and duplicate handling as independent responsibilities.

Dedicated Reporting Layer

Scanners produce results; reporters determine how those results are presented.

This makes the reporting layer easier to extend with future formats.

🗺️ Roadmap

Near Term

Improve Nmap severity mapping

Improve Nikto severity mapping

Add automated tests

Improve CLI usability

Standardize report paths

Improve validation and error handling

Future

Additional scanner integrations

Cross-scanner finding correlation

Parallel scanner execution

Web-based security dashboard

PDF reporting

HTML reporting

Configurable scan profiles

Formal Python packaging

🔐 Security & Legal Disclaimer

SentinelX is intended only for authorized security testing.

Use it only against:

systems you own

systems you have explicit permission to assess

controlled laboratory environments

authorized security-training targets

Do not use SentinelX to scan systems without authorization.

You are responsible for complying with all applicable laws, policies, and rules governing security testing in your environment.

🤝 Contributing

SentinelX is currently in active development.

Bug reports, suggestions, architectural feedback, and contributions are welcome.

When adding a new scanner, follow the existing modular scanner architecture and keep scanner-specific parsing and finding conversion isolated from the core processing pipeline.

🛡️ SentinelX

Scan. Normalize. Aggregate. Prioritize. Report.

Built as a hands-on security engineering project.

📄 License

SentinelX is licensed under the MIT License.
See the [LICENSE](LICENSE) file for details.#   S e n t i n a l - X  
 