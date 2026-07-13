# 🛡️ SOC Storyteller

![Python](https://img.shields.io/badge/Python-3.12-blue)
![Tests](https://img.shields.io/badge/Tests-152_Passing-success)
![Coverage](https://img.shields.io/badge/Coverage-94%25-brightgreen)
![License](https://img.shields.io/badge/License-MIT-green)

**Turning Windows Event Logs into Attack Narratives.**

SOC Storyteller parses Windows `.evtx` Security/System logs, detects
suspicious activity across 17 built-in detection rules, correlates
related detections into coherent **attack chains**, scores their risk,
maps them to **MITRE ATT&CK**, and writes the whole thing out as a
human-readable **attack story** --- in Markdown, HTML, JSON, or PDF.

It exists to answer the question every SOC analyst asks when a pile of
alerts lands in their queue: *"Ok, but what actually happened, in order,
and how bad is it?"*

    6 failed logons for 'jsmith' → successful logon → suspicious PowerShell →
    new local account 'svc_update' → added to Administrators → service +
    scheduled task persistence → lateral movement to SRV-DB01 → Security
    log cleared.

    Risk Score: 100/100 — CRITICAL

------------------------------------------------------------------------

## Table of Contents

-   [Features](#features)
-   [Architecture](#architecture)
-   [Installation](#installation)
-   [Quick Start](#quick-start)
-   [CLI Usage](#cli-usage)
-   [Web UI](#web-ui)
-   [Supported Event IDs](#supported-event-ids)
-   [Detection Rules](#detection-rules)
-   [MITRE ATT&CK Mapping](#mitre-attck-mapping)
-   [Risk Scoring Model](#risk-scoring-model)
-   [Report Formats](#report-formats)
-   [Project Structure](#project-structure)
-   [Testing](#testing)
-   [Extending SOC Storyteller](#extending-soc-storyteller)
-   [Limitations](#limitations)
-   [Contributing](#contributing)
-   [License](#license)

------------------------------------------------------------------------

## Features

-   📂 **EVTX parsing** --- reads real binary Windows `.evtx` files via
    [`python-evtx`](https://github.com/williballenthin/python-evtx).
-   🔎 **32 supported Windows Event IDs** across authentication, account
    management, process execution, persistence, and log tampering.
-   🧩 **17 detection rules** covering brute force, privilege
    escalation, persistence, lateral movement, credential theft, and
    anti-forensics.
-   🔗 **Correlation engine** that stitches related detections --- even
    across a *pivot* to a newly-created identity --- into a single
    attack chain.
-   📖 **Narrative generator** that writes a plain-English story of what
    happened, in chronological order, with zero hand-authored templates
    per-scenario.
-   📊 **Risk scoring engine** (0--100) with severity, technique
    diversity, and multi-stage bonuses.
-   🗺️ **MITRE ATT&CK mapping** for every detection rule.
-   🧑‍💻 **SOC analyst recommendations** --- concrete next steps per
    detection.
-   📄 **Four report formats**: Markdown, HTML, JSON, and PDF.
-   🖥️ **Optional web UI** (Streamlit) for drag-and-drop analysis.
-   ✅ **150+ unit/integration tests**, \~94% coverage.
-   🆓 **100% free/open-source dependencies.** No paid services, no
    cloud, no database.

## Architecture

SOC Storyteller is a straight-line pipeline. Each stage is an
independent, testable module that only depends on the shared data
contract in `utils/models.py` --- never on another stage's internals:

    .evtx file(s)
         │
         ▼
    ┌─────────────┐   Event      ┌──────────────┐  Detection   ┌───────────────┐
    │   parser/   │ ───────────▶ │ detections/  │ ───────────▶ │ correlation/  │
    │ EvtxParser  │              │ 17 rules     │              │ CorrelationEngine
    └─────────────┘              └──────────────┘              └───────┬───────┘
                                                                        │ AttackChain
                                                                        ▼
                                                             ┌──────────────────┐
                                                             │   risk_engine/   │
                                                             │  RiskCalculator  │
                                                             └────────┬─────────┘
                                                                      │ scored AttackChain
                                                                      ▼
                                                             ┌──────────────────┐
                                                             │    reports/      │
                                                             │ Narrative + MD/  │
                                                             │ HTML/JSON/PDF    │
                                                             └──────────────────┘

**Design principles applied throughout:**

-   **Single Responsibility** --- each module does exactly one job
    (parsing, detecting, correlating, scoring, narrating, reporting).
-   **Open/Closed** --- new detection rules or report formats are added
    by writing a new class, never by modifying existing ones.
-   **Dependency Inversion** --- every module depends only on the shared
    `Event` / `Detection` / `AttackChain` dataclasses in
    `utils/models.py`, never on another module's implementation.
-   **Strategy pattern** --- `DetectionRule` subclasses are pluggable
    strategies run by a generic `DetectionEngine`.

## Installation

Requires **Python 3.12+**.

``` bash
git clone https://github.com/mohamedahmede004/SOC-Storyteller.git
cd SOC-Storyteller
python3 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

All dependencies are free and open source (MIT/BSD-licensed):
`python-evtx`, `lxml`, `reportlab`, `streamlit` (UI only), `pytest`.

## Quick Start

No `.evtx` file handy? Run the bundled synthetic attack scenario --- a
realistic brute-force → privilege-escalation → persistence →
lateral-movement → log-clearing chain --- end to end in one command:

``` bash
python run_demo.py
```

This writes `output/demo_report.{md,html,json,pdf}` and prints the full
attack narrative to the console.

## CLI Usage

Analyze a real `.evtx` file:

``` bash
python main.py --input path/to/Security.evtx --format html --output output/incident
```

Analyze every `.evtx` file in a directory (e.g. logs collected from
multiple hosts) as a single correlated incident:

``` bash
python main.py --input-dir path/to/logs/ --format all --output output/incident
```

### Options

  -----------------------------------------------------------------------------------
  Flag                    Description             Default
  ----------------------- ----------------------- -----------------------------------
  `--input`               Path to a single        ---
                          `.evtx` file            

  `--input-dir`           Path to a directory of  ---
                          `.evtx` files           

  `--output`              Output path *without*   `output/incident_report`
                          extension               

  `--format`              `markdown` \| `html` \| `markdown`
                          `json` \| `pdf` \|      
                          `all`                   

  `--max-gap-minutes`     Max time gap allowed    `60`
                          between correlated      
                          detections              

  `--title`               Report title            `SOC Storyteller Incident Report`

  `--verbose`             Enable DEBUG logging    off

  `--log-file`            Also write logs to this ---
                          file                    
  -----------------------------------------------------------------------------------

`--input` and `--input-dir` are mutually exclusive; exactly one is
required.

**Exit codes:** `0` success, `1` error, `2` no supported events / no
attack chains found (i.e. nothing to report --- not a failure).

## Web UI

A lightweight [Streamlit](https://streamlit.io) UI is included for
analysts who prefer drag-and-drop over the command line:

``` bash
streamlit run ui/streamlit_app.py
```

Upload one or more `.evtx` files, tune the correlation window, and get
interactive attack-chain cards with downloadable Markdown/HTML/JSON/PDF
reports.

## Supported Event IDs

  -----------------------------------------------------------------------
  Category                            Event IDs
  ----------------------------------- -----------------------------------
  Authentication                      4624, 4625, 4634, 4647, 4648, 4771,
                                      4776

  Privilege Use                       4672

  Process Execution                   4688, 4689

  Persistence                         4697, 4698--4702, 7045

  Account Management                  4720, 4722--4726, 4728, 4732, 4738,
                                      4740, 4756, 4767

  Object Access                       5140, 5145

  Log Tampering                       1102
  -----------------------------------------------------------------------

See `parser/event_id_registry.py` for the full catalogue with
descriptions.

## Detection Rules

  --------------------------------------------------------------------------
  Rule ID                                What it catches
  -------------------------------------- -----------------------------------
  `brute_force_logon`                    Dense clusters of failed logons
                                         against one account

  `successful_logon_after_brute_force`   A success shortly after a failure
                                         burst

  `account_created`                      New local/domain account creation

  `account_added_to_privileged_group`    Account added to an admin-like
                                         group

  `scheduled_task_persistence`           Scheduled task creation

  `service_installation_persistence`     New Windows service installation

  `audit_log_cleared`                    Security event log cleared
                                         (anti-forensics)

  `explicit_credential_logon`            `runas`-style explicit credential
                                         use

  `lateral_movement_network_logon`       One account, many hosts, short
                                         window

  `rdp_logon`                            Interactive RDP (Type 10) logons

  `possible_pass_the_hash`               NewCredentials (Type 9) logons

  `kerberos_preauth_failure`             Repeated Kerberos pre-auth failures

  `account_lockout`                      Account lockout events

  `suspicious_process_creation`          LOLBins + obfuscation markers
                                         together

  `special_privileges_assigned`          SeDebugPrivilege /
                                         SeBackupPrivilege grants

  `network_share_access`                 Admin share (`C$`, `ADMIN$`,
                                         `IPC$`) access

  `password_reset`                       Password reset by a different
                                         account
  --------------------------------------------------------------------------

Every rule lives in `detections/rules.py` as a small, independently
testable class implementing `DetectionRule.evaluate()`.

## MITRE ATT&CK Mapping

Every detection rule maps to one or more MITRE ATT&CK techniques via
`mitre/attack_mapping.py`. A guard test (`tests/test_mitre.py`) ensures
every shipped rule has a mapping --- a missing mapping fails CI.

## Risk Scoring Model

Each attack chain gets a 0--100 score
(`risk_engine/risk_calculator.py`):

    score = log-dampened(sum of detection severity weights)
          + 6  × (distinct MITRE tactics beyond the first)
          + 5  × (distinct detection rules beyond the first)
          + 20 if any detection is CRITICAL severity

Bands: `0–14 INFO` · `15–34 LOW` · `35–59 MEDIUM` · `60–84 HIGH` ·
`85–100 CRITICAL`.

An **overall incident score** aggregates multiple chains with
diminishing returns, so one CRITICAL chain always outranks several
low-risk ones.

## Report Formats

  Format         Use case
  -------------- ------------------------------------------
  **Markdown**   Version control, tickets, wikis
  **HTML**       Self-contained, shareable in any browser
  **JSON**       SIEM ingestion, tooling, automation
  **PDF**        Formal incident reports for stakeholders

Every report includes: executive summary, per-chain narrative, MITRE
mapping, chronological timeline table, SOC analyst recommendations, and
a raw-event appendix for auditability.

## Project Structure

    SOC-Storyteller/
    ├── parser/            EVTX file & XML parsing, event ID registry
    ├── detections/        DetectionRule base class + 17 concrete rules
    ├── correlation/        Groups detections into AttackChains
    ├── risk_engine/        Numeric risk scoring
    ├── timeline/            Chronological timeline construction
    ├── mitre/               MITRE ATT&CK technique catalogue & mapping
    ├── reports/              Narrative generator, recommendations, MD/HTML/JSON/PDF
    ├── utils/                Shared models, exceptions, logging
    ├── ui/                   Optional Streamlit web UI
    ├── sample_logs/           Synthetic attack scenario generator + fixture
    ├── tests/                 150+ pytest tests (~94% coverage)
    ├── main.py                CLI entry point
    ├── run_demo.py             One-command end-to-end demo
    ├── requirements.txt
    └── pyproject.toml          pytest + coverage configuration

## Testing

``` bash
pip install -r requirements.txt
python3 sample_logs/generate_sample_data.py   # regenerate the demo scenario if needed
pytest                                         # run the full suite
pytest --cov --cov-report=term-missing         # with coverage
```

Real binary `.evtx` parsing (`EvtxParser.parse`) is tested against a
mocked `python-evtx` backend so the suite runs without needing a Windows
host; the synthetic scenario in `sample_logs/attack_scenario.xml`
exercises the *entire* pipeline (detections → correlation → risk →
narrative → all four report formats) end-to-end in
`tests/test_integration.py`.

## Extending SOC Storyteller

**Add a new detection rule:** 1. Subclass `DetectionRule` in
`detections/rules.py`, implement `evaluate()`. 2. Add it to
`default_rule_set()`. 3. Add a technique mapping in
`mitre/attack_mapping._RULE_TO_TECHNIQUES`. 4. Add recommendations in
`reports/recommendations._RULE_RECOMMENDATIONS`. 5. Add a test in
`tests/test_detections.py`.

No other file needs to change --- the correlation engine, risk scorer,
and report generator all consume the rule's output through the shared
`Detection` contract automatically.

**Add a new supported Event ID:** add one line to
`parser/event_id_registry.SUPPORTED_EVENT_IDS`.

**Add a new report format:** add a `render_x()` method to
`ReportGenerator`, reusing `render_markdown()`'s content construction
where possible (as `render_html()` does) rather than duplicating logic.

## Limitations

-   Detection thresholds are tuned for demonstration/portfolio use, not
    a specific production environment --- expect to tune `threshold`/
    `window_minutes` constructor args per SOC.
-   Correlation is single-pass (`O(n²)` over detection count) --- fine
    for incident-scale investigations, not for streaming all logs from
    an entire fleet in real time.
-   This is a **retrospective analysis tool**, not a real-time SIEM/EDR.
-   `sample_logs/attack_scenario.xml` is *synthetic* Windows Event XML
    (not a binary `.evtx` file) because fabricating the proprietary
    binary EVTX chunk format requires a real Windows host; it is fed
    through the exact same parsing code path as a real EVTX export.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

[MIT](LICENSE).

------------------------------------------------------------------------

## Demo

Run the complete demonstration:

``` bash
python run_demo.py
```

Generated outputs are written to the `output/` directory:

-   Incident Report (.md)
-   Incident Report (.html)
-   Incident Report (.json)
-   Incident Report (.pdf)

------------------------------------------------------------------------

## Screenshots

Create a folder named `screenshots/` and add:

    screenshots/
    ├── terminal.png
    ├── html-report.png
    ├── pdf-report.png
    └── streamlit-ui.png

Then reference them here:

``` markdown
![Terminal](screenshots/terminal.png)

![HTML Report](screenshots/html-report.png)

![PDF Report](screenshots/pdf-report.png)
```

------------------------------------------------------------------------

## Author

**Mohamed Ahmed Ibrahim**

SOC Analyst \| Blue Team \| DFIR \| Python

GitHub: https://github.com/mohamedahmede004

> For privacy, contact information is intentionally omitted from the
> public repository.
