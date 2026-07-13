# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [1.0.0] - 2026-07-11

### Added
- Initial public release of SOC Storyteller.
- **Parser**: binary `.evtx` parsing via `python-evtx`, plus an XML-fixture
  loader (`parse_xml_events_file`) for tests/demos without a Windows host.
  32 supported Windows Security/System Event IDs.
- **Detections**: 17 detection rules covering brute force, successful
  logon after brute force, account creation, privileged group membership,
  scheduled task and service persistence, audit log clearing, explicit
  credential logons, lateral movement, RDP logons, pass-the-hash
  indicators, Kerberos pre-auth failures, account lockouts, suspicious
  process creation, sensitive privilege assignment, admin share access,
  and password resets.
- **Correlation**: union-find based engine that merges detections sharing
  a host or user identity within a configurable time window, including
  transitive identity pivots (e.g. attacker creates and continues
  operating as a new account).
- **Risk Engine**: 0–100 risk scoring with log-dampened severity
  aggregation, MITRE tactic diversity bonus, multi-stage bonus, and a
  critical-detection bonus, plus an aggregate overall-incident score
  across multiple chains.
- **Timeline**: chronological timeline construction, per-chain or merged
  across an entire incident.
- **MITRE ATT&CK**: curated technique catalogue and rule-to-technique
  mapping for every shipped detection rule.
- **Reports**: template-based narrative generator plus Markdown, HTML,
  JSON, and PDF report rendering (PDF via ReportLab), including an
  executive summary, per-chain narrative, MITRE mapping, timeline table,
  SOC analyst recommendations, and a raw-event appendix.
- **Recommendations**: rule-mapped SOC analyst guidance (investigation,
  containment, hardening steps) surfaced in every report format.
- **CLI** (`main.py`): analyze a single `.evtx` file or a directory of
  them, choose output format(s), tune the correlation window.
- **Demo script** (`run_demo.py`) and synthetic multi-stage attack
  scenario generator (`sample_logs/generate_sample_data.py`) so the full
  pipeline can be exercised with zero setup.
- **Web UI** (`ui/streamlit_app.py`): optional Streamlit app for
  drag-and-drop `.evtx` analysis with downloadable reports.
- **Tests**: 150+ pytest tests (~94% branch/line coverage) covering
  every module, including a mocked-`python-evtx` backend for exercising
  real binary-file code paths without a Windows host, and a full
  end-to-end integration test.
- **Docs**: README, CONTRIBUTING guide, this CHANGELOG, MIT LICENSE.

[1.0.0]: https://github.com/your-org/SOC-Storyteller/releases/tag/v1.0.0
