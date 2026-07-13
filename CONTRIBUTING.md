# Contributing to SOC Storyteller

Thanks for considering a contribution! This project aims to stay a
**lightweight, dependency-free, single-purpose** SOC log analysis tool —
please read the [Scope](#scope) section before proposing large features.

## Scope

SOC Storyteller intentionally does **not** include:

- A database or persistent storage layer
- Authentication/authorization
- Docker/container packaging
- Cloud deployment tooling
- A REST API
- Kubernetes manifests

It is a local, offline, retrospective log-analysis tool. PRs adding any
of the above will likely be declined unless discussed in an issue first.

Contributions that *are* welcome:

- New detection rules
- Additional supported Event IDs
- Better narrative/report wording
- Bug fixes and performance improvements
- Additional tests
- Documentation improvements

## Development Setup

```bash
git clone https://github.com/mohamedahmede004/SOC-Storyteller.git
cd SOC-Storyteller
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python3 sample_logs/generate_sample_data.py
pytest
```

## Coding Standards

- **Python 3.12+**, fully type-hinted (`from __future__ import annotations`
  at the top of every module).
- **Google-style docstrings** on every public class/function (Args,
  Returns, Raises).
- **One responsibility per module/class.** If you find yourself adding
  an `if isinstance(...)` chain, consider a new `DetectionRule` or
  strategy class instead.
- **No duplicated logic.** If two report formats need the same content,
  build it once and render it multiple ways (see how `render_html()`
  reuses `render_markdown()`).
- **Logging, not print.** Use `utils.logger.get_logger(__name__)` inside
  library code. `print()` is reserved for `main.py`/`run_demo.py` CLI
  output.
- **Custom exceptions.** Raise the most specific exception from
  `utils/exceptions.py`; add a new one there if none fits.

## Adding a Detection Rule

1. Add a class to `detections/rules.py` subclassing `DetectionRule`.
2. Give it a unique, descriptive `rule_id` and `title`.
3. Implement `evaluate(self, events: list[Event]) -> list[Detection]`.
4. Register it in `default_rule_set()`.
5. Add a MITRE ATT&CK mapping in
   `mitre/attack_mapping._RULE_TO_TECHNIQUES`.
6. Add SOC analyst guidance in
   `reports/recommendations._RULE_RECOMMENDATIONS`.
7. Add unit tests in `tests/test_detections.py` covering both the
   positive (fires) and negative (does not fire) case.
8. Run `pytest tests/test_mitre.py` — it will fail if your rule has no
   MITRE mapping.

## Adding a Supported Event ID

Add one entry to `SUPPORTED_EVENT_IDS` in
`parser/event_id_registry.py`. That's it — the parser picks it up
automatically; write a detection rule separately if you want it acted on.

## Testing

- Every new module or public function needs at least one test.
- Prefer building synthetic `Event` objects via `tests/conftest.py`'s
  `make_event()` helper over requiring real `.evtx` files.
- Run the full suite with coverage before opening a PR:

  ```bash
  pytest --cov --cov-report=term-missing
  ```

- Keep or improve overall coverage; don't merge a PR that drops it
  significantly without a good reason (e.g. genuinely untestable
  environment-dependent code, marked `# pragma: no cover`).

## Pull Request Checklist

- [ ] Code is type-hinted and documented (Google-style docstrings).
- [ ] New/changed behavior has tests.
- [ ] `pytest` passes locally.
- [ ] No new required dependency unless it's free/open-source and
      justified in the PR description.
- [ ] `README.md` updated if you added a detection rule, event ID, or
      report format.

## Reporting Bugs

Open an issue with:
- What you expected to happen.
- What actually happened (include the `--verbose` log output if possible).
- A minimal reproducer if you can — a small synthetic `.evtx`/XML
  fixture is ideal (see `sample_logs/generate_sample_data.py` for the
  pattern).

## Code of Conduct

Be respectful, assume good faith, and keep discussion focused on the
technical merits of a change.
---

## Maintainer

**Mohamed Ahmed Ibrahim**

SOC Analyst | Blue Team | Detection Engineering

GitHub:
https://github.com/mohamedahmede004

Thank you for contributing to SOC Storyteller!
