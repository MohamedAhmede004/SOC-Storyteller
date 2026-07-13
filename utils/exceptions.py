"""
utils/exceptions.py

Central exception hierarchy for SOC Storyteller.

Keeping all custom exceptions in a single module (rather than scattering
``raise ValueError(...)`` throughout the codebase) gives calling code a
predictable, importable set of error types to catch, and keeps error
handling consistent across the parser, correlation engine, risk engine,
and report generator.
"""

from __future__ import annotations


class SocStorytellerError(Exception):
    """Base class for all SOC Storyteller exceptions.

    Every custom exception raised anywhere in this project inherits from
    this class, so calling code can do ``except SocStorytellerError`` to
    catch any project-specific failure while still letting unrelated
    exceptions (e.g. genuine bugs) propagate normally.
    """


class EvtxFileNotFoundError(SocStorytellerError):
    """Raised when the requested .evtx file does not exist on disk."""


class EvtxParsingError(SocStorytellerError):
    """Raised when an .evtx file cannot be parsed or is corrupted."""


class UnsupportedEventIdError(SocStorytellerError):
    """Raised when an event ID has no registered parser/field mapping.

    This is intentionally *not* raised during normal parsing (unsupported
    events are simply skipped/logged) but is available for strict-mode
    parsing or for detection rules that require a known schema.
    """


class DetectionRuleError(SocStorytellerError):
    """Raised when a detection rule fails to evaluate correctly."""


class CorrelationError(SocStorytellerError):
    """Raised when the correlation engine cannot build attack chains."""


class RiskCalculationError(SocStorytellerError):
    """Raised when risk scoring fails due to invalid or missing data."""


class ReportGenerationError(SocStorytellerError):
    """Raised when report rendering/export fails."""


class MitreMappingError(SocStorytellerError):
    """Raised when a MITRE ATT&CK technique lookup fails unexpectedly."""


class ConfigurationError(SocStorytellerError):
    """Raised when the application is misconfigured (bad CLI args, etc.)."""
