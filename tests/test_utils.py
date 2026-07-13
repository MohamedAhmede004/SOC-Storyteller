"""
tests/test_utils.py

Unit tests for :mod:`utils.exceptions` and :mod:`utils.logger`.
"""

from __future__ import annotations

import logging

from utils.exceptions import (
    CorrelationError,
    DetectionRuleError,
    EvtxFileNotFoundError,
    EvtxParsingError,
    MitreMappingError,
    ReportGenerationError,
    RiskCalculationError,
    SocStorytellerError,
    UnsupportedEventIdError,
)
from utils.logger import configure_logging, get_logger


class TestExceptionHierarchy:
    def test_all_custom_exceptions_inherit_base(self) -> None:
        exception_classes = [
            EvtxFileNotFoundError,
            EvtxParsingError,
            UnsupportedEventIdError,
            DetectionRuleError,
            CorrelationError,
            RiskCalculationError,
            ReportGenerationError,
            MitreMappingError,
        ]
        for exc_cls in exception_classes:
            assert issubclass(exc_cls, SocStorytellerError)

    def test_exceptions_carry_message(self) -> None:
        try:
            raise EvtxParsingError("bad file")
        except SocStorytellerError as exc:
            assert str(exc) == "bad file"

    def test_catching_base_catches_all_subtypes(self) -> None:
        for exc_cls in (EvtxFileNotFoundError, CorrelationError, RiskCalculationError):
            try:
                raise exc_cls("test")
            except SocStorytellerError:
                pass
            else:
                raise AssertionError(f"{exc_cls} was not caught by SocStorytellerError")


class TestLogger:
    def test_get_logger_returns_namespaced_logger(self) -> None:
        logger = get_logger("some.module")
        assert logger.name == "soc_storyteller.some.module"

    def test_get_logger_does_not_double_prefix(self) -> None:
        logger = get_logger("soc_storyteller.already.prefixed")
        assert logger.name == "soc_storyteller.already.prefixed"

    def test_configure_logging_sets_level(self) -> None:
        configure_logging(level=logging.WARNING)
        root_logger = logging.getLogger("soc_storyteller")
        assert root_logger.level == logging.WARNING

    def test_verbose_forces_debug_level(self) -> None:
        configure_logging(verbose=True)
        root_logger = logging.getLogger("soc_storyteller")
        assert root_logger.level == logging.DEBUG
        configure_logging(level=logging.INFO, verbose=False)  # reset for other tests

    def test_log_file_creates_file_handler(self, tmp_path) -> None:
        log_file = tmp_path / "logs" / "test.log"
        configure_logging(log_file=log_file)
        logger = get_logger("test_utils")
        logger.info("hello")
        assert log_file.exists()
