import logging

from vanguard.core.logger import get_logger


def test_get_logger() -> None:
    logger = get_logger("test_vanguard")
    assert isinstance(logger, logging.Logger)
    assert logger.name == "test_vanguard"
    assert len(logger.handlers) >= 1
