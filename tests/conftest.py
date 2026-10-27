"""Shared pytest fixtures for the test suite."""

from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _zero_final_save_wait(monkeypatch: pytest.MonkeyPatch) -> None:
    """Set the final save retry wait to zero seconds across all tests."""
    monkeypatch.setattr(
        "vt_ioc_checker.runner.FINAL_SAVE_WAIT_SECONDS", 0.0, raising=False
    )
