"""Tests for cooperative cancellation used by the desktop app."""

from __future__ import annotations

import threading
import time

import pytest
import requests

from vt_ioc_checker.cancel import CancelToken, OperationCancelled
from vt_ioc_checker.ioc_parser import IocType
from vt_ioc_checker.vt_client import RateLimiter, VTClient


def test_sleep_completes_and_reports_waits() -> None:
    seen: list[float] = []
    token = CancelToken(on_wait=seen.append)
    token.sleep(0.3)
    assert seen and seen[-1] == 0.0


def test_cancel_interrupts_long_sleep_quickly() -> None:
    token = CancelToken()
    threading.Timer(0.2, token.cancel).start()
    start = time.monotonic()
    with pytest.raises(OperationCancelled):
        token.sleep(30)
    assert time.monotonic() - start < 2


def test_check_raises_after_cancel() -> None:
    token = CancelToken()
    token.check()
    token.cancel()
    assert token.cancelled
    with pytest.raises(OperationCancelled):
        token.check()


def test_cancelled_token_stops_rate_limited_lookup() -> None:
    """A Stop during the rate-limit wait aborts the VT lookup immediately."""

    class Session:
        def get(self, *a, **k):
            raise requests.exceptions.ConnectionError("unused")

    token = CancelToken()
    limiter = RateLimiter(1, sleep=token.sleep)
    client = VTClient("key-123", limiter, session=Session(), sleep=token.sleep, reanalyze=False)
    limiter.wait()  # first slot is free; the next call must wait ~60s
    threading.Timer(0.2, token.cancel).start()
    start = time.monotonic()
    with pytest.raises(OperationCancelled):
        client.lookup(IocType.IP, "8.8.8.8")
    assert time.monotonic() - start < 2

