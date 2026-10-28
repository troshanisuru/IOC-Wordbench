"""Cooperative cancellation for long-running lookups (used by the desktop app)."""

from __future__ import annotations

import threading
import time
from typing import Callable, Optional


class OperationCancelled(KeyboardInterrupt):
    """Raised inside a worker when the user presses Stop.

    Subclasses KeyboardInterrupt so the existing runners, which already treat
    KeyboardInterrupt as "stopped by the user", handle it without changes.
    """


class CancelToken:
    """A stop flag whose sleep() wakes immediately when cancelled."""

    def __init__(
        self, on_wait: Optional[Callable[[float], None]] = None
    ) -> None:
        self._event = threading.Event()
        self.on_wait = on_wait

    @property
    def cancelled(self) -> bool:
        return self._event.is_set()

    def cancel(self) -> None:
        self._event.set()

    def check(self) -> None:
        if self._event.is_set():
            raise OperationCancelled()

    def sleep(self, seconds: float) -> None:
        """Cancellable replacement for time.sleep; reports remaining time."""
        end = time.monotonic() + max(0.0, seconds)
        while True:
            self.check()
            remaining = end - time.monotonic()
            if remaining <= 0:
                break
            if self.on_wait is not None:
                self.on_wait(remaining)
            self._event.wait(min(0.25, remaining))
        if self.on_wait is not None:
            self.on_wait(0.0)

