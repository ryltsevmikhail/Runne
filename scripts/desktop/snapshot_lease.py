"""Object-bound leases for immutable package snapshot use."""
from __future__ import annotations

import threading


class SnapshotLeaseError(Exception):
    def __init__(self, code: str = "PACKAGE_ARTIFACT_SNAPSHOT_CLOSED"):
        super().__init__(code)
        self.code = code


class SnapshotUseLease:
    def __init__(self, state: "SnapshotLeaseState", snapshot: object):
        self._state = state
        self._snapshot = snapshot
        self._released = False

    def __enter__(self) -> "SnapshotUseLease":
        return self

    def __exit__(self, _type: object, _value: object, _traceback: object) -> None:
        self.release()

    def release(self) -> None:
        if not self._released:
            self._released = True
            self._state._release()

    def is_active_for(self, snapshot: object) -> bool:
        return not self._released and self._snapshot is snapshot and self._state._owns(self)


class SnapshotLeaseState:
    def __init__(self) -> None:
        self._condition = threading.Condition()
        self._active = 0
        self._closing = False
        self._finished = False

    def acquire(self, snapshot: object) -> SnapshotUseLease:
        with self._condition:
            if self._closing or self._finished:
                raise SnapshotLeaseError()
            self._active += 1
            return SnapshotUseLease(self, snapshot)

    def _owns(self, lease: SnapshotUseLease) -> bool:
        with self._condition:
            return not self._finished and not lease._released

    def _release(self) -> None:
        with self._condition:
            self._active -= 1
            self._condition.notify_all()

    def begin_close(self) -> bool:
        with self._condition:
            if self._finished:
                return False
            if self._closing:
                while not self._finished:
                    self._condition.wait()
                return False
            self._closing = True
            while self._active:
                self._condition.wait()
            return True

    def finish_close(self) -> None:
        with self._condition:
            self._finished = True
            self._condition.notify_all()
