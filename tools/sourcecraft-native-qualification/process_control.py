"""Bounded subprocess execution with whole-process-group cleanup."""
from __future__ import annotations

import os
import select
import signal
import stat
import subprocess
import sys
import time
from pathlib import Path

from codec import Rejected

SANDBOX_EXEC = Path("/usr/bin/sandbox-exec")
SANDBOX_PROFILE = "(version 1) (allow default) (deny process-fork)"


def run(command: list[str], payload: bytes | None, timeout: float = 30,
        limit: int = 131072, pass_fds: tuple[int, ...] = (), contain: bool = False) -> tuple[bytes, int]:
    process: subprocess.Popen[bytes] | None = None
    completed = False
    descendants: set[int] = set()
    try:
        process = subprocess.Popen(
            _contained(command) if contain else command, stdin=subprocess.PIPE if payload is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            env={"PATH": "/usr/bin:/bin"}, start_new_session=True, pass_fds=pass_fds,
        )
        deadline = time.monotonic() + timeout
        if payload is not None: _write(process, payload, deadline)
        result = _read(process, deadline, limit, descendants)
        completed = True
        return result
    except (OSError, BrokenPipeError, subprocess.TimeoutExpired):
        raise Rejected("protected subprocess is unavailable") from None
    finally:
        if process is not None:
            if not completed and process.poll() is None: _kill_group(process, descendants)
            for stream in (process.stdin, process.stdout):
                if stream is not None and not stream.closed: stream.close()


def _contained(command: list[str]) -> list[str]:
    """On qualifying macOS, forbid forks so reparenting cannot escape cleanup."""
    if sys.platform != "darwin": return command
    try:
        info = SANDBOX_EXEC.stat()
    except OSError: raise Rejected("macOS process containment is unavailable") from None
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise Rejected("macOS process containment is unavailable")
    return [str(SANDBOX_EXEC), "-p", SANDBOX_PROFILE, *command]


def _write(process: subprocess.Popen[bytes], payload: bytes, deadline: float) -> None:
    assert process.stdin is not None; descriptor = process.stdin.fileno(); offset = 0
    try:
        os.set_blocking(descriptor, False)
        while offset < len(payload):
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not select.select([], [descriptor], [], remaining)[1]:
                raise subprocess.TimeoutExpired(process.args, 0)
            offset += os.write(descriptor, payload[offset:])
    finally:
        process.stdin.close()


def _read(process: subprocess.Popen[bytes], deadline: float, limit: int,
          descendants: set[int]) -> tuple[bytes, int]:
    assert process.stdout is not None
    output = bytearray()
    try:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0: raise subprocess.TimeoutExpired(process.args, 0)
            ready, _, _ = select.select([process.stdout], [], [], min(remaining, 0.1))
            descendants.update(_descendants(process.pid))
            if not ready: continue
            block = os.read(process.stdout.fileno(), limit + 1 - len(output))
            if not block:
                status = process.wait(timeout=max(0.01, remaining)); descendants.update(_descendants(process.pid))
                if _group_alive(process.pid) or any(_alive(pid) for pid in descendants):
                    _kill_group(process, descendants)
                    raise Rejected("protected subprocess left descendants")
                return bytes(output), status
            output.extend(block)
            if len(output) > limit: raise Rejected("protected subprocess output exceeded limit")
    except (Rejected, subprocess.TimeoutExpired):
        _kill_group(process, descendants); raise


def _kill_group(process: subprocess.Popen[bytes], descendants: set[int] | None = None) -> None:
    descendants = set() if descendants is None else descendants
    for pid in descendants:
        try: os.kill(pid, signal.SIGKILL)
        except ProcessLookupError: pass
    try: os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError: pass
    finally:
        try: process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill(); process.wait()


def _group_alive(group: int) -> bool:
    try: os.killpg(group, 0); return True
    except ProcessLookupError: return False
    except PermissionError: return True


def _descendants(parent: int) -> set[int]:
    try:
        output = subprocess.run(["/bin/ps", "-axo", "pid=,ppid="], capture_output=True,
                                text=True, timeout=1, check=True, env={"PATH":"/usr/bin:/bin"}).stdout
        table = {int(pid):int(ppid) for line in output.splitlines() if len((parts := line.split())) == 2
                 for pid,ppid in [parts]}
    except (OSError, ValueError, subprocess.SubprocessError): raise Rejected("process containment is unavailable") from None
    result, pending = set(), {parent}
    while pending:
        found = {pid for pid,ppid in table.items() if ppid in pending and pid not in result}
        result.update(found); pending = found
    return result


def _alive(pid: int) -> bool:
    try: os.kill(pid, 0); return True
    except ProcessLookupError: return False
