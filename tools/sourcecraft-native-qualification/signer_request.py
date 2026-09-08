#!/usr/bin/python3 -I
"""Unprivileged fixed request client for the root launchd signer broker."""
from __future__ import annotations
import socket
import sys
from pathlib import Path
SOCKET = Path("/private/var/run/gocode/sourcecraft-native-qualification-sign.sock")
def main(argv: list[str] | None = None) -> int:
    if argv not in (None, []): return 1
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(15); client.connect(str(SOCKET)); client.sendall(b"issue\n"); client.shutdown(socket.SHUT_WR)
            return 0 if client.recv(3) == b"ok\n" else 1
    except OSError: return 1
if __name__ == "__main__": raise SystemExit(main(sys.argv[1:]))
