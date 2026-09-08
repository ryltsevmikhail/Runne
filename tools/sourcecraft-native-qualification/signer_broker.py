#!/usr/bin/python3 -I
"""Root launchd endpoint: the only production caller of the evidence issuer."""
from __future__ import annotations
import os
import socket
import sys
from ctypes import CDLL, POINTER, byref, c_int, c_size_t
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from codec import Rejected, load_installed_json
from policy import EVIDENCE_ROOT, POLICY_PATH, installed, validate
from signer import KEY_PATH, issue

def _connection() -> socket.socket:
    count = c_size_t(); descriptors = POINTER(c_int)()
    try:
        launch = CDLL("/usr/lib/libSystem.B.dylib").launch_activate_socket
        if launch(b"sign", byref(descriptors), byref(count)) != 0 or count.value != 1: raise OSError
        fd = descriptors[0]; CDLL("/usr/lib/libSystem.B.dylib").free(descriptors)
        return socket.socket(fileno=fd)
    except (OSError, AttributeError): raise Rejected("launchd signer socket unavailable") from None

def main(argv: list[str] | None = None) -> int:
    if argv not in (None, []) or os.geteuid() != 0: return 1
    try:
        policy = load_installed_json(POLICY_PATH); checked = validate(policy, Path(policy["verifier"]["path"]), True)
        if Path(sys.argv[0]) != Path(checked["signer_broker"]["path"]): raise Rejected("signer broker identity differs")
        with _connection() as listener:
            listener.settimeout(15)
            connection, _ = listener.accept()
            with connection:
                connection.settimeout(15)
                if connection.recv(7) != b"issue\n" or connection.recv(1): raise Rejected("signer broker request rejected")
                issue(checked, EVIDENCE_ROOT, KEY_PATH, authorized=True); connection.sendall(b"ok\n"); return 0
    except (Rejected, OSError): return 1
if __name__ == "__main__": raise SystemExit(main(sys.argv[1:]))
