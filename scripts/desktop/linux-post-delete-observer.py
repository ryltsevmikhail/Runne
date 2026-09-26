#!/usr/bin/env python3
"""Observe native Revoke deletion, then SIGKILL its waiting CLI via pidfd."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import select
import signal
import stat
import struct
import subprocess
import sys
import time
from datetime import datetime, timezone


class Abort(Exception):
    def __init__(self, reason):
        self.reason = reason


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def private_dir(path, uid):
    if not path.is_absolute() or path.resolve(strict=True) != path:
        raise Abort("noncanonical_directory")
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != uid or stat.S_IMODE(info.st_mode) != 0o700:
        raise Abort("directory_not_private")
    return path


def package_file(path):
    if not path.is_absolute() or path.resolve(strict=True) != path:
        raise Abort("noncanonical_package_path")
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode):
        raise Abort("package_not_regular")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode) or (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
            raise Abort("package_changed")
        digest = hashlib.sha256()
        while chunk := os.read(fd, 1024 * 1024):
            digest.update(chunk)
        return opened.st_dev, opened.st_ino, digest.hexdigest()
    finally:
        os.close(fd)


def proc_facts(pid):
    stat_text = Path(f"/proc/{pid}/stat").read_text(encoding="ascii")
    rest = stat_text.rsplit(")", 1)[1].split()
    if len(rest) < 20:
        raise Abort("process_stat_invalid")
    state = rest[0]
    if state in {"Z", "X", "x"}:
        raise Abort("process_not_alive")
    parent_pid, start_ticks = int(rest[1]), int(rest[19])
    status = Path(f"/proc/{pid}/status").read_text(encoding="ascii")
    uid_line = next((line for line in status.splitlines() if line.startswith("Uid:")), None)
    if uid_line is None:
        raise Abort("process_uid_missing")
    uids = [int(value) for value in uid_line.split()[1:]]
    if len(uids) != 4:
        raise Abort("process_uid_invalid")
    exe = os.stat(f"/proc/{pid}/exe")
    digest = hashlib.sha256()
    with open(f"/proc/{pid}/exe", "rb", buffering=0) as image:
        while chunk := image.read(1024 * 1024):
            digest.update(chunk)
    return {"ppid": parent_pid, "state": state, "start_ticks": start_ticks,
            "uids": uids, "dev": exe.st_dev, "ino": exe.st_ino,
            "sha256": digest.hexdigest()}

def same_process_identity(first, second):
    return {key: value for key, value in first.items() if key != "state"} == {key: value for key, value in second.items() if key != "state"}


def marker_pid(root):
    marker = root / "post-delete.marker"
    info = marker.lstat()
    if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600:
        raise Abort("marker_not_regular_private")
    if info.st_uid != os.geteuid() or info.st_nlink != 1 or info.st_size > 32:
        raise Abort("marker_metadata_invalid")
    fd = os.open(marker, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        opened = os.fstat(fd)
        if (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
            raise Abort("marker_changed")
        if (not stat.S_ISREG(opened.st_mode) or stat.S_IMODE(opened.st_mode) != 0o600
                or opened.st_uid != os.geteuid() or opened.st_nlink != 1 or opened.st_size > 32):
            raise Abort("marker_metadata_invalid")
        raw = os.read(fd, 33)
    finally:
        os.close(fd)
    if len(raw) != info.st_size or not re.fullmatch(rb"[1-9][0-9]{0,9}\n", raw):
        raise Abort("marker_pid_invalid")
    return int(raw[:-1])


def wait_marker(root, seconds):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if os.path.lexists(root / "post-delete.marker"):
            return marker_pid(root)
        time.sleep(0.05)
    raise Abort("marker_timeout")


def version_service(provider, version):
    provider_bytes = provider.encode("ascii")
    ref = hashlib.sha256(
        b"GOCODE_CREDENTIAL_VERSION_REF_V1\0"
        + struct.pack(">Q", len(provider_bytes))
        + provider_bytes
        + struct.pack(">Q", version)
    ).hexdigest()
    return f"dev.runne.provider-credential.v1.version.{version}.{ref}"


def native_version_absent(provider, version, uid):
    bus_path = Path(f"/run/user/{uid}/bus")
    bus = bus_path.lstat()
    if not stat.S_ISSOCK(bus.st_mode) or bus.st_uid != uid:
        raise Abort("user_bus_invalid")
    command = [
        "/usr/bin/busctl", f"--address=unix:path={bus_path}", "--json=short", "call",
        "org.freedesktop.secrets", "/org/freedesktop/secrets",
        "org.freedesktop.Secret.Service", "SearchItems", "a{ss}", "3",
        "target", "default", "service", version_service(provider, version),
        "username", provider,
    ]
    try:
        result = subprocess.run(command, check=True, capture_output=True, text=True, timeout=5,
                                env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"})
        response = json.loads(result.stdout)
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError):
        raise Abort("secret_service_query_failed") from None
    data = response.get("data") if response.get("type") == "aoao" else None
    if not isinstance(data, list) or len(data) != 2 or any(
        not isinstance(items, list) or any(not isinstance(item, str) for item in items)
        for items in data
    ):
        raise Abort("secret_service_response_invalid")
    return not data[0] and not data[1]


def output_file(path, uid):
    private_dir(path.parent, uid)
    if not path.is_absolute() or path.exists() or path.is_symlink():
        raise Abort("evidence_path_unavailable")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    os.fchmod(fd, 0o600)
    return fd


def observe(args, record):
    uid = os.geteuid()
    root = args.fixture_root
    private_dir(root.parent, uid)
    private_dir(root, uid)
    cli_dev, cli_ino, cli_hash = package_file(args.cli)
    daemon_dev, daemon_ino, daemon_hash = package_file(args.daemon)
    record.update({
        "fixture_root": str(root), "packaged_cli": str(args.cli), "packaged_daemon": str(args.daemon),
        "cli_sha256": cli_hash, "daemon_sha256": daemon_hash,
        "post_delete_marker": str(root / "post-delete.marker"),
        "secret_service_bus": f"/run/user/{os.geteuid()}/bus",
        "provider": args.provider, "version": args.version,
        "version_ref_sha256": version_service(args.provider, args.version).rsplit(".", 1)[1],
        "marker_wait_started_utc": utc_now(),
    })
    if not hasattr(os, "pidfd_open") or not hasattr(signal, "pidfd_send_signal"):
        raise Abort("pidfd_unavailable")
    pid = wait_marker(root, args.wait_seconds)
    record["marker_observed_utc"] = utc_now()
    record["marker_valid"] = True
    pidfd = os.pidfd_open(pid, 0)
    record["pidfd_opened"] = True
    try:
        cli = proc_facts(pid)
        parent_pid = cli["ppid"]
        daemon = proc_facts(parent_pid)
        if cli["uids"][1] != uid:
            raise Abort("writer_uid_mismatch")
        if (cli["dev"], cli["ino"]) != (cli_dev, cli_ino) or cli["sha256"] != cli_hash:
            raise Abort("writer_package_mismatch")
        if daemon["uids"][1] != uid or daemon["sha256"] != daemon_hash:
            raise Abort("daemon_package_mismatch")
        record.update({"writer_uid_verified": True, "writer_package_verified": True,
                       "daemon_uid_verified": True, "daemon_package_verified": True})
        absent = native_version_absent(args.provider, args.version, uid)
        record["native_version_absent"] = absent
        if not absent:
            raise Abort("native_version_still_present")
        record["native_absence_observed_utc"] = utc_now()
        cli_now, daemon_now = proc_facts(pid), proc_facts(parent_pid)
        if not same_process_identity(cli_now, cli) or not same_process_identity(daemon_now, daemon) \
                or package_file(args.cli) != (cli_dev, cli_ino, cli_hash) \
                or package_file(args.daemon) != (daemon_dev, daemon_ino, daemon_hash):
            raise Abort("process_identity_changed")
        if not native_version_absent(args.provider, args.version, uid):
            raise Abort("native_version_reappeared")
        if cli_now["state"] in {"Z", "X", "x"}:
            raise Abort("writer_not_alive_before_signal")
        readiness = select.poll()
        readiness.register(pidfd, select.POLLIN | select.POLLHUP | select.POLLERR)
        if readiness.poll(0):
            raise Abort("writer_exited_before_signal")
        record["writer_alive_before_signal"] = True
        record["pidfd_not_ready_before_signal"] = True
        record["writer_state_before_signal"] = cli_now["state"]
        record["pre_signal_revalidation_utc"] = utc_now()
        try:
            signal.pidfd_send_signal(pidfd, signal.SIGKILL, None, 0)
        except OSError:
            raise Abort("pidfd_signal_failed") from None
        record["signal_syscall_succeeded"] = True
        record["signal_sent_utc"] = utc_now()
        record["signal_number"] = signal.SIGKILL
        poller = select.poll()
        poller.register(pidfd, select.POLLIN | select.POLLHUP | select.POLLERR)
        record["pidfd_exit_observed"] = bool(poller.poll(5000))
        record["exit_observed_utc"] = utc_now() if record["pidfd_exit_observed"] else None
        if not record["pidfd_exit_observed"]:
            raise Abort("pidfd_exit_timeout")
        record["outcome"] = "signal_accepted_and_exit_observed"
        record["exit_cause_proven"] = False
    finally:
        os.close(pidfd)


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture-root", type=Path, required=True)
    parser.add_argument("--cli", type=Path, required=True, help="expected packaged runne executable")
    parser.add_argument("--daemon", type=Path, required=True, help="expected packaged runned executable")
    parser.add_argument("--provider", required=True, choices=("deepseek", "openai", "openai-codex", "github-copilot"))
    parser.add_argument("--version", type=int, required=True)
    parser.add_argument("--output", type=Path, required=True, help="new private JSON evidence file")
    parser.add_argument("--wait-seconds", type=int, default=20)
    args = parser.parse_args()
    if args.version < 1 or not 1 <= args.wait_seconds <= 25:
        parser.error("version must be positive and wait-seconds must be 1..25")
    return args


def main():
    args = parse_args()
    record = {"schema": "runne.linux-post-delete-observer/v1", "started_utc": utc_now(),
              "fixture_root": str(args.fixture_root), "packaged_cli": str(args.cli),
              "packaged_daemon": str(args.daemon), "evidence_path": str(args.output),
              "provider": args.provider, "version": args.version,
              "marker_valid": False, "writer_uid_verified": False, "writer_package_verified": False,
              "daemon_uid_verified": False, "daemon_package_verified": False,
              "native_version_absent": False, "pidfd_opened": False, "pidfd_exit_observed": False,
              "writer_alive_before_signal": False, "pidfd_not_ready_before_signal": False,
              "signal_syscall_succeeded": False, "signal_number": None, "exit_cause_proven": False,
              "limitation": "pidfd identity and exit are observed; exit cause/status is not waitable here"}
    try:
        fd = output_file(args.output, os.geteuid())
    except (Abort, OSError):
        print("observer aborted: evidence_path_unavailable", file=sys.stderr)
        return 2
    try:
        try:
            observe(args, record)
        except Abort as error:
            record["outcome"] = "aborted"
            record["reason"] = error.reason
        except (OSError, RuntimeError, ValueError, OverflowError, AttributeError):
            record["outcome"] = "aborted"
            record["reason"] = "identity_or_io_check_failed"
        record["finished_utc"] = utc_now()
        with os.fdopen(fd, "w", encoding="utf-8") as evidence:
            json.dump(record, evidence, sort_keys=True, indent=2)
            evidence.write("\n")
            evidence.flush()
            os.fsync(evidence.fileno())
    except OSError:
        print("observer aborted: evidence_write_failed", file=sys.stderr)
        return 2
    if record.get("outcome") != "signal_accepted_and_exit_observed":
        print(f"observer aborted: {record.get('reason', 'check_failed')}", file=sys.stderr)
        return 1
    print("observer completed: pidfd SIGKILL sent and exit observed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
