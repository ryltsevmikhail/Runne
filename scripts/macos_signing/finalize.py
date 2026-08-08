"""Digest-helper CLI: финализация macOS production evidence документа.

Читает JSON evidence из явного пути из argv, вычисляет и добавляет
канонический `evidence_sha256` (или проверяет существующий) и выводит
канонический JSON в stdout либо атомарно пишет в `--output`.

Контракт ошибок: при любой ошибке в stderr выводится только
`<CODE> <PHASE>` (код — значение `FailureCode`), процесс завершается
с кодом 1; значения документа никогда не выводятся.

Инварианты чистоты: модуль не читает переменные окружения, не запускает
внешние процессы, не выполняет сетевых операций; файлы читаются только
по явному argv-пути.
"""

import argparse
import contextlib
import json
import os
import sys
import tempfile
from pathlib import Path

from .ingestion_rules import evidence_digest, scan_secrets, strict_json_loads
from .models import FailureCode


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise ValueError(message)


class _FinalizeError(Exception):
    def __init__(self, code: FailureCode, phase: str) -> None:
        super().__init__()
        self.code = code
        self.phase = phase


def main(argv=None) -> int:
    """Run the finalize CLI and return the process exit code."""
    parser = _Parser(prog="finalize-macos-signing-evidence.py")
    parser.add_argument("--evidence", required=True, metavar="PATH")
    parser.add_argument("--output", metavar="PATH")
    try:
        args = parser.parse_args(argv)
    except ValueError:
        return _report(FailureCode.EVIDENCE_INCOMPLETE, "args")
    except SystemExit as exit_error:
        if exit_error.code not in (0, None):
            return _report(FailureCode.EVIDENCE_INCOMPLETE, "args")
        return 0
    try:
        return _finalize(args.evidence, args.output)
    except _FinalizeError as error:
        return _report(error.code, error.phase)
    except Exception:
        return _report(FailureCode.EVIDENCE_INCOMPLETE, "finalize")


def _finalize(path: str, output: str | None) -> int:
    try:
        with open(path, "rb") as stream:
            raw = stream.read()
    except OSError:
        raise _FinalizeError(FailureCode.ARTIFACT_NOT_FOUND, "read") from None
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise _FinalizeError(FailureCode.EVIDENCE_INCOMPLETE, "parse") from None
    document, ok = strict_json_loads(text)
    if not ok:
        raise _FinalizeError(FailureCode.EVIDENCE_INCOMPLETE, "parse")
    if scan_secrets(document):
        raise _FinalizeError(FailureCode.EVIDENCE_SECRET_MARKER, "secret-scan")
    if type(document) is not dict:
        raise _FinalizeError(FailureCode.EVIDENCE_INCOMPLETE, "conformance")
    digest = evidence_digest(document)
    if document.get("evidence_sha256") is not None and document.get("evidence_sha256") != digest:
        raise _FinalizeError(FailureCode.EVIDENCE_INTEGRITY, "integrity")
    if "evidence_sha256" not in document:
        document["evidence_sha256"] = digest
    payload = json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8") + b"\n"
    if output:
        _atomic_write(output, payload)
    else:
        sys.stdout.write(payload.decode("utf-8"))
    return 0


def _atomic_write(path: str, payload: bytes) -> None:
    target = Path(path)
    if target.is_symlink():
        raise _FinalizeError(FailureCode.EVIDENCE_INCOMPLETE, "output")
    temporary = ""
    try:
        descriptor, temporary = tempfile.mkstemp(prefix=f".{target.name}.", suffix=".tmp", dir=str(target.parent))
        os.close(descriptor)
        with open(temporary, "wb") as stream:
            stream.write(payload)
        os.replace(temporary, target)
    except OSError:
        if temporary:
            with contextlib.suppress(OSError):
                Path(temporary).unlink()
        raise _FinalizeError(FailureCode.EVIDENCE_INCOMPLETE, "output") from None


def _report(code: FailureCode, phase: str) -> int:
    print(f"{code.value} {phase}", file=sys.stderr)
    return 1
