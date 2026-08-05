"""Validate structural fixtures locally; Task16 remains explicitly not run."""

import argparse
import sys
from pathlib import Path

from scripts.release_v2.canonical import canonical_json
from scripts.release_v2.fixture_loader import LoadedFixtureGate, load_fixture_gate
from scripts.release_v2.fixtures import SOURCE_DATE_EPOCH, generate_fixture
from scripts.release_v2.gate import evaluate_gate, production_gate_exit_code
from scripts.release_v2.human_fixture_validation import snapshot_human_fixture, validate_human_fixture
from scripts.release_v2.model import FailureCodeV1, GateResultV1, ReleaseFailure


_SCHEMA = "release-v2-cli-result.v1"
_MAX_SOURCE_DATE_EPOCH = 2**63 - 1


class _InputError(ValueError):
    pass


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise _InputError


class _One(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None) -> None:
        if getattr(namespace, self.dest, None) is not None:
            raise _InputError
        setattr(namespace, self.dest, values)


class _FlagOnce(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None) -> None:
        if getattr(namespace, self.dest, None) is not None:
            raise _InputError
        setattr(namespace, self.dest, True)


def main(argv: list[str] | None = None) -> int:
    try:
        arguments = _parser().parse_args(argv)
        if arguments.command == "build-fixture":
            return _build(arguments)
        return _verify(arguments)
    except _InputError:
        return _emit({"error": {"code": "InputInvalid"}, "schema_version": _SCHEMA}, "input invalid", 2)
    except ReleaseFailure as error:
        return _emit({"error": {"code": error.code.value}, "schema_version": _SCHEMA}, "verification failed", 1)
    except Exception:
        return _emit({"error": {"code": "InternalError"}, "schema_version": _SCHEMA}, "internal failure", 3)


def _parser() -> _Parser:
    parser = _Parser(add_help=False, allow_abbrev=False)
    commands = parser.add_subparsers(dest="command", required=True)
    build = commands.add_parser("build-fixture", add_help=False, allow_abbrev=False)
    build.add_argument("--output", action=_One, required=True)
    build.add_argument("--source-date-epoch", action=_One, required=True)
    verify = commands.add_parser("verify", add_help=False, allow_abbrev=False)
    verify.add_argument("--candidate", action=_One, required=True)
    verify.add_argument("--fixture", action=_FlagOnce, nargs=0, default=None)
    return parser


def _build(arguments: argparse.Namespace) -> int:
    epoch = _epoch(arguments.source_date_epoch)
    if epoch != SOURCE_DATE_EPOCH:
        raise _InputError
    output = Path(arguments.output)
    if output.exists() and (not output.is_dir() or any(output.iterdir())):
        raise _InputError
    generate_fixture(output)
    loaded = _load_fixture(output)
    result = evaluate_gate(loaded.manifest, context=loaded.context, fixture_mode=True)
    return _emit(_report("build-fixture", loaded, result), "", 0)


def _verify(arguments: argparse.Namespace) -> int:
    candidate = Path(arguments.candidate)
    if not candidate.is_dir():
        raise _InputError
    if arguments.fixture:
        loaded = _load_fixture(candidate)
        result = evaluate_gate(loaded.manifest, context=loaded.context, fixture_mode=True)
        return _emit(_report("verify-fixture", loaded, result), "", 0)
    loaded = _load_fixture(candidate)
    result = evaluate_gate(loaded.manifest, context=loaded.context, fixture_mode=False)
    report = _report("production-gate", loaded, result)
    return _emit(report, "production gate blocked", production_gate_exit_code(result))


def _epoch(value: str) -> int:
    if (
        type(value) is not str
        or not value.isascii()
        or not value.isdecimal()
        or len(value) > len(str(_MAX_SOURCE_DATE_EPOCH))
    ):
        raise _InputError
    try:
        epoch = int(value)
    except (TypeError, ValueError) as error:
        raise _InputError from error
    if not 0 <= epoch <= _MAX_SOURCE_DATE_EPOCH:
        raise _InputError
    return epoch


def _load_fixture(candidate: Path) -> LoadedFixtureGate:
    snapshot = snapshot_human_fixture(candidate)
    validate_human_fixture(candidate, before=snapshot)
    return load_fixture_gate(snapshot)


def _report(command: str, loaded: LoadedFixtureGate, result: object) -> dict[str, object]:
    if type(result) is not GateResultV1:
        raise ReleaseFailure(FailureCodeV1.MANIFEST_INVALID, "gate_result_invalid")
    return {
        "candidate_sha256": loaded.manifest.candidate_sha256,
        "command": command,
        "limitation": {"task": "Task16", "status": "NOT_RUN"},
        "qualification_subject_sha256": loaded.manifest.inputs.subject.subject_sha256,
        "validation_scope": "validated_structural_candidate_candidate_bound_blocked_claims",
        **result.as_dict(),
    }


def _emit(value: dict[str, object], diagnostic: str, exit_code: int) -> int:
    sys.stdout.buffer.write(canonical_json(value))
    if diagnostic:
        sys.stderr.write(f"release-v2: {diagnostic}\n")
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
