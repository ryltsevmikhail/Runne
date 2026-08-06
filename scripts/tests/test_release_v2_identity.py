import unittest
from dataclasses import dataclass
from dataclasses import replace
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
from unittest.mock import patch
from scripts.release_v2.canonical import canonical_json as j, parse_canonical_json as p, sort_utf8 as s, validate_relative_path as r, validate_sha256 as h, validate_unique_relative_paths as u
from scripts.release_v2.model import ArtifactEntry as A, ArtifactInventoryV2 as N, BuildInputIdentityV2 as B, ClaimDisposition as D, ClaimRecordV1 as C, FailureCodeV1 as F, FailureCodeV2 as V, FailureRecordV1 as R, FixtureStatus as X, GateResultV1 as G, OverallStatus as O, ProductTupleIdentityV1 as T, ProductionGateV1 as P, QualificationSubjectIdentityV1 as Q, ReleaseCandidateIdentityV2 as K, ReleaseFailure as E, ReleaseSnapshotIdentity as S
from scripts.release_v2.preflight import BuildRequest, build_input_identity, preflight_candidate
from scripts.release_v2 import preflight
from scripts.release_v2 import repository_snapshot

I, Z = frozenset({"identity"}), frozenset()
BAD = ("/tmp/artifact", "invalid\ndetail", "token=redacted", "{\"bytes\":1}")


class IdentityTests(unittest.TestCase):
    def assert_failure(self, callback, code) -> None:
        with self.assertRaises(E) as raised:
            callback()
        self.assertEqual(raised.exception.code, code)

    def fixture_repositories(self) -> tuple[Path, Path, BuildRequest]:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        source = Path(temporary.name) / "source"
        source.mkdir()
        (source / "Cargo.lock").write_text("cargo-lock\n", encoding="utf-8")
        (source / "pnpm-lock.yaml").write_text("pnpm-lock\n", encoding="utf-8")
        (source / "main.txt").write_text("source\n", encoding="utf-8")
        self.git(source, "init")
        self.git(source, "add", ".")
        self.git(source, "commit", "-m", "fixture")
        candidate = Path(temporary.name) / "candidate"
        shutil.copytree(source, candidate)
        return source, candidate, BuildRequest("1.0.0", "x86_64-unknown-linux-gnu", "linux", ("a" * 64,), "rust-1.97.1", "release", 0)

    @staticmethod
    def git(root: Path, *args: str) -> None:
        subprocess.run(["git", "-C", str(root), "-c", "user.name=fixture", "-c", "user.email=fixture@example.invalid", *args], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def test_at_02_clean_candidate_is_accepted(self) -> None:
        source, candidate, request = self.fixture_repositories()
        self.assertIsNone(preflight_candidate(source, candidate, build_input_identity(source, request)))

    def test_at_02_dirty_candidate_blocks(self) -> None:
        source, candidate, request = self.fixture_repositories()
        (candidate / "unexpected.txt").write_text("dirty\n", encoding="utf-8")
        self.assert_failure(lambda: preflight_candidate(source, candidate, build_input_identity(source, request)), F.CANDIDATE_DIRTY)

    def test_at_03_exact_source_revision_is_accepted(self) -> None:
        source, candidate, request = self.fixture_repositories()
        build = build_input_identity(source, request)
        self.assertRegex(build.source_revision, r"^[0-9a-f]{40}$")
        preflight_candidate(source, candidate, build)

    def test_at_03_wrong_source_revision_blocks(self) -> None:
        source, candidate, request = self.fixture_repositories()
        build = replace(build_input_identity(source, request), source_revision="0" * 40)
        self.assert_failure(lambda: preflight_candidate(source, candidate, build), F.SOURCE_REVISION_INVALID)

    def test_at_04_exact_lock_digests_are_accepted(self) -> None:
        source, candidate, request = self.fixture_repositories()
        build = build_input_identity(source, request)
        self.assertEqual(len(build.cargo_lock_sha256), 64)
        self.assertEqual(len(build.pnpm_lock_sha256), 64)
        preflight_candidate(source, candidate, build)

    def test_at_04_wrong_lock_digest_blocks(self) -> None:
        source, candidate, request = self.fixture_repositories()
        build = replace(build_input_identity(source, request), cargo_lock_sha256="0" * 64)
        self.assert_failure(lambda: preflight_candidate(source, candidate, build), F.CANDIDATE_IDENTITY_MISMATCH)

    def test_at_05_bound_candidate_is_accepted(self) -> None:
        source, candidate, request = self.fixture_repositories()
        self.assertIsNone(preflight_candidate(source, candidate, build_input_identity(source, request)))

    def test_at_05_candidate_mismatch_blocks(self) -> None:
        source, candidate, request = self.fixture_repositories()
        (candidate / "main.txt").write_text("candidate\n", encoding="utf-8")
        self.git(candidate, "add", "main.txt")
        self.git(candidate, "commit", "-m", "candidate")
        self.assert_failure(lambda: preflight_candidate(source, candidate, build_input_identity(source, request)), F.CANDIDATE_IDENTITY_MISMATCH)

    def test_at_10_matching_target_profile_toolchain_is_accepted(self) -> None:
        source, candidate, request = self.fixture_repositories()
        self.assertIsNone(preflight_candidate(source, candidate, build_input_identity(source, request)))

    def test_at_10_wrong_target_profile_toolchain_blocks(self) -> None:
        source, candidate, request = self.fixture_repositories()
        build = build_input_identity(source, request)
        cases = ({"target": "unsupported"}, {"platform": "macos"}, {"release_version": "01.0.0"}, {"profile_digests": ("b" * 64, "a" * 64)}, {"toolchain": "rust-latest"}, {"release_profile": "debug"})
        for changes in cases:
            self.assert_failure(lambda changes=changes: preflight_candidate(source, candidate, replace(build, **changes)), F.MANIFEST_INVALID)

    def test_at_10_fixed_request_inputs_reject_invalid_version_and_epoch(self) -> None:
        source, _, request = self.fixture_repositories()
        cases = ({"platform": "windows"}, {"release_version": "1.0.0-."}, {"release_version": "01.0.0"}) + tuple({"source_date_epoch": value} for value in (True, "0", -1))
        for changes in cases:
            self.assert_failure(lambda changes=changes: build_input_identity(source, replace(request, **changes)), F.MANIFEST_INVALID)

    def test_preflight_keeps_git_indexes_unchanged(self) -> None:
        source, candidate, request = self.fixture_repositories()
        def index_state(root: Path) -> tuple[str, int, int, int, int]:
            index = root / ".git" / "index"
            stat = index.stat()
            return hashlib.sha256(index.read_bytes()).hexdigest(), stat.st_mode, stat.st_size, stat.st_mtime_ns, stat.st_ctime_ns
        before = index_state(source), index_state(candidate)
        preflight_candidate(source, candidate, build_input_identity(source, request))
        self.assertEqual((index_state(source), index_state(candidate)), before)

    def test_preflight_detects_injected_worktree_snapshot_change(self) -> None:
        source, candidate, request = self.fixture_repositories()
        build = build_input_identity(source, request)
        calls: dict[Path, int] = {}
        original = preflight._capture_repository
        def snapshot(root: Path) -> tuple[str, str, str, str]:
            calls[root] = calls.get(root, 0) + 1
            value = original(root)
            return value if root != candidate or calls[root] == 1 else (value[0], "0" * 64, value[2], value[3])
        with patch.object(preflight, "_capture_repository", side_effect=snapshot):
            self.assert_failure(lambda: preflight_candidate(source, candidate, build), F.INPUT_MUTATION_DETECTED)

    def test_preflight_ignores_ambient_git_overrides_and_credentials(self) -> None:
        source, candidate, request = self.fixture_repositories()
        observed: list[dict[str, str]] = []
        run = subprocess.run
        ambient = {"GIT_DIR": "/hostile/git", "GIT_WORK_TREE": "/hostile/worktree", "GIT_INDEX_FILE": "/hostile/index", "GIT_OBJECT_DIRECTORY": "/hostile/objects", "GIT_ALTERNATE_OBJECT_DIRECTORIES": "/hostile/alternates", "GIT_COMMON_DIR": "/hostile/common", "GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "core.hooksPath", "GIT_CONFIG_VALUE_0": "/hostile/hooks", "GIT_CONFIG_PARAMETERS": "core.hooksPath=/hostile/hooks", "GIT_NAMESPACE": "hostile", "AWS_SECRET_ACCESS_KEY": "credential"}
        def capture(*args: object, **kwargs: object) -> subprocess.CompletedProcess[bytes]:
            observed.append(kwargs["env"])
            return run(*args, **kwargs)
        with patch.dict(os.environ, ambient), patch.object(repository_snapshot.subprocess, "run", side_effect=capture):
            preflight_candidate(source, candidate, build_input_identity(source, request))
        self.assertTrue(observed)
        expected = {"GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_SYSTEM": os.devnull, "GIT_NO_LAZY_FETCH": "1", "GIT_OPTIONAL_LOCKS": "0", "GIT_PAGER": "cat", "LC_ALL": "C", "PATH": os.defpath}
        self.assertTrue(all(environment == expected for environment in observed))

    def test_at_01_valid_structural_candidate(self) -> None:
        self.assertEqual(j({"identity": "fixture"}), b'{"identity":"fixture"}\n')

    def test_at_01_rejects_noncanonical_identity(self) -> None:
        invalid = (b'\xef\xbb\xbf{"identity":"fixture"}\n', b'{"identity":"first","identity":"second"}\n', '{"identity":"cafe\u0301"}\n'.encode(), b'{"identity":"fixture"}')
        for raw in invalid:
            self.assert_failure(lambda: p(raw, required=I, optional=Z), F.MANIFEST_INVALID)

    def test_at_06_known_manifest_is_accepted(self) -> None:
        self.assertEqual(p(b'{"identity":"fixture"}\n', required=I, optional=frozenset({"comment"})), {"identity": "fixture"})

    def test_at_06_unknown_manifest_blocks(self) -> None:
        self.assert_failure(lambda: p(b'{"identity":"fixture","unexpected":true}\n', required=I, optional=Z), F.MANIFEST_INVALID)
        with self.assertRaises(ValueError):
            E("UnknownFailure", "rejected")
        for path in ("", ".", "..", "/absolute", "dir\\file", "dir/\x01file"):
            self.assert_failure(lambda: r(path), F.PATH_UNSAFE)

    def test_result_model_rejects_unapproved_or_raw_enum_values(self) -> None:
        gate = P(D.BLOCKED, F.PRODUCTION_GATE_BLOCKED)
        args = dict(schema_version="release-v2-result.v1", overall_status=O.BLOCKED_EVIDENCE, production_approved=False, production_gate=gate, failures=(), claims=())
        for changed in ({"production_approved": True}, {"overall_status": "BLOCKED_EVIDENCE"}):
            with self.assertRaises(ValueError):
                G(**(args | changed))
        with self.assertRaises(ValueError):
            P("BLOCKED", F.PRODUCTION_GATE_BLOCKED)

    def test_release_failure_rejects_unsafe_detail(self) -> None:
        for detail in BAD:
            with self.assertRaises(ValueError):
                E(F.MANIFEST_INVALID, detail)
        self.assertEqual(E(F.MANIFEST_INVALID, "json_invalid").detail, "json_invalid")

    def test_failure_detail(self) -> None:
        for detail in BAD:
            with self.assertRaises(ValueError):
                R(F.MANIFEST_INVALID, detail)

    def test_gate_result_typed_tuples(self) -> None:
        gate = P(D.BLOCKED, F.PRODUCTION_GATE_BLOCKED)
        failure, claim = R(F.MANIFEST_INVALID, "json_invalid"), C("manifest", D.BLOCKED, F.MANIFEST_INVALID, "a" * 64)
        args = dict(schema_version="release-v2-result.v1", overall_status=O.BLOCKED_EVIDENCE, production_approved=False, production_gate=gate)
        cases = (([failure], (claim,)), (("ManifestInvalid",), (claim,)), ((failure,), [claim]), ((failure,), (D.BLOCKED,)))
        for failures, claims in cases:
            with self.assertRaises(ValueError):
                G(**(args | {"failures": failures, "claims": claims}))
        G(**(args | {"failures": (failure,), "claims": (claim,)}))

    def test_gate_result_serializes_minimal_blocked_shape(self) -> None:
        gate = P(D.BLOCKED, F.PRODUCTION_GATE_BLOCKED)
        result = G("release-v2-result.v1", O.BLOCKED_EVIDENCE, False, gate, (), ())
        self.assertEqual(result.as_dict(), {"schema_version": "release-v2-result.v1", "overall_status": "BLOCKED_EVIDENCE", "production_approved": False, "production_gate": {"disposition": "BLOCKED", "failure_code": "ProductionGateBlocked"}, "failures": [], "claims": []})
        with self.assertRaises(ValueError):
            G("release-v2-result.v2", O.BLOCKED_EVIDENCE, False, gate, (), ())

    def test_result_model_rejects_dataclass_subclasses(self) -> None:
        @dataclass(frozen=True)
        class DerivedGate(P):
            extra: int = 1
        @dataclass(frozen=True)
        class DerivedFailure(R):
            extra: int = 1
        @dataclass(frozen=True)
        class DerivedClaim(C):
            extra: int = 1
        gate = P(D.BLOCKED, F.PRODUCTION_GATE_BLOCKED)
        args = dict(schema_version="release-v2-result.v1", overall_status=O.BLOCKED_EVIDENCE, production_approved=False, production_gate=gate, failures=(), claims=())
        for changed in ({"production_gate": DerivedGate(D.BLOCKED, F.PRODUCTION_GATE_BLOCKED)}, {"failures": (DerivedFailure(F.EVIDENCE_MISSING, "json_invalid"),)}, {"claims": (DerivedClaim("claim", D.BLOCKED, F.EVIDENCE_MISSING, "a" * 64),)}):
            with self.assertRaises(ValueError):
                G(**(args | changed))

    def test_result_model_rejects_non_exact_field_types(self) -> None:
        class StringSubclass(str):
            pass
        class TupleSubclass(tuple):
            pass
        gate = P(D.BLOCKED, F.PRODUCTION_GATE_BLOCKED)
        args = dict(schema_version="release-v2-result.v1", overall_status=O.BLOCKED_EVIDENCE, production_approved=False, production_gate=gate, failures=(), claims=())
        for changed in ({"schema_version": StringSubclass("release-v2-result.v1")}, {"failures": TupleSubclass()}, {"claims": TupleSubclass()}, {"fixture_status": "STRUCTURAL_FIXTURE_VALID"}, {"fixture_status": StringSubclass("STRUCTURAL_FIXTURE_VALID")}, {"production_approved": 0}):
            with self.assertRaises(ValueError):
                G(**(args | changed))
        for code in (F.EVIDENCE_MISSING.value, V.HARDLINK_REJECTED.value):
            with self.assertRaises(ValueError):
                R(code, "json_invalid")

    def test_failure_detail_contract(self) -> None:
        for detail in ("json_invalid", "hosted lane evidence absent", "a0_b1", "a b_c"):
            self.assertEqual(R(F.MANIFEST_INVALID, detail).detail, detail)
        invalid = ("", "a" * 65, "Upper", "two  spaces", "_leading", "trailing_", "two__words", "two _ words", "dir/file", "dir\\file", "key:value", "key=value", "quote\"", "{json}", "line\nbreak", "token", "token_value", "credential_marker", "password", "secret")
        for detail in invalid:
            with self.assertRaises(ValueError):
                R(F.MANIFEST_INVALID, detail)
        with self.assertRaises(ValueError):
            R(F.MANIFEST_INVALID, type("StringSubclass", (str,), {})("json_invalid"))

    def test_production_gate_is_exactly_blocked(self) -> None:
        self.assertEqual(P(D.BLOCKED, F.PRODUCTION_GATE_BLOCKED).disposition, D.BLOCKED)
        for disposition in D:
            if disposition is not D.BLOCKED:
                with self.assertRaises(ValueError):
                    P(disposition, F.PRODUCTION_GATE_BLOCKED)
        for code in (*F, *V):
            if code is not F.PRODUCTION_GATE_BLOCKED:
                with self.assertRaises(ValueError):
                    P(D.BLOCKED, code)

    def test_canonical_public_functions_close_malformed_inputs(self) -> None:
        cyclic = []
        cyclic.append(cyclic)
        cases = ((lambda: j(cyclic), F.MANIFEST_INVALID), (lambda: p("{}", required=Z, optional=Z), F.MANIFEST_INVALID), (lambda: s([1]), F.MANIFEST_INVALID), (lambda: h(None), F.CHECKSUM_INVALID), (lambda: u(None), F.PATH_UNSAFE))
        for callback, code in cases:
            self.assert_failure(callback, code)

    def test_identity_inventory_models_close_field_shapes_and_subclasses(self) -> None:
        entry = A("artifact", "file", "0644", 1, "a" * 64)
        models = ((B, dict(schema_version="v2", source_revision="a" * 40, source_tree_sha256="b" * 64, release_version="1", target="x", platform="y", profile_digests=("c" * 64,), toolchain="z", cargo_lock_sha256="d" * 64, pnpm_lock_sha256="e" * 64, release_profile="r", source_date_epoch=0)), (A, dict(path="artifact", kind="file", mode="0644", size=1, sha256="a" * 64)), (N, dict(schema_version="v2", candidate_sha256="a" * 64, entries=(entry,), inventory_sha256="b" * 64)), (T, dict(build_input_sha256="a" * 64, artifact_inventory_sha256="b" * 64, sbom_sha256="c" * 64, license_report_sha256="d" * 64, provenance_sha256="e" * 64, components=("f" * 64,), schema_revision="v1")), (Q, dict(build_input_sha256="a" * 64, product_tuple_sha256="b" * 64, subject_sha256="c" * 64)), (K, dict(build_input_sha256="a" * 64, artifact_inventory_sha256="b" * 64, manifest_schema="v2", release_profile="r", product_tuple_sha256="c" * 64, qualification_evidence_sha256s=("d" * 64,))), (S, dict(candidate_sha256="a" * 64, claim_matrix_sha256="b" * 64, review_sha256s=("c" * 64,), archive_index_sha256="d" * 64, snapshot_sha256="e" * 64)))
        for model, args in models:
            with self.assertRaises(ValueError):
                type(f"Derived{model.__name__}", (model,), {})(**args)
        with self.assertRaises(ValueError):
            B(**(models[0][1] | {"source_date_epoch": True}))
        with self.assertRaises(ValueError):
            N(**(models[2][1] | {"entries": (type("DerivedEntry", (A,), {})(**entry.__dict__),)}))
        with self.assertRaises(ValueError):
            K(**(models[5][1] | {"qualification_evidence_sha256s": (type("StringSubclass", (str,), {})("d" * 64),)}))

    def test_canonical_functions_reject_closed_type_subclasses(self) -> None:
        class GuardDict(dict):
            def items(self):
                raise AssertionError("subclass method called")
        class GuardList(list):
            def __iter__(self):
                raise AssertionError("subclass method called")
        class GuardTuple(tuple):
            def __iter__(self):
                raise AssertionError("subclass method called")
        class GuardBytes(bytes):
            def startswith(self, prefix):
                raise AssertionError("subclass method called")
        class GuardKeys(frozenset):
            def __iter__(self):
                raise AssertionError("subclass method called")
        text = type("StringSubclass", (str,), {})("artifact")
        for value in (GuardDict(), GuardList(), GuardTuple()):
            self.assert_failure(lambda value=value: j(value), F.MANIFEST_INVALID)
        self.assert_failure(lambda: p(GuardBytes(b"{}"), required=Z, optional=Z), F.MANIFEST_INVALID)
        self.assert_failure(lambda: p(b"{}", required=GuardKeys(), optional=Z), F.MANIFEST_INVALID)
        self.assert_failure(lambda: h(text), F.CHECKSUM_INVALID)
        self.assert_failure(lambda: r(text), F.PATH_UNSAFE)

    def test_relative_path_rejects_drive_relative_form(self) -> None:
        for path in ("C:artifact", "z:relative/path"):
            self.assert_failure(lambda path=path: r(path), F.PATH_UNSAFE)
