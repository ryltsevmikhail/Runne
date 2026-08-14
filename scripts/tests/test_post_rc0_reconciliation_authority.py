"""Fail-closed selector checks for the post-RC0 composed universe."""

from __future__ import annotations

import unittest

from scripts.tests.test_pre_authority_document_delta import fixture_repo, git, load_module, write


class PostRc0ReconciliationAuthorityTests(unittest.TestCase):
    def test_composed_needs_opaque_production_authority_and_conflicts_with_staging(self) -> None:
        module = load_module(); temporary, repo = fixture_repo(); self.addCleanup(temporary.cleanup)
        index = repo / "candidate.index"; git(repo, "read-tree", "HEAD", index=index)
        write(repo, module.COMPOSED_PATH, b'{"fixture_only":true}\n'); git(repo, "add", module.COMPOSED_PATH, index=index)
        with self.assertRaisesRegex(ValueError, "DOCS_COMPOSED_AUTHORITY_UNAVAILABLE"):
            module.select_documentation_mode(repo, index_file=index)
        write(repo, module.ARTIFACT_PATH, b"{}"); git(repo, "add", module.ARTIFACT_PATH, index=index)
        with self.assertRaisesRegex(ValueError, "DOCS_MODE_CONFLICT"):
            module.select_documentation_mode(repo, index_file=index)

    def test_fixture_profile_never_creates_production_authority_context(self) -> None:
        module = load_module(); temporary, repo = fixture_repo(); self.addCleanup(temporary.cleanup)
        with self.assertRaisesRegex(ValueError, "DOCS_COMPOSED_AUTHORITY_UNAVAILABLE"):
            module.validate_post_rc0_composed_authority(None, {"fixture_only": True})


if __name__ == "__main__":
    unittest.main()
