import json
import pathlib
import unittest
import hashlib
from copy import deepcopy

from scripts.tests.test_project_owner_authority_schemas import _errors


ROOT = pathlib.Path(__file__).parents[2]
CORPUS = ROOT / "crates/runne-promotion-contracts/tests/fixtures/rc3_v2_corpus.json"


class Rc3V2SchemaTests(unittest.TestCase):
    def test_shared_corpus_has_digest_coherent_graph_and_semantic_mutations(self) -> None:
        corpus = json.loads(CORPUS.read_text(encoding="utf-8"))
        canonical = lambda value: json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
        manifest, review, authorization = (corpus[key] for key in ("publication_manifest", "final_review", "authorization"))
        manifest_digest = hashlib.sha256(canonical(manifest)).hexdigest()
        review_digest = hashlib.sha256(canonical(review)).hexdigest()
        self.assertEqual(review["publication_manifest_sha256"], manifest_digest)
        self.assertEqual(authorization["publication_manifest_sha256"], manifest_digest)
        self.assertEqual(authorization["final_review_sha256"], review_digest)
        self.assertEqual(corpus["mutations"], ["human_alias", "invalid_window", "identity_overlap", "mixed_manifest_digest"])
        self.assertEqual(len(set(manifest["human_artifacts"].values())), 6)
        self.assertLess(review["valid_from"], review["expires_at"])
        for authorizer, executor in zip(authorization["authorizer"].values(), authorization["executor"].values(), strict=True):
            self.assertNotEqual(authorizer, executor)
    def test_v2_leaf_schemas_are_closed_and_match_the_shared_manifest(self) -> None:
        corpus = json.loads(CORPUS.read_text(encoding="utf-8"))
        schemas = {
            "publication_manifest": "publication-manifest-v2.schema.json",
            "final_review": "rc3-final-review-v1.schema.json",
            "authorization": "rc3-publication-authorization-v2.schema.json",
        }
        for key, name in schemas.items():
            schema = json.loads((ROOT / "docs/schemas" / name).read_text(encoding="utf-8"))
            self.assertFalse(_errors(schema, corpus[key]), key)
            invalid = deepcopy(corpus[key])
            invalid["unknown"] = True
            self.assertTrue(_errors(schema, invalid), key)

    def test_manifest_schema_rejects_public_and_human_artifact_mutations(self) -> None:
        corpus = json.loads(CORPUS.read_text(encoding="utf-8"))
        schema = json.loads((ROOT / "docs/schemas/publication-manifest-v2.schema.json").read_text(encoding="utf-8"))
        value = corpus["publication_manifest"]
        for path in (("human_artifacts", "checksums"), ("public_artifacts",), ("macos_preview_excluded",)):
            invalid = deepcopy(value)
            parent = invalid
            for key in path[:-1]:
                parent = parent[key]
            if path[-1] == "checksums":
                parent.pop(path[-1])
            elif path[-1] == "public_artifacts":
                parent[path[-1]].reverse()
            else:
                parent[path[-1]] = False
            self.assertTrue(_errors(schema, invalid), path)


if __name__ == "__main__":
    unittest.main()
