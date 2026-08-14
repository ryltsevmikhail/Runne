"""Fail-closed repair pin for the one mixed pre-authority predecessor."""
REPAIR_PREDECESSOR_COMMIT = "1ea5dec17c36488819194b1d6aa443d932593966"
REPAIR_PREDECESSOR_TREE = "5d0e8167e73614ea8ef513ebc9d963770f61093b"
REPAIR_PREDECESSOR_COMMIT_SHA256 = "33cde8fc635e85f52732535ee74f061c432730f0a7f956ab6898bb069ee39983"
REPAIR_PREDECESSOR_TREE_SHA256 = "7a04c76353c9c46a4395c85c7afa92716788db16a78bbee3668fa952ea30a73a"
REPAIR_MARKERS = {
    ARTIFACT_PATH: ("100644", "addb4684a12527ef93a29503d88473f39ad764ab", "b0f4a92f07df9efd78aebf5dee5ef682e6698ad92fc3b21957e37705ff817d54"),
    "docs/authority/PRE_AUTHORITY_DOCUMENT_OVERLAY_V2.json": ("100644", "45773d1a0a3bc959cf339f043b0b03e3b92db1d5", "70e533bb5734b1f2e466932ab3f73a87eb875ef99f74e0cbfa44eb4dfbec2c67"),
}


def is_exact_overlay_repair_predecessor(snapshot):
    if snapshot.head_oid != REPAIR_PREDECESSOR_COMMIT:
        return False
    try:
        if (git_bytes(snapshot.repo, ["rev-parse", f"{REPAIR_PREDECESSOR_COMMIT}^{{tree}}"]).decode().strip() != REPAIR_PREDECESSOR_TREE
                or digest(git_bytes(snapshot.repo, ["cat-file", "commit", REPAIR_PREDECESSOR_COMMIT])) != REPAIR_PREDECESSOR_COMMIT_SHA256
                or digest(git_bytes(snapshot.repo, ["cat-file", "tree", REPAIR_PREDECESSOR_TREE])) != REPAIR_PREDECESSOR_TREE_SHA256):
            return False
        entries = snapshot.head_entries()
        if COMPOSED_PATH in entries:
            return False
        for path, (mode, oid, expected) in REPAIR_MARKERS.items():
            if entries.get(path) != (mode, oid) or digest(git_bytes(snapshot.repo, ["cat-file", "blob", oid])) != expected:
                return False
    except ValueError:
        return False
    return True
