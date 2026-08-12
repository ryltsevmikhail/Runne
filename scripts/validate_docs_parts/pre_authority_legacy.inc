"""Run the legacy universe validator against snapshot bytes, never checkout bytes."""
import tempfile


def validate_legacy_snapshot(snapshot):
    """Materialize a disposable Git tree solely from one captured snapshot."""
    with tempfile.TemporaryDirectory(prefix="gocode-docs-snapshot-", dir="/srv/data") as name:
        root = Path(name)
        git_bytes(root, ["init", "-q", "-b", "main"])
        paths = []
        needed = set(BASE_DIGESTS) | {path for path in snapshot.entries if path.endswith((".md", ".markdown"))}
        for path in needed:
            entry = snapshot.entries.get(path)
            if entry is None:
                continue
            if entry.mode not in {"100644", "120000"}:
                continue
            target = root / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(snapshot_symlink_target(snapshot.entries, path) if entry.mode == "120000" else entry.blob_bytes)
            paths.append(path)
        if not paths:
            return ["UNIVERSE_MANIFEST_MISSING"]
        git_bytes(root, ["add", "--", *paths])
        return validate_document_universe(root, index_file=root / ".git" / "index")
