use std::path::Path;

pub(super) fn has_installed_candidate(db_path: &str) -> bool {
    let Some(runtime_root) = Path::new(db_path).parent().and_then(Path::parent) else {
        return false;
    };
    let updates = runtime_root.join("updates");
    std::fs::symlink_metadata(&updates)
        .is_ok_and(|metadata| metadata.is_dir() && !metadata.file_type().is_symlink())
        && has_numbered_journal(&updates, "install-state.json")
        && has_numbered_journal(&updates, "trust-state.json")
}

fn has_numbered_journal(updates: &Path, base: &str) -> bool {
    const MAX_CANDIDATE_ENTRIES: usize = 512;
    let prefix = format!("{base}.");
    let Ok(entries) = std::fs::read_dir(updates) else {
        return false;
    };
    entries
        .take(MAX_CANDIDATE_ENTRIES)
        .filter_map(Result::ok)
        .any(|entry| {
            let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
                return false;
            };
            let Some(sequence) = name
                .strip_prefix(&prefix)
                .and_then(|rest| rest.strip_suffix(".json"))
                .and_then(|value| value.parse::<u64>().ok())
            else {
                return false;
            };
            sequence > 0
                && std::fs::symlink_metadata(entry.path())
                    .is_ok_and(|metadata| metadata.file_type().is_file())
        })
}

#[cfg(test)]
mod tests {
    use super::has_installed_candidate;

    #[test]
    fn candidate_requires_both_regular_installed_journals() {
        let temporary = tempfile::tempdir().unwrap();
        let profile = temporary.path();
        let runtime_root = profile.join("bundled-runtime");
        let db_path = runtime_root.join("runne-daemon/event-log.db");
        std::fs::create_dir_all(runtime_root.join("updates")).unwrap();
        assert!(!has_installed_candidate(db_path.to_str().unwrap()));
        std::fs::write(
            runtime_root.join("updates/install-state.json.1.json"),
            b"candidate",
        )
        .unwrap();
        std::fs::write(
            runtime_root.join("updates/trust-state.json.1.json"),
            b"candidate",
        )
        .unwrap();
        assert!(has_installed_candidate(db_path.to_str().unwrap()));
        std::fs::remove_file(runtime_root.join("updates/trust-state.json.1.json")).unwrap();
        assert!(!has_installed_candidate(db_path.to_str().unwrap()));
        std::fs::remove_file(runtime_root.join("updates/install-state.json.1.json")).unwrap();
        let wrong_parent = profile.join("updates");
        std::fs::create_dir_all(&wrong_parent).unwrap();
        std::fs::write(
            wrong_parent.join("install-state.json.1.json"),
            b"wrong parent",
        )
        .unwrap();
        std::fs::write(
            wrong_parent.join("trust-state.json.1.json"),
            b"wrong parent",
        )
        .unwrap();
        assert!(!has_installed_candidate(db_path.to_str().unwrap()));
    }

    #[test]
    fn unsuffixed_and_temporary_journals_are_not_installed_candidates() {
        let temporary = tempfile::tempdir().unwrap();
        let runtime_root = temporary.path().join("bundled-runtime");
        let db_path = runtime_root.join("runne-daemon/event-log.db");
        let updates = runtime_root.join("updates");
        std::fs::create_dir_all(&updates).unwrap();
        std::fs::write(updates.join("install-state.json"), b"legacy").unwrap();
        std::fs::write(updates.join("trust-state.json"), b"legacy").unwrap();
        std::fs::write(updates.join("install-state.json.1.tmp"), b"partial").unwrap();
        std::fs::write(updates.join("trust-state.json.1.tmp"), b"partial").unwrap();
        assert!(!has_installed_candidate(db_path.to_str().unwrap()));
    }
}
