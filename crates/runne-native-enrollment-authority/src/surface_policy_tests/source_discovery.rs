#![cfg(test)]

use std::fs;
use std::path::{Path, PathBuf};

const APPROVED_TEST_SOURCES: [&str; 8] = [
    "session_tests.rs",
    "surface_policy_tests.rs",
    "surface_policy_tests/attribute_audit.rs",
    "surface_policy_tests/method_audit.rs",
    "surface_policy_tests/mint_call_audit.rs",
    "surface_policy_tests/mutations.rs",
    "surface_policy_tests/source_discovery.rs",
    "surface_policy_tests/use_audit.rs",
];

pub(super) fn production_sources() -> Vec<PathBuf> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut paths = Vec::new();
    collect_production_sources(&root, &root, &mut paths);
    paths
}

fn collect_production_sources(root: &Path, directory: &Path, paths: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(directory).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            collect_production_sources(root, &path, paths);
        } else if path.extension().is_some_and(|extension| extension == "rs")
            && !is_approved_test_source(root, &path)
        {
            paths.push(path);
        }
    }
    paths.sort();
}

fn is_approved_test_source(root: &Path, path: &Path) -> bool {
    let relative = path.strip_prefix(root).unwrap().to_string_lossy();
    if !APPROVED_TEST_SOURCES.contains(&relative.as_ref()) {
        return false;
    }
    let source = fs::read_to_string(path).unwrap();
    assert!(
        source.starts_with("#![cfg(test)]"),
        "approved test source must be file-level cfg(test): {relative}"
    );
    true
}

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;

    #[test]
    fn production_tests_suffix_does_not_escape_source_audit() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "runne-native-authority-source-policy-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir(&root).unwrap();
        let backdoor = root.join("backdoor_tests.rs");
        fs::write(&backdoor, "pub fn mint_unverified() {}").unwrap();
        let mut discovered = Vec::new();
        collect_production_sources(&root, &root, &mut discovered);
        fs::remove_dir_all(&root).unwrap();

        assert_eq!(discovered, vec![backdoor]);
    }
}
