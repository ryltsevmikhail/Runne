use super::*;
use std::path::PathBuf;

#[test]
fn public_free_factories_cannot_escape_the_recursive_audit() {
    for source in [
        "pub fn raw() -> ProviderQualificationAdmissionFenceReceipt { todo!() }",
        "mod nested { pub fn raw() -> Option<Box<MeasuredQualificationAdmission>> { todo!() } }",
    ] {
        let mut audit = Audit {
            source: "runne-provider/src/latest.rs",
            ..Default::default()
        };
        audit.visit_file(&syn::parse_file(source).unwrap());
        assert!(!audit.errors.is_empty(), "free factory escaped: {source}");
    }
}

#[test]
fn free_function_cannot_impersonate_the_private_consuming_method() {
    let mut audit = Audit {
        source: DAEMON,
        ..Default::default()
    };
    audit.visit_file(&syn::parse_file("fn accept_qualification_fence() { FencedQualificationAdmission { _admission: raw, _receipt: receipt }; }").unwrap());
    assert!(!audit.errors.is_empty());
}

#[test]
fn qualified_and_ufcs_mint_calls_are_counted_and_rejected_outside_store() {
    for call in [
        "CredentialEnrollmentStoreAuthority::issue_committed_qualification_receipt(&a, admission, &issued)",
        "<CredentialEnrollmentStoreAuthority>::issue_committed_qualification_receipt(&a, admission, &issued)",
        "<Authority as Issuer>::issue_committed_qualification_receipt(&a, admission, &issued)",
        "(CredentialEnrollmentStoreAuthority::issue_committed_qualification_receipt)(&a, admission, &issued)",
    ] {
        let source = syn::parse_file(&format!("fn leak() {{ {call}; }}")).unwrap();
        let mut audit = Audit {
            source: "runne-daemon/src/latest.rs",
            ..Default::default()
        };
        audit.visit_file(&source);
        assert_eq!(audit.mint, 1, "untracked mint: {call}");
        assert!(!audit.errors.is_empty(), "foreign mint: {call}");
        let mut trusted = Audit {
            source: STORE,
            ..Default::default()
        };
        trusted.visit_file(&source);
        assert_eq!(trusted.mint, 1, "duplicate inside store must count: {call}");
    }
}

struct SourceTree(PathBuf);
impl SourceTree {
    fn new() -> Self {
        static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "runne-qualification-source-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path.canonicalize().unwrap())
    }
    fn write(&self, path: &str, source: &str) {
        let path = self.0.join(path);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, source).unwrap();
    }
    fn collected(&self) -> Vec<String> {
        let mut files = Vec::new();
        sources(&self.0, &mut files);
        let mut names = files
            .iter()
            .map(|path| {
                path.strip_prefix(&self.0)
                    .unwrap()
                    .to_str()
                    .unwrap()
                    .to_owned()
            })
            .collect::<Vec<_>>();
        names.sort();
        names
    }
}
impl Drop for SourceTree {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

#[test]
fn filename_test_substrings_and_test_named_directories_do_not_hide_production() {
    let tree = SourceTree::new();
    tree.write(
        "lib.rs",
        "mod latest; mod tests; mod nested { #[path = \"../alternate.rs\"] mod test_runtime; }",
    );
    tree.write(
        "latest.rs",
        "pub fn factory() -> ProviderQualificationAdmissionFenceReceipt { todo!() }",
    );
    tree.write("tests/mod.rs", "mod production;");
    tree.write("tests/production.rs", "fn production() {}");
    tree.write("alternate.rs", "fn production() {}");
    assert_eq!(
        tree.collected(),
        [
            "alternate.rs",
            "latest.rs",
            "lib.rs",
            "tests/mod.rs",
            "tests/production.rs"
        ]
    );
}

#[test]
fn only_proven_cfg_test_module_subtrees_are_excluded() {
    let tree = SourceTree::new();
    tree.write("lib.rs", "#[cfg(test)] #[path = \"fixture.rs\"] mod cases; mod production; #[cfg(test)] mod nested { #[path = \"../shared.rs\"] mod shared; } #[path = \"shared.rs\"] mod shared;");
    tree.write("fixture.rs", "mod child;");
    tree.write(
        "fixture/child.rs",
        "pub fn fake() -> MeasuredQualificationAdmission { todo!() }",
    );
    tree.write(
        "production.rs",
        "#[cfg(any(test, feature = \"shipping\"))] #[path = \"shipping.rs\"] mod shipping;",
    );
    tree.write("shipping.rs", "fn production() {}");
    tree.write("shared.rs", "fn production() {}");
    assert_eq!(
        tree.collected(),
        ["lib.rs", "production.rs", "shared.rs", "shipping.rs"]
    );
}

#[test]
fn cfg_test_includes_are_excluded_but_crate_roots_remain_production() {
    let tree = SourceTree::new();
    tree.write("lib.rs", "#[cfg(test)] #[path = \"lib.rs\"] mod self_test; #[cfg(test)] mod cases { include!(\"fragment.rs\"); }");
    tree.write(
        "fragment.rs",
        "pub fn fake() -> MeasuredQualificationAdmission { todo!() }",
    );
    assert_eq!(tree.collected(), ["lib.rs"]);
}
