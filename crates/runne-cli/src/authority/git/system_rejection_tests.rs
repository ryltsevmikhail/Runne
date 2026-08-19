use super::{GitObjectResolver, system::SystemGit};
use runne_project_owner_authority::PurposeProfileV1;
use std::fs;
#[cfg(unix)]
#[allow(unused_imports)]
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use std::process::Command;
use tempfile::tempdir;
fn git(root: &Path, args: &[&str]) {
    assert!(
        Command::new("git")
            .current_dir(root)
            .args(args)
            .status()
            .expect("git")
            .success()
    );
}
fn rejects(f: impl FnOnce(&Path)) {
    let d = tempdir().expect("temp");
    let r = d.path();
    git(r, &["init", "-q"]);
    git(r, &["config", "user.email", "a@b"]);
    git(r, &["config", "user.name", "a"]);
    fs::create_dir_all(r.join("docs/adr")).expect("dir");
    fs::create_dir_all(r.join("docs/decisions")).expect("dir");
    fs::write(r.join("docs/adr/ADR-0027-v1-platform-scope.md"), b"a").expect("file");
    fs::write(r.join("docs/decisions/v1-platform-scope-v1.json"), b"{}").expect("file");
    git(r, &["add", "."]);
    git(r, &["commit", "-qm", "a"]);
    f(r);
    assert!(
        GitObjectResolver {
            root: r.to_owned(),
            runner: SystemGit
        }
        .capture_subject(&PurposeProfileV1::v1_platform_scope())
        .is_err()
    );
}
#[test]
fn rejects_dirty_and_alternates() {
    rejects(|r| fs::write(r.join("untracked"), b"x").expect("file"));
    for n in ["alternates", "http-alternates"] {
        rejects(|r| {
            let p = r.join(".git/objects/info");
            fs::create_dir_all(&p).expect("dir");
            fs::write(p.join(n), b"x").expect("file");
        });
    }
}
#[cfg(unix)]
#[test]
fn rejects_required_executable() {
    rejects(|r| {
        let p = r.join("docs/adr/ADR-0027-v1-platform-scope.md");
        let mut m = fs::metadata(&p).expect("meta").permissions();
        m.set_mode(0o755);
        fs::set_permissions(p, m).expect("mode");
        git(r, &["add", "."]);
        git(r, &["commit", "-qm", "x"]);
    });
}
#[test]
fn rejects_effective_promisor() {
    rejects(|r| git(r, &["config", "remote.origin.promisor", "true"]));
}

#[test]
fn rejects_effective_partial_clone() {
    rejects(|r| git(r, &["config", "extensions.partialClone", "origin"]));
}
