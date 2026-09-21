use std::fs;
#[cfg(unix)]
#[allow(unused_imports)]
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use std::process::Command;

#[allow(unused_imports)]
use runne_project_owner_authority::PurposeProfileV1;
#[allow(unused_imports)]
use tempfile::tempdir;

#[allow(unused_imports)]
use super::{GitObjectResolver, system::SystemGit};

fn git(root: &Path, arguments: &[&str]) -> Vec<u8> {
    let output = Command::new("git")
        .current_dir(root)
        .args(arguments)
        .output()
        .expect("run git");
    assert!(
        output.status.success(),
        "git {arguments:?}: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );
    output.stdout
}

fn write_profile_documents(root: &Path) {
    let adr = root.join("docs/adr");
    let decisions = root.join("docs/decisions");
    fs::create_dir_all(&adr).expect("create adr");
    fs::create_dir_all(&decisions).expect("create decisions");
    fs::write(adr.join("ADR-0027-v1-platform-scope.md"), b"adr\n").expect("write adr");
    fs::write(decisions.join("v1-platform-scope-v1.json"), b"{}\n").expect("write decision");
}

fn initialize(root: &Path) {
    git(root, &["init", "-q"]);
    // Pin deterministic line endings: the host default (core.autocrlf=true
    // on Windows) makes `worktree add` and submodule checkouts rewrite files
    // with CRLF, which the size-based dirty check then reports as changes.
    git(root, &["config", "core.autocrlf", "false"]);
    // Pin byte-stable checkouts across clones: `submodule add` creates a
    // fresh clone whose checkout follows the HOST configuration (repo-local
    // settings are not inherited by the clone), while production capture
    // reads with the hardened config-free environment where CRLF worktree
    // bytes differ from the committed LF blobs. `* -text` disables
    // end-of-line conversion everywhere, so every checkout of these
    // repositories is byte-identical regardless of the host configuration.
    fs::write(root.join(".gitattributes"), b"* -text\n").expect("write gitattributes");
    git(root, &["config", "user.email", "authority@example.invalid"]);
    git(root, &["config", "user.name", "Authority Test"]);
    write_profile_documents(root);
    git(root, &["add", "."]);
    git(root, &["commit", "-qm", "subject"]);
}

fn snapshot(root: &Path) -> Vec<Vec<u8>> {
    [
        ["show-ref"].as_slice(),
        ["config", "--local", "--list"].as_slice(),
        ["count-objects", "-v"].as_slice(),
        ["status", "--porcelain=v2", "-z"].as_slice(),
    ]
    .into_iter()
    .map(|arguments| git(root, arguments))
    .collect()
}

fn collect_git_files(base: &Path, current: &Path, files: &mut Vec<(String, Vec<u8>)>) {
    for entry in current.read_dir().expect("read git directory") {
        let entry = entry.expect("git directory entry");
        let path = entry.path();
        if path.is_dir() {
            collect_git_files(base, &path, files);
        } else if path.is_file() {
            files.push((
                path.strip_prefix(base)
                    .expect("relative path")
                    .display()
                    .to_string(),
                fs::read(path).expect("read git file"),
            ));
        }
    }
}

fn raw_git_state(root: &Path) -> Vec<(String, Vec<u8>)> {
    let git_dir =
        String::from_utf8(git(root, &["rev-parse", "--git-common-dir"])).expect("git dir");
    let base = root.join(git_dir.trim());
    let mut files = Vec::new();
    collect_git_files(&base, &base, &mut files);
    files.sort_by(|left, right| left.0.cmp(&right.0));
    files
}

#[test]
fn system_git_captures_immutable_profile_without_repository_mutation() {
    let directory = tempdir().expect("temporary repository");
    let root = directory.path();
    initialize(root);
    let before = (snapshot(root), raw_git_state(root));
    let resolver = GitObjectResolver {
        root: root.to_owned(),
        runner: SystemGit,
    };
    let captured = resolver
        .capture_subject(&PurposeProfileV1::v1_platform_scope())
        .expect("capture");
    assert_eq!(captured.retained_documents.len(), 2);
    assert_eq!(before, (snapshot(root), raw_git_state(root)));
}

#[test]
fn system_git_accepts_a_linked_worktree_using_the_common_object_directory() {
    let directory = tempdir().expect("temporary repository");
    let root = directory.path();
    initialize(root);
    let linked = directory.path().join("linked");
    git(
        root,
        &[
            "worktree",
            "add",
            "-qb",
            "linked-authority",
            linked.to_str().expect("utf8 path"),
        ],
    );
    let resolver = GitObjectResolver {
        root: linked,
        runner: SystemGit,
    };
    assert!(
        resolver
            .capture_subject(&PurposeProfileV1::v1_platform_scope())
            .is_ok()
    );
}

#[test]
fn system_git_rejects_promisor_in_linked_worktree_config() {
    let directory = tempdir().expect("temporary repository");
    let root = directory.path();
    initialize(root);
    git(root, &["config", "extensions.worktreeConfig", "true"]);
    let linked = root.join("linked-promisor");
    git(
        root,
        &[
            "worktree",
            "add",
            "-qb",
            "promisor",
            linked.to_str().expect("utf8 path"),
        ],
    );
    git(
        &linked,
        &["config", "--worktree", "remote.origin.promisor", "true"],
    );
    let resolver = GitObjectResolver {
        root: linked,
        runner: SystemGit,
    };
    assert!(
        resolver
            .capture_subject(&PurposeProfileV1::v1_platform_scope())
            .is_err()
    );
}

#[test]
fn system_git_allows_an_unrelated_pinned_gitlink() {
    let directory = tempdir().expect("temporary repository");
    let root = directory.path();
    initialize(root);
    let child = tempdir().expect("temporary child repository");
    initialize(child.path());
    git(
        root,
        &[
            "-c",
            "protocol.file.allow=always",
            "submodule",
            "add",
            "-q",
            child.path().to_str().expect("utf8 path"),
            "upstream/opencode",
        ],
    );
    git(root, &["commit", "-qm", "pinned gitlink"]);
    let resolver = GitObjectResolver {
        root: root.to_owned(),
        runner: SystemGit,
    };
    assert!(
        resolver
            .capture_subject(&PurposeProfileV1::v1_platform_scope())
            .is_ok()
    );
}

#[test]
fn system_git_rejects_a_dirty_nested_submodule() {
    let directory = tempdir().expect("temporary repository");
    let root = directory.path();
    initialize(root);
    let child = tempdir().expect("temporary child repository");
    initialize(child.path());
    git(
        root,
        &[
            "-c",
            "protocol.file.allow=always",
            "submodule",
            "add",
            "-q",
            child.path().to_str().expect("utf8 path"),
            "upstream/opencode",
        ],
    );
    git(root, &["commit", "-qm", "pinned gitlink"]);
    fs::write(root.join("upstream/opencode/untracked"), b"dirty\n").expect("dirty submodule");
    let resolver = GitObjectResolver {
        root: root.to_owned(),
        runner: SystemGit,
    };
    assert!(
        resolver
            .capture_subject(&PurposeProfileV1::v1_platform_scope())
            .is_err()
    );
}

#[test]
fn system_git_rejects_a_required_gitlink() {
    let directory = tempdir().expect("temporary repository");
    let root = directory.path();
    initialize(root);
    let child = tempdir().expect("temporary child repository");
    initialize(child.path());
    let child_head =
        String::from_utf8(git(child.path(), &["rev-parse", "HEAD"])).expect("child head");
    let cache_info = format!(
        "160000,{},docs/adr/ADR-0027-v1-platform-scope.md",
        child_head.trim()
    );
    git(root, &["update-index", "--add", "--cacheinfo", &cache_info]);
    git(root, &["commit", "-qm", "required gitlink"]);
    let resolver = GitObjectResolver {
        root: root.to_owned(),
        runner: SystemGit,
    };
    assert!(
        resolver
            .capture_subject(&PurposeProfileV1::v1_platform_scope())
            .is_err()
    );
}

#[test]
fn post_capture_checkout_mutation_keeps_retained_bytes_and_h3_detects_only_head_change() {
    let directory = tempdir().expect("temporary repository");
    let root = directory.path();
    initialize(root);
    let document = root.join("docs/adr/ADR-0027-v1-platform-scope.md");
    let resolver = GitObjectResolver {
        root: root.to_owned(),
        runner: SystemGit,
    };
    let captured = resolver
        .capture_subject_with_hook(&PurposeProfileV1::v1_platform_scope(), |_| {
            fs::write(&document, b"changed checkout\n").expect("mutate after read");
        })
        .expect("head did not change");
    assert_eq!(captured.retained_documents[0].bytes, b"adr\n");
    assert!(git(root, &["status", "--porcelain=v2", "-z"]).starts_with(b"1 "));
}
