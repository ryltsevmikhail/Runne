use std::cell::RefCell;
use std::collections::VecDeque;
use std::path::Path;
#[allow(unused_imports)]
use std::path::PathBuf;

#[allow(unused_imports)]
use runne_project_owner_authority::{GitSubject, PurposeProfileV1};
#[allow(unused_imports)]
use sha2::Digest as _;

use super::super::super::CliError;
#[allow(unused_imports)]
use super::{
    GitObjectResolver,
    system::{GitCommandRunner, GitOutput},
};

struct Expected {
    arguments: Vec<String>,
    input: Vec<u8>,
    output: GitOutput,
}

struct FakeGit(RefCell<VecDeque<Expected>>);

impl GitCommandRunner for FakeGit {
    fn run(&self, root: &Path, arguments: &[String], input: &[u8]) -> Result<GitOutput, CliError> {
        assert_eq!(root, Path::new("/not-a-repository"));
        assert!(matches!(
            arguments.first().map(String::as_str),
            Some("config" | "for-each-ref" | "rev-parse" | "status" | "ls-tree" | "cat-file")
        ));
        let expected = self
            .0
            .borrow_mut()
            .pop_front()
            .ok_or(CliError::AuthorityGit)?;
        assert_eq!(arguments, expected.arguments);
        assert_eq!(input, expected.input);
        Ok(expected.output)
    }
}

fn expect(arguments: &[&str], input: &[u8], status: i32, stdout: impl Into<Vec<u8>>) -> Expected {
    Expected {
        arguments: arguments
            .iter()
            .map(|argument| (*argument).into())
            .collect(),
        input: input.into(),
        output: GitOutput {
            status,
            stdout: stdout.into(),
        },
    }
}

fn guard_commands() -> Vec<Expected> {
    vec![
        expect(
            &[
                "config",
                "--name-only",
                "--get-regexp",
                "^(extensions\\.partialclone|remote\\..*\\.promisor)$",
            ],
            b"",
            1,
            [],
        ),
        expect(
            &["for-each-ref", "--format=%(refname)", "refs/replace/"],
            b"",
            0,
            [],
        ),
        expect(
            &["rev-parse", "--git-path", "objects/info/alternates"],
            b"",
            0,
            ".git/objects/info/alternates\n",
        ),
        expect(
            &["rev-parse", "--git-path", "objects/info/http-alternates"],
            b"",
            0,
            ".git/objects/info/http-alternates\n",
        ),
        expect(&["rev-parse", "--git-common-dir"], b"", 0, ".git\n"),
        expect(
            &["rev-parse", "--git-path", "objects/pack"],
            b"",
            0,
            ".git/objects/pack\n",
        ),
    ]
}

fn object_commands(commit: &str, first: &str, second: &str) -> Vec<Expected> {
    let paths = [
        "docs/adr/ADR-0027-v1-platform-scope.md",
        "docs/decisions/v1-platform-scope-v1.json",
    ];
    vec![
        expect(
            &["ls-tree", "--full-tree", "-z", commit, "--", paths[0]],
            b"",
            0,
            format!("100644 blob {first}\t{}\0", paths[0]),
        ),
        expect(
            &["ls-tree", "--full-tree", "-z", commit, "--", paths[1]],
            b"",
            0,
            format!("100644 blob {second}\t{}\0", paths[1]),
        ),
        expect(
            &["cat-file", "--batch"],
            format!("{first}\n{second}").as_bytes(),
            0,
            format!("{first} blob 3\none\n{second} blob 3\ntwo\n"),
        ),
    ]
}

fn capture_commands(mutated_head: bool) -> VecDeque<Expected> {
    let commit = "a".repeat(40);
    let tree = "b".repeat(40);
    let first = "c".repeat(40);
    let second = "d".repeat(40);
    let mut commands = guard_commands();
    commands.extend([
        expect(
            &["rev-parse", "--verify", concat!("HEAD^", "{commit}")],
            b"",
            0,
            format!("{commit}\n"),
        ),
        expect(
            &[
                "status",
                "--porcelain=v2",
                "-z",
                "--untracked-files=all",
                "--ignore-submodules=none",
            ],
            b"",
            0,
            [],
        ),
        expect(&["rev-parse", "--show-object-format"], b"", 0, "sha1\n"),
        expect(
            &["rev-parse", "--verify", concat!("HEAD^", "{commit}")],
            b"",
            0,
            format!("{commit}\n"),
        ),
        expect(
            &["rev-parse", "--verify", &format!("{commit}^{{tree}}")],
            b"",
            0,
            format!("{tree}\n"),
        ),
    ]);
    commands.extend(object_commands(&commit, &first, &second));
    commands.push(expect(
        &["rev-parse", "--verify", concat!("HEAD^", "{commit}")],
        b"",
        0,
        format!("{}\n", if mutated_head { "e".repeat(40) } else { commit }),
    ));
    commands.into()
}

#[test]
fn capture_retains_bytes_and_rejects_head_change_after_h3() {
    let profile = PurposeProfileV1::v1_platform_scope();
    let resolver = GitObjectResolver::new(
        PathBuf::from("/not-a-repository"),
        FakeGit(RefCell::new(capture_commands(false))),
    );
    let captured = resolver
        .capture_subject(&profile)
        .expect("immutable subject");
    assert_eq!(captured.subject.commit_oid, "a".repeat(40));
    assert_eq!(captured.bindings[0].byte_length, 3);
    assert_eq!(captured.retained_documents[0].bytes, b"one");
    let changed = GitObjectResolver::new(
        PathBuf::from("/not-a-repository"),
        FakeGit(RefCell::new(capture_commands(true))),
    );
    assert!(matches!(
        changed.capture_subject(&profile),
        Err(CliError::AuthorityGit)
    ));
}

#[test]
fn post_capture_hook_observes_retained_bytes_before_h3() {
    let profile = PurposeProfileV1::v1_platform_scope();
    let resolver = GitObjectResolver::new(
        PathBuf::from("/not-a-repository"),
        FakeGit(RefCell::new(capture_commands(false))),
    );
    let observed = std::cell::Cell::new(false);
    let captured = resolver
        .capture_subject_with_hook(&profile, |captured| {
            observed.set(captured.retained_documents[0].bytes == b"one");
        })
        .expect("h3 remains stable after the hook");
    assert!(observed.get());
    assert_eq!(
        captured.bindings[0].content_sha256,
        super::hex(&sha2::Sha256::digest(b"one").into())
    );
}

#[test]
fn resolve_supplied_subject_never_asks_for_head_or_status() {
    let (commit, tree, first, second) = (
        "a".repeat(40),
        "b".repeat(40),
        "c".repeat(40),
        "d".repeat(40),
    );
    let mut commands = guard_commands();
    commands.extend([
        expect(
            &["rev-parse", "--verify", &format!("{commit}^{{commit}}")],
            b"",
            0,
            format!("{commit}\n"),
        ),
        expect(
            &["rev-parse", "--verify", &format!("{commit}^{{tree}}")],
            b"",
            0,
            format!("{tree}\n"),
        ),
    ]);
    commands.extend(object_commands(&commit, &first, &second));
    let resolver = GitObjectResolver::new(
        PathBuf::from("/not-a-repository"),
        FakeGit(RefCell::new(commands.into())),
    );
    let subject = GitSubject {
        object_format: "sha1".into(),
        commit_oid: commit,
        tree_oid: tree,
    };
    assert!(
        resolver
            .resolve_subject(&subject, &PurposeProfileV1::v1_platform_scope())
            .is_ok()
    );
}

#[test]
fn dirty_worktree_is_rejected_before_object_resolution() {
    let commit = "a".repeat(40);
    let mut commands = guard_commands();
    commands.extend([
        expect(
            &["rev-parse", "--verify", concat!("HEAD^", "{commit}")],
            b"",
            0,
            format!("{commit}\n"),
        ),
        expect(
            &[
                "status",
                "--porcelain=v2",
                "-z",
                "--untracked-files=all",
                "--ignore-submodules=none",
            ],
            b"",
            0,
            b"? untracked\0".to_vec(),
        ),
    ]);
    let resolver = GitObjectResolver::new(
        PathBuf::from("/not-a-repository"),
        FakeGit(RefCell::new(commands.into())),
    );
    assert!(matches!(
        resolver.capture_subject(&PurposeProfileV1::v1_platform_scope()),
        Err(CliError::AuthorityDirtyWorktree)
    ));
}
