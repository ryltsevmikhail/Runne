use std::cell::RefCell;
use std::collections::VecDeque;
use std::path::Path;
#[allow(unused_imports)]
use std::path::PathBuf;

#[allow(unused_imports)]
use runne_project_owner_authority::{GitSubject, PurposeProfileV1};

use super::super::super::CliError;
#[allow(unused_imports)]
use super::{
    GitObjectResolver,
    system::{GitCommandRunner, GitOutput},
};

struct Fake(RefCell<VecDeque<GitOutput>>);
impl GitCommandRunner for Fake {
    fn run(&self, _: &Path, _: &[String], _: &[u8]) -> Result<GitOutput, CliError> {
        self.0
            .borrow_mut()
            .pop_front()
            .ok_or(CliError::AuthorityGit)
    }
}
fn out(status: i32, stdout: impl Into<Vec<u8>>) -> GitOutput {
    GitOutput {
        status,
        stdout: stdout.into(),
    }
}

#[test]
fn malformed_or_duplicate_object_entries_are_rejected() {
    let (commit, tree, first) = ("a".repeat(40), "b".repeat(40), "c".repeat(40));
    for entry in [
        format!("100644 blob {first}\tdocs/adr/ADR-0027-v1-platform-scope.md"),
        format!("100644 blob {first}\tdocs/adr/ADR-0027-v1-platform-scope.md\0junk\0"),
        format!("100755 blob {first}\tdocs/adr/ADR-0027-v1-platform-scope.md\0"),
    ] {
        let replies = VecDeque::from([
            out(1, []),
            out(0, []),
            out(0, ".git/objects/info/alternates\n"),
            out(0, ".git/objects/info/http-alternates\n"),
            out(0, ".git\n"),
            out(0, ".git/objects/pack\n"),
            out(0, format!("{commit}\n")),
            out(0, format!("{tree}\n")),
            out(0, []),
            out(0, entry),
        ]);
        let resolver = GitObjectResolver::new(
            PathBuf::from("/not-a-repository"),
            Fake(RefCell::new(replies)),
        );
        let subject = GitSubject {
            object_format: "sha1".into(),
            commit_oid: commit.clone(),
            tree_oid: tree.clone(),
        };
        assert!(matches!(
            resolver.resolve_subject(&subject, &PurposeProfileV1::v1_platform_scope()),
            Err(CliError::AuthorityGit)
        ));
    }
}

struct PromisorConfigRunner(RefCell<VecDeque<(Vec<String>, GitOutput)>>);
impl GitCommandRunner for PromisorConfigRunner {
    fn run(&self, _: &Path, arguments: &[String], _: &[u8]) -> Result<GitOutput, CliError> {
        let (expected, output) = self
            .0
            .borrow_mut()
            .pop_front()
            .ok_or(CliError::AuthorityGit)?;
        assert_eq!(arguments, expected);
        Ok(output)
    }
}

#[test]
fn promisor_remote_configuration_is_rejected_before_capture() {
    let commands = VecDeque::from([(
        vec![
            "config",
            "--name-only",
            "--get-regexp",
            "^(extensions\\.partialclone|remote\\..*\\.promisor)$",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect(),
        out(0, "remote.origin.promisor\n"),
    )]);
    let resolver = GitObjectResolver::new(
        PathBuf::from("/not-a-repository"),
        PromisorConfigRunner(RefCell::new(commands)),
    );
    assert!(matches!(
        resolver.capture_subject(&PurposeProfileV1::v1_platform_scope()),
        Err(CliError::AuthorityGit)
    ));
}
