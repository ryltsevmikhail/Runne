use std::{cell::Cell, collections::BTreeMap, path::Path, sync::Mutex};

use gocode_project_owner_authority::{DocumentBinding, GitSubject, PurposeProfileV1};
use gocode_secure_store::ProjectOwnerKeyStore;
use sha2::{Digest as _, Sha256};

use super::super::git::CapturedSubject;
use super::tests::{FakeClock, FakeFiles, FakeRng, FakeStore, FakeTty, runner};
use super::{
    AuthorityCommandRunner, AuthorityFiles, AuthorityGitResolver, AuthorityTty, InitRequest,
    SignRequest, VerifyRequest,
};
use crate::CliError;

struct CapturingGit {
    capture_calls: Cell<usize>,
    resolve_calls: Cell<usize>,
}
impl AuthorityGitResolver for CapturingGit {
    fn capture_current(&self, _: &PurposeProfileV1) -> Result<CapturedSubject, CliError> {
        self.capture_calls.set(self.capture_calls.get() + 1);
        Ok(Self::captured())
    }
    fn resolve_subject(
        &self,
        subject: &GitSubject,
        _: &PurposeProfileV1,
    ) -> Result<CapturedSubject, CliError> {
        self.resolve_calls.set(self.resolve_calls.get() + 1);
        if *subject != Self::subject() {
            return Err(CliError::AuthorityUnavailable);
        }
        Ok(Self::captured())
    }
    fn repository_root(&self) -> &Path {
        Path::new(".")
    }
}
impl CapturingGit {
    fn subject() -> GitSubject {
        GitSubject {
            object_format: "sha1".into(),
            commit_oid: "a".repeat(40),
            tree_oid: "b".repeat(40),
        }
    }
    fn captured() -> CapturedSubject {
        CapturedSubject::from_documents(
            Self::subject(),
            vec![
                document("docs/adr/ADR-0027-v1-platform-scope.md", 'c', b"adr", None),
                document(
                    "docs/decisions/v1-platform-scope-v1.json",
                    'd',
                    b"json",
                    Some("gocode.governance.v1-platform-scope-decision/1".into()),
                ),
            ],
        )
    }
}
fn document(
    path: &str,
    oid: char,
    bytes: &[u8],
    schema_id: Option<String>,
) -> (DocumentBinding, Vec<u8>) {
    (
        DocumentBinding {
            path: path.into(),
            mode: "100644".into(),
            blob_oid: oid.to_string().repeat(40),
            content_sha256: hex(&Sha256::digest(bytes)),
            byte_length: bytes.len() as u64,
            schema_id,
        },
        bytes.to_vec(),
    )
}
struct RejectingTty;
impl AuthorityTty for RejectingTty {
    fn confirm(&self, _: &str, _: &str) -> Result<(), CliError> {
        Err(CliError::AuthorityUnavailable)
    }
}

#[test]
fn sign_confirmation_failure_never_signs_or_writes_a_receipt() {
    let store = FakeStore::new();
    let files = files();
    let mut rng = FakeRng;
    runner(&store, &files, &mut rng)
        .init(InitRequest {
            trust_out: "docs/trust.json".into(),
        })
        .expect("init");
    let git = CapturingGit {
        capture_calls: Cell::new(0),
        resolve_calls: Cell::new(0),
    };
    let mut rng = FakeRng;
    let command =
        AuthorityCommandRunner::new(&store, &git, &RejectingTty, &mut rng, &FakeClock, &files);
    assert!(
        command
            .sign(SignRequest {
                trust_config: "docs/trust.json".into(),
                receipt_out: "docs/evidence/receipt.json".into()
            })
            .is_err()
    );
    assert_eq!(store.state.lock().expect("state").sign_calls, 0);
    assert!(
        files
            .read_repo_public("docs/evidence/receipt.json")
            .is_err()
    );
    assert_eq!(git.capture_calls.get(), 1);
}

#[test]
fn sign_writes_a_canonical_byte_bound_receipt_after_one_confirmation() {
    let store = FakeStore::new();
    let files = files();
    let mut rng = FakeRng;
    runner(&store, &files, &mut rng)
        .init(InitRequest {
            trust_out: "docs/trust.json".into(),
        })
        .expect("init");
    let git = CapturingGit {
        capture_calls: Cell::new(0),
        resolve_calls: Cell::new(0),
    };
    let mut rng = FakeRng;
    let output = AuthorityCommandRunner::new(&store, &git, &FakeTty, &mut rng, &FakeClock, &files)
        .sign(SignRequest {
            trust_config: "docs/trust.json".into(),
            receipt_out: "docs/evidence/receipt.json".into(),
        })
        .expect("sign");
    let receipt = files
        .read_repo_public("docs/evidence/receipt.json")
        .expect("receipt");
    assert!(receipt.ends_with(b"\n"));
    assert_eq!(store.state.lock().expect("state").sign_calls, 1);
    assert_eq!(git.capture_calls.get(), 1);
    let digest: [u8; 32] = Sha256::digest(&receipt).into();
    assert_eq!(output.artifacts[0].sha256, digest);
}

#[test]
fn sign_does_not_reopen_after_publication_commit() {
    let store = FakeStore::new();
    let mut files = files();
    let mut rng = FakeRng;
    runner(&store, &files, &mut rng)
        .init(InitRequest {
            trust_out: "docs/trust.json".into(),
        })
        .expect("init");
    *files.write_count.lock().expect("count") = 0;
    files.fail_reads_after_write = true;
    let git = CapturingGit {
        capture_calls: Cell::new(0),
        resolve_calls: Cell::new(0),
    };
    let mut rng = FakeRng;
    AuthorityCommandRunner::new(&store, &git, &FakeTty, &mut rng, &FakeClock, &files)
        .sign(SignRequest {
            trust_config: "docs/trust.json".into(),
            receipt_out: "docs/evidence/receipt.json".into(),
        })
        .expect("committed sign");
    assert!(
        files
            .bytes
            .lock()
            .expect("bytes")
            .contains_key("docs/evidence/receipt.json")
    );
}

#[test]
fn verify_resolves_the_receipt_subject_without_capture_or_store() {
    let store = FakeStore::new();
    let files = files();
    let mut rng = FakeRng;
    runner(&store, &files, &mut rng)
        .init(InitRequest {
            trust_out: "docs/trust.json".into(),
        })
        .expect("init");
    let signer_git = CapturingGit {
        capture_calls: Cell::new(0),
        resolve_calls: Cell::new(0),
    };
    let mut rng = FakeRng;
    AuthorityCommandRunner::new(&store, &signer_git, &FakeTty, &mut rng, &FakeClock, &files)
        .sign(SignRequest {
            trust_config: "docs/trust.json".into(),
            receipt_out: "docs/evidence/receipt.json".into(),
        })
        .expect("sign");
    let floor = store
        .read_anchor_floor("gocode")
        .expect("floor")
        .expect("anchor");
    let verify_git = CapturingGit {
        capture_calls: Cell::new(0),
        resolve_calls: Cell::new(0),
    };
    let mut rng = FakeRng;
    let output =
        AuthorityCommandRunner::new(&store, &verify_git, &FakeTty, &mut rng, &FakeClock, &files)
            .verify(&VerifyRequest {
                trust_config: "docs/trust.json".into(),
                receipt: "docs/evidence/receipt.json".into(),
                anchor_epoch: floor.highest_key_epoch(),
                anchor_trust_sha256: floor.accepted_trust_config_sha256(),
            })
            .expect("verify");
    assert_eq!(output.stdout, b"AUTHORITY_RECEIPT_VERIFIED");
    assert_eq!(verify_git.capture_calls.get(), 0);
    assert_eq!(verify_git.resolve_calls.get(), 1);
    assert_eq!(store.state.lock().expect("state").sign_calls, 1);
}

#[test]
fn verify_rejects_a_substituted_anchor_without_store_access() {
    let store = FakeStore::new();
    let files = files();
    let mut rng = FakeRng;
    runner(&store, &files, &mut rng)
        .init(InitRequest {
            trust_out: "docs/trust.json".into(),
        })
        .expect("init");
    let signer_git = CapturingGit {
        capture_calls: Cell::new(0),
        resolve_calls: Cell::new(0),
    };
    let mut rng = FakeRng;
    AuthorityCommandRunner::new(&store, &signer_git, &FakeTty, &mut rng, &FakeClock, &files)
        .sign(SignRequest {
            trust_config: "docs/trust.json".into(),
            receipt_out: "docs/evidence/receipt.json".into(),
        })
        .expect("sign");
    let floor = store
        .read_anchor_floor("gocode")
        .expect("floor")
        .expect("anchor");
    let git = CapturingGit {
        capture_calls: Cell::new(0),
        resolve_calls: Cell::new(0),
    };
    let mut rng = FakeRng;
    assert!(
        AuthorityCommandRunner::new(&store, &git, &FakeTty, &mut rng, &FakeClock, &files)
            .verify(&VerifyRequest {
                trust_config: "docs/trust.json".into(),
                receipt: "docs/evidence/receipt.json".into(),
                anchor_epoch: floor.highest_key_epoch(),
                anchor_trust_sha256: [0; 32]
            })
            .is_err()
    );
    assert_eq!(git.capture_calls.get(), 0);
    assert_eq!(git.resolve_calls.get(), 1);
}
fn files() -> FakeFiles {
    FakeFiles {
        fail_on_write: Mutex::new(None),
        write_count: Mutex::new(0),
        fail_reads_after_write: false,
        bytes: Mutex::new(BTreeMap::new()),
    }
}
fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut value = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(value, "{byte:02x}");
    }
    value
}
