use gocode_project_owner_authority::{GitSubject, PurposeProfileV1};

use super::tests::FakeClock;
use super::{AuthorityClock as _, AuthorityGitResolver as _};

#[test]
fn unavailable_git_resolver_stays_fail_closed() {
    assert!(
        ().capture_current(&PurposeProfileV1::v1_platform_scope())
            .is_err()
    );
    assert!(
        ().resolve_subject(
            &GitSubject {
                object_format: "sha1".into(),
                commit_oid: "a".repeat(40),
                tree_oid: "b".repeat(40)
            },
            &PurposeProfileV1::v1_platform_scope()
        )
        .is_err()
    );
    assert_eq!(().repository_root(), std::path::Path::new("."));
    assert_eq!(
        FakeClock.utc_rfc3339_seconds().expect("clock"),
        "2026-08-13T00:00:00Z"
    );
}
