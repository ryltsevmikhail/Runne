use gocode_application::ports::{
    ProjectWorkspaceRepository, ProjectWorkspaceRepositoryError as Error, RootAdmissionConsumption,
};
use gocode_domain::id::WorkspaceId;

use super::support::*;

#[test]
fn admission_digest_is_part_of_the_bind_receipt_fingerprint() {
    let database = Database::new("project-workspace-admission-digest");
    let repository = database.repository();
    create_project(&repository);
    create_workspace(&repository);
    let first = repository
        .bind_workspace_root(
            "owner",
            command(4),
            &key("bind-root"),
            WorkspaceId::from_bytes(WORKSPACE),
            1,
            RootAdmissionConsumption {
                nonce: [0x31; 16],
                admission_digest: [0x41; 32],
            },
        )
        .unwrap();
    assert_eq!(first.version(), 2);
    assert_eq!(
        repository.bind_workspace_root(
            "owner",
            command(4),
            &key("bind-root"),
            WorkspaceId::from_bytes(WORKSPACE),
            1,
            RootAdmissionConsumption {
                nonce: [0x31; 16],
                admission_digest: [0x42; 32]
            },
        ),
        Err(Error::Conflict)
    );
}

#[test]
fn duplicate_nonce_rolls_back_the_losing_workspace_and_receipt() {
    let database = Database::new("project-workspace-nonce-atomicity");
    let repository = database.repository();
    create_project(&repository);
    create_workspace(&repository);
    repository
        .create_workspace(
            "owner",
            command(41),
            &key("second-workspace"),
            workspace([0x22; 16], PROJECT, "Two"),
        )
        .unwrap();
    repository
        .bind_workspace_root(
            "owner",
            command(42),
            &key("first-bind"),
            WorkspaceId::from_bytes(WORKSPACE),
            1,
            RootAdmissionConsumption {
                nonce: [0x66; 16],
                admission_digest: [0x67; 32],
            },
        )
        .unwrap();
    assert_eq!(
        repository.bind_workspace_root(
            "owner",
            command(43),
            &key("losing-bind"),
            WorkspaceId::from_bytes([0x22; 16]),
            1,
            RootAdmissionConsumption {
                nonce: [0x66; 16],
                admission_digest: [0x68; 32]
            },
        ),
        Err(Error::Conflict),
    );
    assert_eq!(
        repository
            .get_workspace("owner", WorkspaceId::from_bytes([0x22; 16]))
            .unwrap()
            .version(),
        1
    );
    assert_eq!(
        database
            .connection()
            .query_row("SELECT COUNT(*) FROM root_admission_nonces", [], |row| row
                .get::<_, i64>(
                0
            ))
            .unwrap(),
        1
    );
}
