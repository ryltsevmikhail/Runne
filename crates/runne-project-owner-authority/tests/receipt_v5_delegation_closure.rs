use runne_project_owner_authority::{
    RECEIPT_SCHEMA_V5, V5_EVIDENCE_ROLE_SCOPES, V5_TRANSITION_ROLES,
};

#[test]
fn v5_receipt_declares_the_closed_transition_and_evidence_delegation_sets() {
    assert_eq!(RECEIPT_SCHEMA_V5, "runne.project-owner.authority-receipt/5");
    assert_eq!(
        V5_TRANSITION_ROLES,
        [
            "RC1_QUALIFICATION_AUTHORIZER",
            "RC2_SIGNING_AUTHORIZER",
            "RC3_PUBLICATION_AUTHORIZER",
        ]
    );
    assert_eq!(
        V5_EVIDENCE_ROLE_SCOPES,
        [
            ("RC2_NATIVE_EVIDENCE", "linux"),
            ("RC2_NATIVE_EVIDENCE", "windows"),
            ("RC2_SIGNING_REVIEWER", "signing-review"),
            ("RC2_UPDATE_ISSUER", "update-issuer"),
            ("RC3_FINAL_REVIEWER", "final-review"),
        ]
    );
}
