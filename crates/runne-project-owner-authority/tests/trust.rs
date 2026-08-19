use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signer, SigningKey};
use runne_project_owner_authority::{
    AuthorityError, ProjectOwnerTrustConfigV1, SchemaDigest, TrustAnchorState,
    bootstrap_fingerprint, canonical_genesis, canonical_genesis_without_pop, framed_transcript,
    key_id, verify_anchor, verify_genesis, verify_trust_config,
};

const POP_DOMAIN: &[u8] = b"runne.project-owner.genesis-pop/1";

fn config() -> ProjectOwnerTrustConfigV1 {
    let signing = SigningKey::from_bytes(&[7; 32]);
    let mut config = ProjectOwnerTrustConfigV1 {
        schema_version: "runne.project-owner.trust-config/1".into(),
        repository_id: "runne".into(),
        role: "PROJECT_OWNER".into(),
        epoch: 1,
        key_id: key_id(&signing.verifying_key().to_bytes()),
        public_key: signing.verifying_key().to_bytes(),
        schema_digests: vec![SchemaDigest {
            schema_id: "runne.project-owner.authority-receipt/1".into(),
            schema_sha256: [3; 32],
        }],
        proof_of_possession: [0; 64],
        predecessor: None,
    };
    sign_pop(&mut config);
    config
}

fn sign_pop(config: &mut ProjectOwnerTrustConfigV1) {
    sign_pop_for_domain(config, POP_DOMAIN);
}

fn sign_pop_for_domain(config: &mut ProjectOwnerTrustConfigV1, domain: &[u8]) {
    let signing = SigningKey::from_bytes(&[7; 32]);
    let message = framed_transcript(
        domain,
        &canonical_genesis_without_pop(config).expect("canonical"),
    )
    .expect("frame");
    config.proof_of_possession = signing.sign(&message).to_bytes();
}

fn anchor(config: &ProjectOwnerTrustConfigV1) -> TrustAnchorState {
    TrustAnchorState::confirmed("runne".into(), 1, config.sha256().expect("sha"))
}

#[test]
fn verifies_genesis_pop_key_id_and_golden_fingerprint() {
    let config = config();
    verify_genesis(&config).expect("valid genesis");
    assert!(
        String::from_utf8(canonical_genesis(&config).expect("canonical"))
            .expect("utf8")
            .contains(&format!(
                "\"public_key\":\"{}\"",
                URL_SAFE_NO_PAD.encode(config.public_key)
            ))
    );
    assert_eq!(
        canonical_genesis(&config).expect("canonical"),
        b"{\"epoch\":1,\"key_id\":\"57d626391d1c221f9bcb414d494417af4450cd70060a0dd292176d53d1ebf5c7\",\"predecessor\":null,\"proof_of_possession\":\"Zod6Ld6cn9xnLupmCVLn-HtV-y5y7VW3-W_t4pnuQEEQV7_9hrFZuV7hf7U0TBUgQRuy-cUGw9c7TTWPOpURCQ\",\"public_key\":\"6kpsY-KcUgq-9VB7Ey7F-ZVHdq6-vnuSQh7qaRRG0iw\",\"repository_id\":\"runne\",\"role\":\"PROJECT_OWNER\",\"schema_digests\":[{\"schema_id\":\"runne.project-owner.authority-receipt/1\",\"schema_sha256\":\"0303030303030303030303030303030303030303030303030303030303030303\"}],\"schema_version\":\"runne.project-owner.trust-config/1\"}\n"
    );
    assert_eq!(
        bootstrap_fingerprint(&config).expect("fingerprint"),
        "3fbe93b46fb3885e8c050ee9eb063f47120691f93451cc21c4ac13ca6c20eadb"
    );
    assert_eq!(key_id(&config.public_key), config.key_id);
}

#[test]
fn rejects_bad_pop_wrong_key_and_noncanonical_schema_digests() {
    let mut invalid_pop = config();
    invalid_pop.proof_of_possession[0] ^= 1;
    assert_eq!(
        verify_genesis(&invalid_pop),
        Err(AuthorityError::InvalidProofOfPossession)
    );
    let mut invalid_key = config();
    invalid_key.key_id = [0; 32];
    assert_eq!(
        verify_genesis(&invalid_key),
        Err(AuthorityError::InvalidKeyId)
    );
    let mut invalid_schemas = config();
    invalid_schemas
        .schema_digests
        .push(invalid_schemas.schema_digests[0].clone());
    assert_eq!(
        verify_genesis(&invalid_schemas),
        Err(AuthorityError::InvalidSchemaDigests)
    );
}

#[test]
fn rejects_pop_signed_for_a_different_domain() {
    let mut config = config();
    sign_pop_for_domain(&mut config, b"runne.project-owner.genesis-pop/2");
    assert_eq!(
        verify_genesis(&config),
        Err(AuthorityError::InvalidProofOfPossession)
    );
}

#[test]
fn pop_uses_hand_authored_length_framing_and_strict_ed25519() {
    assert_eq!(
        framed_transcript(POP_DOMAIN, b"{}"),
        Ok([
            &33_u32.to_be_bytes()[..],
            POP_DOMAIN,
            &2_u64.to_be_bytes(),
            b"{}",
        ]
        .concat())
    );
    assert_ne!(
        framed_transcript(b"runne.project-owner.genesis-pop/2", b"{}"),
        framed_transcript(POP_DOMAIN, b"{}")
    );
    let mut identity = config();
    identity.public_key = [0; 32];
    identity.public_key[0] = 1;
    identity.key_id = key_id(&identity.public_key);
    identity.proof_of_possession = [0; 64];
    identity.proof_of_possession[0] = 1;
    assert_eq!(
        verify_genesis(&identity),
        Err(AuthorityError::InvalidProofOfPossession)
    );
}

#[test]
fn rejects_malformed_schema_identifiers() {
    for schema_id in [
        "",
        "runne.Example/1",
        "runne.example/-1",
        "runne.example/1/2",
    ] {
        let mut config = config();
        config.schema_digests[0].schema_id = schema_id.into();
        assert_eq!(
            verify_genesis(&config),
            Err(AuthorityError::InvalidSchemaDigests),
            "{schema_id}"
        );
    }
}

#[test]
fn anchor_rejects_bootstrap_fork_rollback_and_repository_mismatch() {
    let config = config();
    let anchor = anchor(&config);
    verify_anchor(config.sha256().expect("sha"), &anchor).expect("pinned");
    assert_eq!(
        verify_anchor([0; 32], &TrustAnchorState::missing()),
        Err(AuthorityError::BootstrapConfirmationRequired)
    );
    assert_eq!(
        verify_anchor([0; 32], &anchor),
        Err(AuthorityError::TrustConfigFork)
    );
    let mut lower = config.clone();
    lower.epoch = 0;
    assert_eq!(
        verify_trust_config(&lower, &anchor),
        Err(AuthorityError::TrustEpochRollback)
    );
    let mut fork = config.clone();
    fork.schema_digests[0].schema_sha256 = [4; 32];
    sign_pop(&mut fork);
    assert_eq!(
        verify_trust_config(&fork, &anchor),
        Err(AuthorityError::TrustConfigFork)
    );
    let mut foreign = config;
    foreign.repository_id = "other".into();
    assert_eq!(
        verify_trust_config(&foreign, &anchor),
        Err(AuthorityError::RepositoryMismatch)
    );
}
