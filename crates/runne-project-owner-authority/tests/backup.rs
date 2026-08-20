use ed25519_dalek::SigningKey;
use runne_project_owner_authority::{
    AuthorityError, BackupParameters, BackupPassphrase, BackupRng, ProjectOwnerTrustConfigV1,
    SchemaDigest, decrypt_backup, encrypt_backup, key_fingerprint,
};
use zeroize::Zeroizing;

struct FixedRng(u8);

impl BackupRng for FixedRng {
    fn fill_bytes(&mut self, bytes: &mut [u8]) -> Result<(), AuthorityError> {
        bytes.fill(self.0);
        self.0 = self.0.wrapping_add(1);
        Ok(())
    }
}

struct FailingRng;

impl BackupRng for FailingRng {
    fn fill_bytes(&mut self, _: &mut [u8]) -> Result<(), AuthorityError> {
        Err(AuthorityError::BackupRandomnessUnavailable)
    }
}

fn trust() -> ProjectOwnerTrustConfigV1 {
    let key = SigningKey::from_bytes(&[7; 32]);
    ProjectOwnerTrustConfigV1 {
        schema_version: "gocode.project-owner.trust-config/1".into(),
        repository_id: "gocode".into(),
        role: "PROJECT_OWNER".into(),
        epoch: 1,
        key_id: runne_project_owner_authority::key_id(&key.verifying_key().to_bytes()),
        public_key: key.verifying_key().to_bytes(),
        schema_digests: vec![SchemaDigest {
            schema_id: "gocode.project-owner.authority-receipt/1".into(),
            schema_sha256: [3; 32],
        }],
        proof_of_possession: [0; 64],
        predecessor: None,
    }
}

fn passphrase() -> BackupPassphrase {
    BackupPassphrase::new(Zeroizing::new(b"correct horse battery staple".to_vec()))
}

#[test]
fn encrypts_canonical_metadata_and_roundtrips_the_exact_seed() {
    let mut rng = FixedRng(1);
    let trust = trust();
    let metadata = encrypt_backup(
        Zeroizing::new([7; 32]),
        passphrase(),
        &trust,
        BackupParameters::default(),
        &mut rng,
    )
    .expect("encrypt");
    let canonical = metadata.to_canonical_json().expect("canonical");
    assert!(canonical.ends_with(b"\n"));
    assert!(canonical.starts_with(b"{\"ciphertext\":\""));
    assert_eq!(metadata.repository_id(), "gocode");
    assert_eq!(metadata.key_epoch(), 1);
    assert_eq!(metadata.parameters(), BackupParameters::default());
    assert_eq!(
        metadata.key_fingerprint(),
        key_fingerprint(&trust.public_key)
    );
    let header = b"{\"kdf\":{\"algorithm\":\"Argon2id\",\"iterations\":3,\"memory_kib\":65536,\"parallelism\":1},\"key_epoch\":1,\"key_fingerprint\":\"ee71591d38ef4eba840ce7015cce37765f093b7b49c215df19511b2ff460e272\",\"key_id\":\"5d3f3c61d5ad51bcdc9a77bc6ae5cbca3326d196be42e0fd2b9f593591c71053\",\"nonce\":\"AgICAgICAgICAgICAgICAgICAgICAgIC\",\"repository_id\":\"gocode\",\"salt\":\"AQEBAQEBAQEBAQEBAQEBAQ\",\"schema_version\":\"gocode.project-owner.encrypted-key-backup/1\"}\n";
    assert_eq!(
        metadata.authenticated_data().expect("aad"),
        [
            &47_u32.to_be_bytes()[..],
            b"gocode.project-owner.encrypted-key-backup-aad/1",
            &421_u64.to_be_bytes(),
            header
        ]
        .concat()
    );
    assert_eq!(
        canonical,
        [
            b"{\"ciphertext\":\"hLm-9g04llyJqUeWTSflFatcxBasElcB0T8MjHCwoF4JU6yOmCJjmKHk2u1BMafU\",",
            &header[1..],
        ]
        .concat()
    );
    assert_eq!(
        decrypt_backup(&metadata, passphrase(), &trust)
            .expect("decrypt")
            .as_ref(),
        &[7; 32]
    );
}

#[test]
fn rejects_duplicate_unknown_padded_truncated_and_noncanonical_json() {
    let mut rng = FixedRng(1);
    let trust = trust();
    let metadata = encrypt_backup(
        Zeroizing::new([7; 32]),
        passphrase(),
        &trust,
        BackupParameters::default(),
        &mut rng,
    )
    .expect("encrypt");
    let canonical =
        String::from_utf8(metadata.to_canonical_json().expect("canonical")).expect("utf8");
    let vectors = [
        canonical.replacen('{', "{\"unknown\":0,", 1),
        canonical.replacen("\"key_epoch\":1", "\"key_epoch\":1,\"key_epoch\":1", 1),
        canonical.replacen("\"salt\":\"", "\"salt\":\"=", 1),
        canonical.replacen('\n', " \n", 1),
    ];
    for bytes in vectors {
        assert!(matches!(
            runne_project_owner_authority::BackupMetadataV1::from_json(bytes.as_bytes()),
            Err(AuthorityError::InvalidBackupMetadata)
        ));
    }
    let oversized = format!(r#"{{"salt":"{}"}}"#, "A".repeat(1_000_000));
    assert!(matches!(
        runne_project_owner_authority::BackupMetadataV1::from_json(oversized.as_bytes()),
        Err(AuthorityError::InvalidBackupMetadata)
    ));
}

#[test]
fn rejects_wrong_passphrase_and_every_authenticated_metadata_mutation_uniformly() {
    let mut rng = FixedRng(1);
    let trust = trust();
    let metadata = encrypt_backup(
        Zeroizing::new([7; 32]),
        passphrase(),
        &trust,
        BackupParameters::default(),
        &mut rng,
    )
    .expect("encrypt");
    assert_eq!(
        decrypt_backup(
            &metadata,
            BackupPassphrase::new(Zeroizing::new(b"wrong".to_vec())),
            &trust
        ),
        Err(AuthorityError::BackupTamperedOrWrongPassphrase)
    );
    let original =
        String::from_utf8(metadata.to_canonical_json().expect("canonical")).expect("utf8");
    let ciphertext = runne_project_owner_authority::BackupMetadataV1::from_json(
        mutate_first_ciphertext_character(&original).as_bytes(),
    )
    .expect("canonical metadata");
    assert_eq!(
        decrypt_backup(&ciphertext, passphrase(), &trust),
        Err(AuthorityError::BackupTamperedOrWrongPassphrase)
    );
    for invalid_metadata in [
        original.replacen(
            "\"repository_id\":\"gocode\"",
            "\"repository_id\":\"other\"",
            1,
        ),
        original.replacen("\"key_epoch\":1", "\"key_epoch\":0", 1),
    ] {
        assert!(matches!(
            runne_project_owner_authority::BackupMetadataV1::from_json(invalid_metadata.as_bytes()),
            Err(AuthorityError::InvalidBackupMetadata)
        ));
    }

    let epoch_two = original.replacen("\"key_epoch\":1", "\"key_epoch\":2", 1);
    let metadata = runne_project_owner_authority::BackupMetadataV1::from_json(epoch_two.as_bytes())
        .expect("canonical metadata");
    assert_eq!(
        decrypt_backup(&metadata, passphrase(), &trust),
        Err(AuthorityError::InvalidBackupBinding)
    );
}

fn mutate_first_ciphertext_character(canonical: &str) -> String {
    let prefix = "\"ciphertext\":\"";
    let start = canonical.find(prefix).expect("ciphertext") + prefix.len();
    let mut bytes = canonical.as_bytes().to_vec();
    bytes[start] = if bytes[start] == b'A' { b'B' } else { b'A' };
    String::from_utf8(bytes).expect("utf8")
}

#[test]
fn validates_bounds_and_public_binding_before_expensive_kdf() {
    assert!(BackupParameters::new(65_536, 3, 1).is_ok());
    for parameters in [
        BackupParameters::new(65_535, 3, 1),
        BackupParameters::new(262_145, 3, 1),
        BackupParameters::new(65_536, 2, 1),
        BackupParameters::new(65_536, 11, 1),
        BackupParameters::new(65_536, 3, 0),
        BackupParameters::new(65_536, 3, 5),
    ] {
        assert_eq!(parameters, Err(AuthorityError::InvalidBackupParameters));
    }
    assert_ne!(key_fingerprint(&[9; 32]), key_fingerprint(&[8; 32]));

    let mut rng = FixedRng(1);
    let trust = trust();
    let metadata = encrypt_backup(
        Zeroizing::new([7; 32]),
        passphrase(),
        &trust,
        BackupParameters::default(),
        &mut rng,
    )
    .expect("encrypt");
    let mut foreign = trust.clone();
    foreign.repository_id = "other".into();
    assert_eq!(
        decrypt_backup(&metadata, passphrase(), &foreign),
        Err(AuthorityError::InvalidBackupBinding)
    );
}

#[test]
fn rng_failure_never_falls_back_to_predictable_randomness() {
    assert!(matches!(
        encrypt_backup(
            Zeroizing::new([7; 32]),
            passphrase(),
            &trust(),
            BackupParameters::default(),
            &mut FailingRng
        ),
        Err(AuthorityError::BackupRandomnessUnavailable)
    ));
}
