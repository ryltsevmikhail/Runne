vec![
    (
        "receipt binding",
        Box::new(move |item| item.receipt_sha256 = [0; 32]),
        AuthorityError::InvalidEvidenceEnvelope,
    ),
    (
        "trust config binding",
        Box::new(move |item| item.trust_config_sha256 = "00".repeat(32)),
        AuthorityError::InvalidEvidenceEnvelope,
    ),
    (
        "trust generation binding",
        Box::new(move |item| item.trust_generation = 3),
        AuthorityError::InvalidEvidenceEnvelope,
    ),
    (
        "repository",
        Box::new(move |item| item.repository_id = "other".into()),
        AuthorityError::InvalidEvidenceEnvelope,
    ),
    (
        "unknown issuer role",
        Box::new(move |item| item.issuer_role = "NOPE".into()),
        AuthorityError::InvalidDelegation,
    ),
    (
        "wrong issuer role",
        Box::new(move |item| item.issuer_role = "RC2_SIGNING_REVIEWER".into()),
        AuthorityError::InvalidDelegation,
    ),
    (
        "wrong issuer scope",
        Box::new(move |item| item.issuer_scope = "signing-review".into()),
        AuthorityError::InvalidDelegation,
    ),
    (
        "wrong role scope pair",
        Box::new(move |item| {
            item.issuer_role = "RC2_NATIVE_EVIDENCE".into();
            item.issuer_scope = "linux".into();
        }),
        AuthorityError::InvalidDelegation,
    ),
    (
        "issuer principal",
        Box::new(move |item| item.issuer_principal_id = "other".into()),
        AuthorityError::InvalidDelegation,
    ),
    (
        "issuer account",
        Box::new(move |item| item.issuer_controlling_account_id = "other".into()),
        AuthorityError::InvalidDelegation,
    ),
    (
        "issuer lane",
        Box::new(move |item| item.issuer_lane_id = "other".into()),
        AuthorityError::InvalidDelegation,
    ),
    (
        "issuer key id",
        Box::new(move |item| {
            item.issuer_key_id =
                crate::trust_canonical::hex(&crate::key_id(&other.verifying_key().to_bytes()))
        }),
        AuthorityError::InvalidDelegation,
    ),
    (
        "issuer key epoch",
        Box::new(move |item| item.issuer_key_epoch = 2),
        AuthorityError::InvalidDelegation,
    ),
    (
        "signature profile",
        Box::new(move |item| item.signature_profile_id = "other".into()),
        AuthorityError::InvalidDelegation,
    ),
    (
        "revocation epoch",
        Box::new(move |item| item.revocation_epoch = 2),
        AuthorityError::InvalidDelegation,
    ),
    (
        "out of window expiry",
        Box::new(move |item| item.expires_at = "2026-01-01T00:00:05Z".into()),
        AuthorityError::InvalidDelegation,
    ),
    (
        "disallowed payload schema",
        Box::new(move |item| {
            item.payload_schema_id = "gocode.release.rc2-native-evidence/1".into()
        }),
        AuthorityError::InvalidEvidenceEnvelope,
    ),
    (
        "unknown payload schema",
        Box::new(move |item| item.payload_schema_id = "gocode.unknown.schema/1".into()),
        AuthorityError::InvalidEvidenceEnvelope,
    ),
    (
        "payload schema pin",
        Box::new(move |item| item.payload_schema_sha256 = [0; 32]),
        AuthorityError::InvalidEvidenceEnvelope,
    ),
    (
        "payload digest",
        Box::new(move |item| item.payload_sha256 = [0; 32]),
        AuthorityError::InvalidEvidenceEnvelope,
    ),
    (
        "payload substitution",
        Box::new(move |item| item.payload = serde_json::json!({"other":"value"})),
        AuthorityError::InvalidEvidenceEnvelope,
    ),
    (
        "unsafe nonce",
        Box::new(move |item| item.authorization_nonce = "unsafe/slash".into()),
        AuthorityError::InvalidEvidenceEnvelope,
    ),
    (
        "root signer",
        Box::new(move |item| item.issuer_key_id = root_key_id.clone()),
        AuthorityError::InvalidDelegation,
    ),
    (
        "unordered expiry",
        Box::new(move |item| item.expires_at = item.not_before.clone()),
        AuthorityError::InvalidEvidenceEnvelope,
    ),
    (
        "unordered issuance",
        Box::new(move |item| item.issued_at = "2026-01-01T00:00:04Z".into()),
        AuthorityError::InvalidEvidenceEnvelope,
    ),
    (
        "zero issuer key epoch",
        Box::new(move |item| item.issuer_key_epoch = 0),
        AuthorityError::InvalidEvidenceEnvelope,
    ),
]
