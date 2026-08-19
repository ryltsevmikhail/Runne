vec![
    (
        "receipt binding",
        Box::new(move |item| item.receipt_sha256 = [0; 32]),
        AuthorityError::InvalidStageEnvelope,
    ),
    (
        "trust config binding",
        Box::new(move |item| item.trust_config_sha256 = "00".repeat(32)),
        AuthorityError::InvalidStageEnvelope,
    ),
    (
        "trust generation binding",
        Box::new(move |item| item.trust_generation = 3),
        AuthorityError::InvalidStageEnvelope,
    ),
    (
        "repository",
        Box::new(move |item| item.repository_id = "other".into()),
        AuthorityError::InvalidStageEnvelope,
    ),
    (
        "unknown issuer role",
        Box::new(move |item| item.issuer_role = "NOPE".into()),
        AuthorityError::InvalidDelegation,
    ),
    (
        "wrong issuer role",
        Box::new(move |item| item.issuer_role = "RC2_SIGNING_AUTHORIZER".into()),
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
            item.payload_schema_id = "runne.release.rc2-signing-authorization/1".into()
        }),
        AuthorityError::InvalidStageEnvelope,
    ),
    (
        "unknown payload schema",
        Box::new(move |item| item.payload_schema_id = "runne.unknown.schema/1".into()),
        AuthorityError::InvalidStageEnvelope,
    ),
    (
        "payload schema pin",
        Box::new(move |item| item.payload_schema_sha256 = [0; 32]),
        AuthorityError::InvalidStageEnvelope,
    ),
    (
        "payload digest",
        Box::new(move |item| item.payload_sha256 = [0; 32]),
        AuthorityError::InvalidStageEnvelope,
    ),
    (
        "payload substitution",
        Box::new(move |item| item.payload = serde_json::json!({"other":"value"})),
        AuthorityError::InvalidStageEnvelope,
    ),
    (
        "enclosing hash payload",
        Box::new(move |item| {
            item.payload = serde_json::json!({"nested":{"envelope_sha256":"x"}})
        }),
        AuthorityError::InvalidStageEnvelope,
    ),
    (
        "unsafe nonce",
        Box::new(move |item| item.authorization_nonce = "unsafe/slash".into()),
        AuthorityError::InvalidStageEnvelope,
    ),
    (
        "root signer",
        Box::new(move |item| item.issuer_key_id = root_key_id.clone()),
        AuthorityError::InvalidDelegation,
    ),
    (
        "unordered expiry",
        Box::new(move |item| item.expires_at = item.not_before.clone()),
        AuthorityError::InvalidStageEnvelope,
    ),
    (
        "unordered issuance",
        Box::new(move |item| item.issued_at = "2026-01-01T00:00:04Z".into()),
        AuthorityError::InvalidStageEnvelope,
    ),
    (
        "zero issuer key epoch",
        Box::new(move |item| item.issuer_key_epoch = 0),
        AuthorityError::InvalidStageEnvelope,
    ),
]
