const SOURCE: &str = include_str!("../src/implementation_parts/security_profile_seal.inc");

#[test]
fn seal_api_is_secure_enclave_only_and_keeps_private_key_internal() {
    for required in [
        "SecurityProfileProcessLock",
        "Token::SecureEnclave",
        "KeyType::ec_sec_prime_random()",
        "set_size_in_bits(256)",
        "set_location(Location::DataProtectionKeychain)",
        "ECDSASignatureMessageX962SHA256",
        "public_key()",
        "ProviderCredentialProcessLock::acquire()",
        "static SECURITY_PROFILE_PROCESS_LOCK",
        "gocode/security-transaction-seal/v1",
    ] {
        assert!(
            SOURCE.contains(required),
            "missing required contract: {required}"
        );
    }

    for forbidden in [
        "external_representation",
        "SecKeyCopyExternalRepresentation",
        "Hmac",
        "hmac",
        "Token::Software",
        "SecKeyCreateWithData",
    ] {
        assert!(
            !SOURCE.contains(forbidden),
            "forbidden private-key or software fallback: {forbidden}"
        );
    }
}

#[test]
fn seal_api_validates_der_and_binds_profile_before_use() {
    for required in [
        "fn valid_der_signature",
        "1..=80",
        "profile_identity_digest != self.profile_identity_digest",
        "InvalidProfileBinding",
    ] {
        assert!(
            SOURCE.contains(required),
            "missing required contract: {required}"
        );
    }
}
