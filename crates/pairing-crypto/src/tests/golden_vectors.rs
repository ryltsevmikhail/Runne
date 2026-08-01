    use super::*;

    const SEED: [u8; 32] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36,
        0x37, 0x38,
    ];

    fn deterministic_challenge() -> PairingChallenge {
        let key = generate_keypair_deterministic(&SEED);
        let device_id = device_id_from_public_key(&key.verifying_key().to_bytes());
        PairingChallenge {
            domain: DOMAIN_SEPARATOR,
            version: VERSION,
            device_id,
            nonce: [0x42; 32],
            issued_at: 1_752_000_000,
            expires_at: 1_752_003_600,
            capabilities: 0,
        }
    }

    #[test]
    fn golden_canonical_hash_matches_typescript() {
        // Simple challenge — cross-language golden vector
        let challenge = PairingChallenge {
            domain: DOMAIN_SEPARATOR,
            version: VERSION,
            device_id: [0xAA; 32],
            nonce: [0xBB; 32],
            issued_at: 1_752_000_000,
            expires_at: 1_752_003_600,
            capabilities: 0,
        };
        let canonical = canonical_bytes(&challenge);
        let hash = hex::encode(Sha256::digest(&canonical));
        assert_eq!(
            hash,
            "c1578ca6e128651894bcbff1c978fa5c95b9e18a50a92075ac7dedc8bfa0859a"
        );
    }

    #[test]
    fn golden_deterministic_signature_verifies() {
        let key = generate_keypair_deterministic(&SEED);
        let challenge = deterministic_challenge();
        let sig = sign_challenge(&challenge, &key);
        let canonical = canonical_bytes(&challenge);

        // Golden: canonical bytes SHA-256 (deterministic)
        let hash = hex::encode(Sha256::digest(&canonical));
        let expected = "2b44fefb452b8e59db4c6bc6b3ac48775c270bfbaa9679b2fae51774a16a21e0";
        assert_eq!(
            hash, expected,
            "deterministic golden hash mismatch — if this fails, update both Rust and TypeScript"
        );
        assert_eq!(sig.signature.len(), 64);
        assert_eq!(sig.public_key, key.verifying_key().to_bytes());
        assert!(verify_pairing(&sig, &key.verifying_key().to_bytes(), 1_752_000_001).is_ok());
    }

    #[test]
    fn golden_expired_rejected() {
        let key = generate_keypair_deterministic(&SEED);
        let challenge = deterministic_challenge();
        let sig = sign_challenge(&challenge, &key);
        let result = verify_pairing(&sig, &key.verifying_key().to_bytes(), 9_999_999_999);
        assert!(matches!(result, Err(PairingError::Expired { .. })));
    }

    #[test]
    fn golden_wrong_key_rejected() {
        let key = generate_keypair_deterministic(&SEED);
        let challenge = deterministic_challenge();
        let sig = sign_challenge(&challenge, &key);
        let wrong_key = [0xFF; 32];
        assert!(matches!(
            verify_pairing(&sig, &wrong_key, 1_752_000_001),
            Err(PairingError::InvalidSignature)
        ));
    }

    #[test]
    fn golden_replay_rejected() {
        let mut checker = InMemoryReplayChecker::new();
        let key = generate_keypair_deterministic(&SEED);
        let challenge = deterministic_challenge();
        let sig = sign_challenge(&challenge, &key);
        checker.check_and_record(&sig.challenge.nonce).unwrap();
        assert!(matches!(
            checker.check_and_record(&sig.challenge.nonce),
            Err(PairingError::ReplayDetected)
        ));
    }

    #[test]
    fn golden_wrong_domain_rejected() {
        let key = generate_keypair_deterministic(&SEED);
        let challenge = PairingChallenge {
            domain: *b"evil-pair/v1\x00\x00\x00\x00",
            ..deterministic_challenge()
        };
        let sig = sign_challenge(&challenge, &key);
        assert!(matches!(
            verify_pairing(&sig, &key.verifying_key().to_bytes(), 1_752_000_001),
            Err(PairingError::InvalidDomain)
        ));
    }

    #[test]
    fn golden_modified_field_rejected() {
        let key = generate_keypair_deterministic(&SEED);
        let challenge = deterministic_challenge();
        let mut sig = sign_challenge(&challenge, &key);
        // Tamper with expires_at after signing
        sig.challenge.expires_at = 1_752_999_999;
        assert!(matches!(
            verify_pairing(&sig, &key.verifying_key().to_bytes(), 1_752_000_001),
            Err(PairingError::InvalidSignature)
        ));
    }
