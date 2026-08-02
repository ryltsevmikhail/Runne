    use super::*;

    #[test]
    fn canonical_serialization_is_deterministic() {
        let challenge = PairingChallenge {
            domain: DOMAIN_SEPARATOR,
            version: VERSION,
            device_id: [0xAA; 32],
            nonce: [0xBB; 32],
            issued_at: 1_752_000_000,
            expires_at: 1_752_003_600,
            capabilities: 0,
        };
        let bytes = canonical_bytes(&challenge);
        assert_eq!(bytes.len(), 100);
        assert_eq!(&bytes[0..16], &DOMAIN_SEPARATOR);
        assert_eq!(u16::from_be_bytes([bytes[16], bytes[17]]), VERSION);
    }

    #[test]
    fn domain_and_version_rejected_before_signature_check() {
        let mut challenge = PairingChallenge {
            domain: DOMAIN_SEPARATOR,
            version: VERSION,
            device_id: [0xAA; 32],
            nonce: [0xBB; 32],
            issued_at: 1_752_000_000,
            expires_at: 1_752_003_600,
            capabilities: 0,
        };
        let keypair = generate_keypair();
        let sig = sign_challenge(&challenge, &keypair);
        assert!(verify_pairing(&sig, &keypair.verifying_key().to_bytes(), 1_752_000_001).is_ok());

        challenge.domain = *b"evil-pair/v1\0\0\0\0";
        let bad = sign_challenge(&challenge, &keypair);
        assert!(matches!(
            verify_pairing(&bad, &keypair.verifying_key().to_bytes(), 1_752_000_001),
            Err(PairingError::InvalidDomain)
        ));

        challenge.domain = DOMAIN_SEPARATOR;
        challenge.version = 99;
        let bad2 = sign_challenge(&challenge, &keypair);
        assert!(matches!(
            verify_pairing(&bad2, &keypair.verifying_key().to_bytes(), 1_752_000_001),
            Err(PairingError::UnsupportedVersion(99))
        ));
    }

    #[test]
    fn expiry_uses_test_clock_not_system_time() {
        let challenge = PairingChallenge {
            domain: DOMAIN_SEPARATOR,
            version: VERSION,
            device_id: [0xAA; 32],
            nonce: [0xBB; 32],
            issued_at: 1000,
            expires_at: 2000,
            capabilities: 0,
        };
        let keypair = generate_keypair();
        let sig = sign_challenge(&challenge, &keypair);

        assert!(verify_pairing(&sig, &keypair.verifying_key().to_bytes(), 1500).is_ok());
        assert!(matches!(
            verify_pairing(&sig, &keypair.verifying_key().to_bytes(), 2500),
            Err(PairingError::Expired { .. })
        ));
        assert!(matches!(
            verify_pairing(&sig, &keypair.verifying_key().to_bytes(), 500),
            Err(PairingError::FutureChallenge(1000))
        ));
    }
