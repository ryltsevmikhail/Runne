#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hmac_high_water_ref_deterministic() {
        let auth = [0x01u8; 16];
        let sess = [0x02u8; 16];
        let secret = [0x03u8; 32];

        let ref1 = build_high_water_ref(&auth, None, 42, &secret, &sess);
        let ref2 = build_high_water_ref(&auth, None, 42, &secret, &sess);

        assert_eq!(ref1, ref2);
        assert_eq!(ref1.len(), 77);
    }

    #[test]
    fn test_hmac_high_water_ref_differs() {
        let auth = [0x01u8; 16];
        let sess = [0x02u8; 16];
        let secret = [0x03u8; 32];

        let ref1 = build_high_water_ref(&auth, None, 42, &secret, &sess);
        let ref2 = build_high_water_ref(&auth, None, 43, &secret, &sess);

        assert_ne!(ref1, ref2);
    }

    #[test]
    fn test_hmac_high_water_ref_differs_on_secret() {
        let auth = [0x01u8; 16];
        let sess = [0x02u8; 16];
        let secret1 = [0x03u8; 32];
        let secret2 = [0x04u8; 32];

        let ref1 = build_high_water_ref(&auth, None, 42, &secret1, &sess);
        let ref2 = build_high_water_ref(&auth, None, 42, &secret2, &sess);

        assert_ne!(ref1, ref2);
    }

    #[test]
    fn test_hmac_high_water_ref_with_floor() {
        let auth = [0x01u8; 16];
        let sess = [0x02u8; 16];
        let secret = [0x03u8; 32];

        let ref1 = build_high_water_ref(&auth, Some(10), 42, &secret, &sess);
        let ref2 = build_high_water_ref(&auth, None, 42, &secret, &sess);

        assert_ne!(ref1, ref2);
        assert_eq!(ref1.len(), 77);
    }

    #[test]
    fn high_water_ref_uses_its_own_schema_version() {
        let high_water_ref = build_high_water_ref(&[0x01; 16], None, 42, &[0x03; 32], &[0x02; 16]);

        assert_eq!(&high_water_ref[33..37], &1_u32.to_be_bytes());
    }
}
