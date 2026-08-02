// ── tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::digest::{Sha256Digest, Sha256Provider};
    use sha2::{Digest, Sha256};

    struct TestSha256;

    impl Sha256Provider for TestSha256 {
        fn sha256(&self, data: &[u8]) -> Sha256Digest {
            Sha256Digest::from_bytes(Sha256::digest(data).into())
        }
    }

    #[test]
    fn test_profile_ref_vec_bounded() {
        let mut v = BoundedProfileRefVec::new();
        let pid = ProfileId::new("p1").unwrap();
        let pd = ProfileDigest::from_bytes([0; 32]);
        assert!(v.push(ProtocolProfileRef::new(pid, pd)).is_ok());
        assert_eq!(v.len(), 1);
    }

    #[test]
    fn test_decode_limits_default() {
        let limits = DecodeLimits::default();
        assert_eq!(limits.max_frame_bytes, 1024 * 1024);
    }

    #[test]
    fn test_validation_error_display() {
        let err = ProtocolValidationError::SequenceGap {
            expected: 5,
            actual: 7,
        };
        assert!(err.to_string().contains("5"));
        assert!(err.to_string().contains("7"));
    }

    #[test]
    fn test_protocol_support_profile_fields() {
        let p = ProtocolSupportProfile::new(
            ProfileId::new("test").unwrap(),
            ProtocolVersion::V1_0,
            BootstrapSchemaDigest::from_bytes([1; 32]),
            WireContractDigest::from_bytes([2; 32]),
            SchemaBundleDigest::from_bytes([3; 32]),
            BoundsProfileDigest::from_bytes([4; 32]),
            vec!["feature-a".to_owned(), "feature-b".to_owned()],
        )
        .unwrap();
        assert_eq!(p.version, ProtocolVersion::V1_0);
        assert_eq!(p.profile_id.as_str(), "test");
        assert_ne!(
            p.profile_digest(&TestSha256),
            ProfileDigest::from_bytes([0; 32])
        );
        assert_eq!(p.enabled_features(), ["feature-a", "feature-b"]);
    }

    #[test]
    fn canonical_profile_digest_matches_pinned_vector() {
        let profile = ProtocolSupportProfile::new(
            ProfileId::new("builtin-profile-v2").unwrap(),
            ProtocolVersion::V1_0,
            BootstrapSchemaDigest::from_bytes([0x11; 32]),
            WireContractDigest::from_bytes([0x22; 32]),
            SchemaBundleDigest::from_bytes([0x33; 32]),
            BoundsProfileDigest::from_bytes([0x44; 32]),
            vec!["bootstrap-v2".to_owned()],
        )
        .unwrap();

        assert_eq!(
            profile.profile_digest(&TestSha256),
            ProfileDigest::from_bytes([
                0x6d, 0xbd, 0xdb, 0xd7, 0x54, 0xf8, 0xbf, 0xf3, 0xd6, 0x2c, 0xfe, 0xfd, 0x31, 0x09,
                0x5b, 0xce, 0x32, 0x56, 0x3a, 0xc2, 0x62, 0x77, 0x05, 0xc9, 0x24, 0x26, 0x1c, 0x0b,
                0xfe, 0x4f, 0x6c, 0x5d,
            ])
        );
    }

    #[test]
    fn test_direction_bounds_clone() {
        let d = DirectionBounds {
            initial_data_frame_credit: 10,
            initial_encoded_byte_credit: 1000,
            max_data_frame_window: 64,
            max_encoded_byte_window: 65536,
            max_in_flight_requests: 8,
        };
        let d2 = d;
        assert_eq!(d2.max_in_flight_requests, 8);
    }

    #[test]
    fn test_validation_error_is_error_trait() {
        let e: &dyn std::error::Error = &ProtocolValidationError::ProfileNotSupported;
        assert_eq!(e.to_string(), "profile not supported");
    }
}
