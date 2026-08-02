    use super::*;
    use crate::bootstrap::{
        BootstrapMessage, HostExecutionIdentity, HostHello, NegotiationRejectReason,
        NegotiationRejected, PluginHello, ProfileSelected, SelectionAcknowledged,
    };
    use crate::digest::DigestAlgorithm;
    use crate::digest::{
        ManifestDigest, PackageDigest, ProfileDigest, ProtocolNegotiationSnapshotDigest,
    };
    use crate::id::{
        EntrypointIdentity, Nonce, PluginId, PluginIdentity, PluginVersion, ProfileId,
        ProtocolSessionId, TargetIdentity,
    };
    use crate::profile::BoundedProfileRefVec;

    fn default_limits() -> DecodeLimits {
        DecodeLimits {
            max_frame_bytes: 65536,
            max_recursion_depth: 10,
            max_array_items: 1024,
            max_map_items: 1024,
            max_text_bytes: 4096,
            max_byte_string_bytes: 4096,
            max_unsigned: 1_000_000,
            min_signed: -1_000_000,
            max_signed: 1_000_000,
            max_string_bytes: 4096,
            max_nesting_depth: 10,
        }
    }

    fn frame_limits() -> FrameLimits {
        FrameLimits {
            max_frame_bytes: 65536,
        }
    }

    fn empty_profiles() -> BoundedProfileRefVec {
        BoundedProfileRefVec::new()
    }

    #[test]
    fn test_encode_decode_host_hello() {
        let msg = BootstrapMessage::HostHello(HostHello {
            nonce: Nonce::from_bytes([0; 16]),
            host_identity: HostExecutionIdentity::Plugin(PluginIdentity::new("host-plug").unwrap()),
            supported_profiles: empty_profiles(),
            negotiation_snapshot: ProtocolNegotiationSnapshotDigest::from_bytes([0; 32]),
        });

        let frame = encode_frame(&msg, &frame_limits()).unwrap();
        let decoded = decode_frame(&frame, &default_limits()).unwrap();

        match decoded {
            BootstrapMessage::HostHello(h) => {
                assert_eq!(h.nonce, Nonce::from_bytes([0; 16]));
            }
            _ => panic!("expected HostHello"),
        }
    }

    #[test]
    fn test_decode_frame_empty() {
        let err = decode_frame(&[], &default_limits()).unwrap_err();
        assert!(matches!(err, DecodeError::FrameTruncated { .. }));
    }

    #[test]
    fn test_decode_frame_too_small() {
        let err = decode_frame(&[0x00], &default_limits()).unwrap_err();
        assert!(matches!(err, DecodeError::FrameTruncated { .. }));
    }

    #[test]
    fn test_decode_frame_oversize() {
        let mut limits = default_limits();
        limits.max_frame_bytes = 10;
        let mut buf = Vec::new();
        buf.extend_from_slice(&1000u32.to_be_bytes());
        buf.resize(1004, 0);
        let err = decode_frame(&buf, &limits).unwrap_err();
        assert!(matches!(err, DecodeError::FrameTooLarge { .. }));
    }

    #[test]
    fn test_decode_frame_trailing_bytes() {
        let msg = BootstrapMessage::HostHello(HostHello {
            nonce: Nonce::from_bytes([0; 16]),
            host_identity: HostExecutionIdentity::Plugin(PluginIdentity::new("host").unwrap()),
            supported_profiles: empty_profiles(),
            negotiation_snapshot: ProtocolNegotiationSnapshotDigest::from_bytes([0; 32]),
        });
        let mut frame = encode_frame(&msg, &frame_limits()).unwrap();
        frame.push(0xFF); // trailing byte
        let err = decode_frame(&frame, &default_limits()).unwrap_err();
        assert!(matches!(err, DecodeError::TrailingBytes { .. }));
    }

    #[test]
    fn test_encode_frame_too_large() {
        let limits = FrameLimits { max_frame_bytes: 5 };
        let msg = BootstrapMessage::HostHello(HostHello {
            nonce: Nonce::from_bytes([0; 16]),
            host_identity: HostExecutionIdentity::Plugin(PluginIdentity::new("host").unwrap()),
            supported_profiles: empty_profiles(),
            negotiation_snapshot: ProtocolNegotiationSnapshotDigest::from_bytes([0; 32]),
        });
        let err = encode_frame(&msg, &limits).unwrap_err();
        assert!(matches!(err, EncodeError::FrameTooLarge { .. }));
    }

    #[test]
    fn test_roundtrip_all_bootstrap_messages() {
        let limits = default_limits();
        let flimits = frame_limits();

        // HostHello
        let m1 = BootstrapMessage::HostHello(HostHello {
            nonce: Nonce::from_bytes([1; 16]),
            host_identity: HostExecutionIdentity::Plugin(PluginIdentity::new("h1").unwrap()),
            supported_profiles: empty_profiles(),
            negotiation_snapshot: ProtocolNegotiationSnapshotDigest::from_bytes([2; 32]),
        });
        let f1 = encode_frame(&m1, &flimits).unwrap();
        let d1 = decode_frame(&f1, &limits).unwrap();
        assert!(matches!(d1, BootstrapMessage::HostHello(_)));

        // PluginHello
        let m2 = BootstrapMessage::PluginHello(PluginHello {
            host_nonce: Nonce::from_bytes([3; 16]),
            plugin_nonce: Nonce::from_bytes([4; 16]),
            host_identity: HostExecutionIdentity::Plugin(PluginIdentity::new("p1").unwrap()),
            package_id: PluginId::new("com.example.pkg").unwrap(),
            package_digest: PackageDigest::new(DigestAlgorithm::Sha256, [5; 32]),
            package_version: PluginVersion::new("1.0.0").unwrap(),
            manifest_digest: ManifestDigest::from_bytes([6; 32]),
            plugin_identity: HostExecutionIdentity::Plugin(PluginIdentity::new("pi1").unwrap()),
            target_identity: TargetIdentity::new("target").unwrap(),
            entrypoint: EntrypointIdentity::new("entry").unwrap(),
            supported_profiles: empty_profiles(),
        });
        let f2 = encode_frame(&m2, &flimits).unwrap();
        let d2 = decode_frame(&f2, &limits).unwrap();
        assert!(matches!(d2, BootstrapMessage::PluginHello(_)));

        // NegotiationRejected
        let m3 = BootstrapMessage::NegotiationRejected(NegotiationRejected {
            reason: NegotiationRejectReason::ProfileNotSupported,
        });
        let f3 = encode_frame(&m3, &flimits).unwrap();
        let d3 = decode_frame(&f3, &limits).unwrap();
        assert!(matches!(d3, BootstrapMessage::NegotiationRejected(_)));

        // ProfileSelected
        let sid: ProtocolSessionId = "018f2e3a-7000-7000-8000-000000000001".parse().unwrap();
        let pid: ProfileId = ProfileId::new("profile-1").unwrap();
        let m4 = BootstrapMessage::ProfileSelected(ProfileSelected {
            host_nonce: Nonce::from_bytes([7; 16]),
            plugin_nonce: Nonce::from_bytes([8; 16]),
            session_id: sid,
            profile_id: pid.clone(),
            profile_digest: ProfileDigest::from_bytes([9; 32]),
        });
        let f4 = encode_frame(&m4, &flimits).unwrap();
        let d4 = decode_frame(&f4, &limits).unwrap();
        assert!(matches!(d4, BootstrapMessage::ProfileSelected(_)));

        // SelectionAcknowledged
        let m5 = BootstrapMessage::SelectionAcknowledged(SelectionAcknowledged {
            host_nonce: Nonce::from_bytes([10; 16]),
            plugin_nonce: Nonce::from_bytes([11; 16]),
            session_id: sid,
            profile_id: pid,
            profile_digest: ProfileDigest::from_bytes([12; 32]),
        });
        let f5 = encode_frame(&m5, &flimits).unwrap();
        let d5 = decode_frame(&f5, &limits).unwrap();
        assert!(matches!(d5, BootstrapMessage::ProfileSelected(_)));
    }
