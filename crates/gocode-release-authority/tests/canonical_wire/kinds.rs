use gocode_release_authority::CanonicalPayloadKind;

pub const KINDS: [CanonicalPayloadKind; 10] = [
    CanonicalPayloadKind::Rc1Decision,
    CanonicalPayloadKind::UnsignedManifest,
    CanonicalPayloadKind::Rc2Authorization,
    CanonicalPayloadKind::ArtifactRecord,
    CanonicalPayloadKind::ThresholdMetadata,
    CanonicalPayloadKind::Inventory,
    CanonicalPayloadKind::VerificationReport,
    CanonicalPayloadKind::PublicationManifest,
    CanonicalPayloadKind::Rc3Authorization,
    CanonicalPayloadKind::Snapshot,
];
