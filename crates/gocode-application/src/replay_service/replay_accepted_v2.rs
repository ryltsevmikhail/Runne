/// Current promotion snapshot captured and read back from the V18 admission
/// transaction. It deliberately has no witness or baseline construction API.
#[derive(Clone)]
pub struct ReplayAcceptedPromotionV2 {
    codec: u8,
    projection: gocode_api::UnauthenticatedReplayPromotionProjectionV1,
    bytes: Vec<u8>,
    digest: [u8; 32],
    sequence: u64,
    version: u64,
    global_position: i64,
    head_event_id: [u8; 16],
    head_integrity_digest: [u8; 32],
    captured_high_water: i64,
}

/// Durable facts supplied only by the store after snapshot readback.
pub struct ReplayAcceptedPromotionV2Parts {
    pub codec: u8,
    pub bytes: Vec<u8>,
    pub digest: [u8; 32],
    pub sequence: u64,
    pub version: u64,
    pub global_position: i64,
    pub head_event_id: [u8; 16],
    pub head_integrity_digest: [u8; 32],
    pub captured_high_water: i64,
}

impl ReplayAcceptedPromotionV2 {
    pub fn from_storage(parts: ReplayAcceptedPromotionV2Parts) -> Result<Self, ReplayError> {
        if parts.codec != 1 || parts.sequence == 0 || parts.sequence != parts.version
            || parts.global_position <= 0 || parts.global_position > parts.captured_high_water
            || parts.digest == [0; 32] || parts.head_integrity_digest == [0; 32] {
            return Err(ReplayError::Integrity("invalid accepted V2 promotion".to_owned()));
        }
        let projection = gocode_api::UnauthenticatedReplayPromotionProjectionV1::decode(&parts.bytes)
            .map_err(|_| ReplayError::Integrity("invalid accepted V2 promotion".to_owned()))?;
        Ok(Self { codec: parts.codec, projection, bytes: parts.bytes, digest: parts.digest,
            sequence: parts.sequence, version: parts.version, global_position: parts.global_position,
            head_event_id: parts.head_event_id, head_integrity_digest: parts.head_integrity_digest,
            captured_high_water: parts.captured_high_water })
    }

    pub const fn codec(&self) -> u8 { self.codec }
    pub fn bytes(&self) -> &[u8] { &self.bytes }
    pub const fn digest(&self) -> &[u8; 32] { &self.digest }
    pub const fn sequence(&self) -> u64 { self.sequence }
    pub const fn version(&self) -> u64 { self.version }
    pub const fn global_position(&self) -> i64 { self.global_position }
    pub const fn head_event_id(&self) -> &[u8; 16] { &self.head_event_id }
    pub const fn head_integrity_digest(&self) -> &[u8; 32] { &self.head_integrity_digest }
    pub const fn captured_high_water(&self) -> i64 { self.captured_high_water }
    pub const fn projection(&self) -> &gocode_api::UnauthenticatedReplayPromotionProjectionV1 { &self.projection }
}

impl std::fmt::Debug for ReplayAcceptedPromotionV2 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReplayAcceptedPromotionV2").field("sequence", &self.sequence).field("redacted", &true).finish()
    }
}
