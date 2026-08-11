/// One bounded authenticated control message for a protected root-handle transfer.
pub enum RootHandleControlFrame {
    Offer(RootHandleTransferOffer),
    Ready(RootHandleTransferReady),
    Result(RootHandleTransferResult),
}

const ROOT_CONTROL_MAGIC: &[u8; 8] = b"GCRHCTL2";
const ROOT_CONTROL_UNSIGNED_BYTES: usize = 158;
const ROOT_CONTROL_RESULT_UNSIGNED_BYTES: usize =
    ROOT_CONTROL_UNSIGNED_BYTES + ROOT_HANDLE_ADMISSION_V2_BYTES;
const ROOT_CONTROL_OFFER: u8 = 1;
const ROOT_CONTROL_READY: u8 = 2;
const ROOT_CONTROL_RESULT: u8 = 3;
const ROOT_CONTROL_ACCEPTED: u8 = 1;

/// Closed tuple bound into every phase of one root-handle transfer.
#[derive(Clone, PartialEq, Eq)]
pub struct RootHandleTransferContext {
    authority_id: [u8; 16], session_id: [u8; 16], launch_generation: u64,
    sender_pid: u32, receiver_pid: u32, effective_uid: u32, workspace_id: WorkspaceId,
    expected_version: u64, transfer_id: [u8; 16], issued_at_unix_millis: u64,
    expires_at_unix_millis: u64,
}

impl RootHandleTransferContext {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        authority_id: [u8; 16], session_id: [u8; 16], launch_generation: u64,
        sender_pid: u32, receiver_pid: u32, effective_uid: u32, workspace_id: WorkspaceId,
        expected_version: u64, transfer_id: [u8; 16], issued_at_unix_millis: u64,
        expires_at_unix_millis: u64,
    ) -> Result<Self, LaunchAuthorityError> {
        if validate_uuid_v7_bytes(&authority_id).is_err()
            || validate_uuid_v7_bytes(&session_id).is_err()
            || validate_uuid_v7_bytes(workspace_id.as_bytes()).is_err()
            || launch_generation == 0 || sender_pid == 0 || receiver_pid == 0
            || expected_version == 0 || transfer_id == [0; 16]
            || issued_at_unix_millis == 0 || expires_at_unix_millis <= issued_at_unix_millis
            || expires_at_unix_millis - issued_at_unix_millis > MAX_LAUNCH_TTL_MILLIS
        { return Err(LaunchAuthorityError::InvalidContract); }
        Ok(Self { authority_id, session_id, launch_generation, sender_pid, receiver_pid,
            effective_uid, workspace_id, expected_version, transfer_id, issued_at_unix_millis,
            expires_at_unix_millis })
    }
    #[must_use] pub const fn authority_id(&self) -> &[u8; 16] { &self.authority_id }
    #[must_use] pub const fn session_id(&self) -> &[u8; 16] { &self.session_id }
    #[must_use] pub const fn launch_generation(&self) -> u64 { self.launch_generation }
    #[must_use] pub const fn sender_pid(&self) -> u32 { self.sender_pid }
    #[must_use] pub const fn receiver_pid(&self) -> u32 { self.receiver_pid }
    #[must_use] pub const fn effective_uid(&self) -> u32 { self.effective_uid }
    #[must_use] pub const fn workspace_id(&self) -> WorkspaceId { self.workspace_id }
    #[must_use] pub const fn expected_version(&self) -> u64 { self.expected_version }
    #[must_use] pub const fn transfer_id(&self) -> &[u8; 16] { &self.transfer_id }
    #[must_use] pub const fn expires_at_unix_millis(&self) -> u64 { self.expires_at_unix_millis }
}

/// Authenticated offer that precedes the native descriptor transfer.
pub struct RootHandleTransferOffer { context: RootHandleTransferContext, sequence: u64, proof: [u8; 32] }
/// Authenticated receiver readiness bound to the exact offer digest.
pub struct RootHandleTransferReady { context: RootHandleTransferContext, sequence: u64, offer_digest: [u8; 32], proof: [u8; 32] }
/// Authenticated post-descriptor result; rejection stays protocol-synchronized.
pub struct RootHandleTransferResult {
    context: RootHandleTransferContext, sequence: u64, offer_digest: [u8; 32],
    accepted: bool, admission: Option<RootHandleAdmission>, proof: [u8; 32],
}

impl RootHandleTransferOffer {
    pub fn new(context: RootHandleTransferContext, sequence: u64, keys: &RootHandleTransferAuthenticator) -> Result<Self, LaunchAuthorityError> {
        if sequence == 0 { return Err(LaunchAuthorityError::RenewalReplay); }
        let mut value = Self { context, sequence, proof: [0; 32] };
        value.proof = keys.authenticate_root_offer(&value.unsigned()); Ok(value)
    }
    #[must_use] pub const fn context(&self) -> &RootHandleTransferContext { &self.context }
    #[must_use] pub const fn sequence(&self) -> u64 { self.sequence }
    #[must_use] pub fn digest(&self) -> [u8; 32] { Sha256::digest(self.unsigned()).into() }
    fn unsigned(&self) -> [u8; ROOT_CONTROL_UNSIGNED_BYTES] { encode_unsigned(ROOT_CONTROL_OFFER, &self.context, self.sequence, [0; 32], 0) }
}
impl RootHandleTransferReady {
    pub fn new(offer: &RootHandleTransferOffer, keys: &RootHandleTransferAuthenticator) -> Self {
        let mut value = Self { context: offer.context.clone(), sequence: offer.sequence + 1, offer_digest: offer.digest(), proof: [0; 32] };
        value.proof = keys.authenticate_root_ready(&value.unsigned()); value
    }
    fn unsigned(&self) -> [u8; ROOT_CONTROL_UNSIGNED_BYTES] { encode_unsigned(ROOT_CONTROL_READY, &self.context, self.sequence, self.offer_digest, 0) }
    #[must_use] pub const fn offer_digest(&self) -> &[u8; 32] { &self.offer_digest }
}
impl RootHandleTransferResult {
    /// Creates the only semantic rejection result. It carries no native material.
    pub fn rejected(ready: &RootHandleTransferReady, keys: &RootHandleTransferAuthenticator) -> Self {
        let mut value = Self { context: ready.context.clone(), sequence: ready.sequence + 1, offer_digest: ready.offer_digest, accepted: false, admission: None, proof: [0; 32] };
        value.proof = keys.authenticate_root_result(&value.unsigned()); value
    }
    /// Creates a successful result bound to the exact offer and opaque admission.
    pub fn admitted(ready: &RootHandleTransferReady, admission: RootHandleAdmission, keys: &RootHandleTransferAuthenticator) -> Self {
        let mut value = Self { context: ready.context.clone(), sequence: ready.sequence + 1, offer_digest: ready.offer_digest, accepted: true, admission: Some(admission), proof: [0; 32] };
        value.proof = keys.authenticate_root_result(&value.unsigned()); value
    }
    #[must_use] pub const fn accepted(&self) -> bool { self.accepted }
    #[must_use] pub const fn offer_digest(&self) -> &[u8; 32] { &self.offer_digest }
    /// Returns the opaque admission only after the signed result has been verified.
    #[must_use] pub fn into_admission(self) -> Option<RootHandleAdmission> { self.admission }
    fn unsigned(&self) -> Vec<u8> {
        let mut value = encode_unsigned(ROOT_CONTROL_RESULT, &self.context, self.sequence, self.offer_digest, u8::from(self.accepted)).to_vec();
        match &self.admission { Some(admission) => value.extend_from_slice(&admission.bytes), None => value.extend([0; ROOT_HANDLE_ADMISSION_V2_BYTES]) }
        value
    }
}

impl RootHandleControlFrame {
    /// Encodes one ordinary protected-channel frame, including its length prefix.
    #[must_use]
    pub fn encode_frame(&self) -> Vec<u8> {
        let (unsigned, proof): (Vec<u8>, [u8; 32]) = match self {
            Self::Offer(value) => (value.unsigned().to_vec(), value.proof),
            Self::Ready(value) => (value.unsigned().to_vec(), value.proof),
            Self::Result(value) => (value.unsigned(), value.proof),
        };
        let mut bytes = Vec::with_capacity(unsigned.len() + proof.len() + 4);
        bytes.extend_from_slice(&u32::try_from(unsigned.len() + proof.len()).unwrap_or(0).to_be_bytes());
        bytes.extend_from_slice(&unsigned); bytes.extend_from_slice(&proof); bytes
    }
    pub fn decode_and_verify(
        bytes: &[u8], keys: &RootHandleTransferAuthenticator, expected: &RootHandleTransferContext,
        previous_sequence: u64, now_unix_millis: u64,
    ) -> Result<Self, LaunchAuthorityError> {
        if !valid_frame(bytes) || now_unix_millis == 0 { return Err(LaunchAuthorityError::InvalidContract); }
        let phase = bytes[12]; let unsigned_len = if phase == ROOT_CONTROL_RESULT { ROOT_CONTROL_RESULT_UNSIGNED_BYTES } else { ROOT_CONTROL_UNSIGNED_BYTES };
        if bytes.len() != 4 + unsigned_len + 32 { return Err(LaunchAuthorityError::InvalidContract); }
        let unsigned = &bytes[4..4 + unsigned_len];
        let proof: [u8; 32] = bytes[4 + unsigned_len..].try_into().map_err(|_| LaunchAuthorityError::InvalidContract)?;
        let fixed: [u8; ROOT_CONTROL_UNSIGNED_BYTES] = unsigned[..ROOT_CONTROL_UNSIGNED_BYTES].try_into().map_err(|_| LaunchAuthorityError::InvalidContract)?;
        let (phase, context, sequence, digest, accepted) = decode_unsigned(&fixed)?;
        if &context != expected || sequence != previous_sequence.checked_add(1).ok_or(LaunchAuthorityError::RenewalReplay)?
            || now_unix_millis < context.issued_at_unix_millis || now_unix_millis > context.expires_at_unix_millis { return Err(LaunchAuthorityError::OwnershipMismatch); }
        let frame = match phase {
            ROOT_CONTROL_OFFER if digest == [0; 32] && accepted == 0 && keys.verifies_root_offer(unsigned, &proof) => Self::Offer(RootHandleTransferOffer { context, sequence, proof }),
            ROOT_CONTROL_READY if accepted == 0 && keys.verifies_root_ready(unsigned, &proof) => Self::Ready(RootHandleTransferReady { context, sequence, offer_digest: digest, proof }),
            ROOT_CONTROL_RESULT if accepted <= ROOT_CONTROL_ACCEPTED && keys.verifies_root_result(unsigned, &proof) => {
                let payload = &unsigned[ROOT_CONTROL_UNSIGNED_BYTES..];
                let admission = if accepted == ROOT_CONTROL_ACCEPTED { Some(RootHandleAdmission::from_verified_bytes(payload.to_vec()).ok_or(LaunchAuthorityError::InvalidContract)?) } else if payload.iter().all(|value| *value == 0) { None } else { return Err(LaunchAuthorityError::InvalidContract); };
                Self::Result(RootHandleTransferResult { context, sequence, offer_digest: digest, accepted: accepted == ROOT_CONTROL_ACCEPTED, admission, proof })
            },
            _ => return Err(LaunchAuthorityError::ReadinessProofMismatch),
        };
        Ok(frame)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn decode_offer_for_receiver(
        bytes: &[u8], keys: &RootHandleTransferAuthenticator, authority_id: &[u8; 16],
        session_id: &[u8; 16], launch_generation: u64, sender_pid: u32, receiver_pid: u32,
        effective_uid: u32, previous_sequence: u64, now_unix_millis: u64,
    ) -> Result<RootHandleTransferOffer, LaunchAuthorityError> {
        if !valid_frame(bytes) || now_unix_millis == 0 { return Err(LaunchAuthorityError::InvalidContract); }
        let unsigned: [u8; ROOT_CONTROL_UNSIGNED_BYTES] = bytes[4..4 + ROOT_CONTROL_UNSIGNED_BYTES].try_into().map_err(|_| LaunchAuthorityError::InvalidContract)?;
        let proof: [u8; 32] = bytes[4 + ROOT_CONTROL_UNSIGNED_BYTES..].try_into().map_err(|_| LaunchAuthorityError::InvalidContract)?;
        let (phase, context, sequence, digest, accepted) = decode_unsigned(&unsigned)?;
        if phase != ROOT_CONTROL_OFFER || sequence != previous_sequence.checked_add(1).ok_or(LaunchAuthorityError::RenewalReplay)? || digest != [0; 32] || accepted != 0
            || context.authority_id != *authority_id || context.session_id != *session_id
            || context.launch_generation != launch_generation || context.sender_pid != sender_pid
            || context.receiver_pid != receiver_pid || context.effective_uid != effective_uid
            || now_unix_millis < context.issued_at_unix_millis || now_unix_millis > context.expires_at_unix_millis
            || !keys.verifies_root_offer(&unsigned, &proof)
        { return Err(LaunchAuthorityError::OwnershipMismatch); }
        Ok(RootHandleTransferOffer { context, sequence, proof })
    }
}

/// Returns whether one ordinary protected-channel frame is a root control frame.
#[must_use]
pub fn is_root_handle_control_frame(bytes: &[u8]) -> bool { valid_frame(bytes) && bytes[4..12] == *ROOT_CONTROL_MAGIC }

fn valid_frame(bytes: &[u8]) -> bool {
    bytes.len() >= 4 + ROOT_CONTROL_UNSIGNED_BYTES + 32
        && u32::from_be_bytes(bytes[..4].try_into().unwrap_or([0; 4])) as usize == bytes.len() - 4
}

fn encode_unsigned(phase: u8, context: &RootHandleTransferContext, sequence: u64, digest: [u8; 32], accepted: u8) -> [u8; ROOT_CONTROL_UNSIGNED_BYTES] {
    let mut value = [0; ROOT_CONTROL_UNSIGNED_BYTES]; value[..8].copy_from_slice(ROOT_CONTROL_MAGIC); value[8] = phase;
    let mut index = 9; for bytes in [&context.authority_id[..], &context.session_id[..]] { value[index..index + bytes.len()].copy_from_slice(bytes); index += bytes.len(); }
    for bytes in [context.launch_generation.to_be_bytes().as_slice(), context.sender_pid.to_be_bytes().as_slice(), context.receiver_pid.to_be_bytes().as_slice(), context.effective_uid.to_be_bytes().as_slice(), context.workspace_id.as_bytes().as_slice(), context.expected_version.to_be_bytes().as_slice(), context.transfer_id.as_slice(), context.issued_at_unix_millis.to_be_bytes().as_slice(), context.expires_at_unix_millis.to_be_bytes().as_slice(), sequence.to_be_bytes().as_slice(), digest.as_slice(), &[accepted]] { value[index..index + bytes.len()].copy_from_slice(bytes); index += bytes.len(); }
    value
}
fn decode_unsigned(value: &[u8; ROOT_CONTROL_UNSIGNED_BYTES]) -> Result<(u8, RootHandleTransferContext, u64, [u8; 32], u8), LaunchAuthorityError> {
    if value[..8] != *ROOT_CONTROL_MAGIC { return Err(LaunchAuthorityError::InvalidContract); }
    let mut index = 9; let take16 = |index: &mut usize| { let output = value[*index..*index + 16].try_into().unwrap(); *index += 16; output }; let take8 = |index: &mut usize| { let output = u64::from_be_bytes(value[*index..*index + 8].try_into().unwrap()); *index += 8; output }; let take4 = |index: &mut usize| { let output = u32::from_be_bytes(value[*index..*index + 4].try_into().unwrap()); *index += 4; output };
    let authority = take16(&mut index); let session = take16(&mut index); let generation = take8(&mut index); let sender = take4(&mut index); let receiver = take4(&mut index); let uid = take4(&mut index); let workspace = WorkspaceId::from_bytes(take16(&mut index)); let version = take8(&mut index); let transfer = take16(&mut index); let issued = take8(&mut index); let expires = take8(&mut index); let sequence = take8(&mut index); let digest = value[index..index + 32].try_into().unwrap(); index += 32; let accepted = value[index];
    let context = RootHandleTransferContext::new(authority, session, generation, sender, receiver, uid, workspace, version, transfer, issued, expires)?;
    Ok((value[8], context, sequence, digest, accepted))
}

impl std::fmt::Debug for RootHandleControlFrame { fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { formatter.write_str("RootHandleControlFrame(<redacted>)") } }

#[cfg(test)]
mod root_handle_control_tests {
    use super::*;
    fn context() -> RootHandleTransferContext { RootHandleTransferContext::new([0,0,0,0,0,0,0x70,0,0x80,0,0,0,0,0,0,1], [0,0,0,0,0,0,0x70,0,0x80,0,0,0,0,0,0,2], 1, 10, 11, 1000, WorkspaceId::from_bytes([0,0,0,0,0,0,0x70,0,0x80,0,0,0,0,0,0,3]), 1, [4;16], 100, 30_100).unwrap() }
    #[test] fn root_control_offer_is_framed_authenticated_and_strictly_sequenced() { let keys = RootHandleTransferAuthenticator::from_protected_activation(&LaunchSecret::from_bytes([7;32]).unwrap().derive_keys()); let offer = RootHandleTransferOffer::new(context(), 1, &keys).unwrap(); let encoded = RootHandleControlFrame::Offer(offer).encode_frame(); assert!(is_root_handle_control_frame(&encoded)); assert!(matches!(RootHandleControlFrame::decode_and_verify(&encoded, &keys, &context(), 0, 100).unwrap(), RootHandleControlFrame::Offer(_))); assert!(RootHandleControlFrame::decode_and_verify(&encoded, &keys, &context(), 1, 100).is_err()); }
    #[test] fn root_control_binds_ready_and_admission_result_to_the_offer_digest() { let keys = RootHandleTransferAuthenticator::from_protected_activation(&LaunchSecret::from_bytes([8;32]).unwrap().derive_keys()); let offer = RootHandleTransferOffer::new(context(), 1, &keys).unwrap(); let ready = RootHandleTransferReady::new(&offer, &keys); let admission = RootHandleAdmission::from_verified_bytes(vec![7; ROOT_HANDLE_ADMISSION_V2_BYTES]).unwrap(); let result = RootHandleTransferResult::admitted(&ready, admission, &keys); assert_eq!(offer.digest(), *ready.offer_digest()); assert_eq!(*ready.offer_digest(), *result.offer_digest()); let decoded = RootHandleControlFrame::decode_and_verify(&RootHandleControlFrame::Result(result).encode_frame(), &keys, &context(), 2, 100).unwrap(); let RootHandleControlFrame::Result(value) = decoded else { panic!("expected result") }; assert!(value.accepted()); assert!(value.into_admission().is_some()); }
    #[test] fn root_control_rejects_a_signed_rejection_with_payload() { let keys = RootHandleTransferAuthenticator::from_protected_activation(&LaunchSecret::from_bytes([8;32]).unwrap().derive_keys()); let offer = RootHandleTransferOffer::new(context(), 1, &keys).unwrap(); let ready = RootHandleTransferReady::new(&offer, &keys); let mut result = RootHandleTransferResult { context: ready.context.clone(), sequence: 2, offer_digest: *ready.offer_digest(), accepted: false, admission: RootHandleAdmission::from_verified_bytes(vec![7; ROOT_HANDLE_ADMISSION_V2_BYTES]), proof: [0;32] }; result.proof = keys.authenticate_root_result(&result.unsigned()); assert!(RootHandleControlFrame::decode_and_verify(&RootHandleControlFrame::Result(result).encode_frame(), &keys, &context(), 1, 100).is_err()); }
    #[test] fn root_control_rejects_tampering_expiry_and_peer_substitution() { let keys = RootHandleTransferAuthenticator::from_protected_activation(&LaunchSecret::from_bytes([9;32]).unwrap().derive_keys()); let offer = RootHandleTransferOffer::new(context(), 1, &keys).unwrap(); let mut encoded = RootHandleControlFrame::Offer(offer).encode_frame(); encoded[24] ^= 1; assert!(RootHandleControlFrame::decode_and_verify(&encoded, &keys, &context(), 0, 100).is_err()); let offer = RootHandleTransferOffer::new(context(), 1, &keys).unwrap(); let encoded = RootHandleControlFrame::Offer(offer).encode_frame(); assert!(RootHandleControlFrame::decode_and_verify(&encoded, &keys, &context(), 0, 30_101).is_err()); assert!(RootHandleControlFrame::decode_offer_for_receiver(&encoded, &keys, context().authority_id(), context().session_id(), 1, 99, 11, 1000, 0, 100).is_err()); }
    #[test] fn root_control_rejects_bad_length_prefix_before_magic() { let keys = RootHandleTransferAuthenticator::from_protected_activation(&LaunchSecret::from_bytes([10;32]).unwrap().derive_keys()); let offer = RootHandleTransferOffer::new(context(), 1, &keys).unwrap(); let mut frame = RootHandleControlFrame::Offer(offer).encode_frame(); frame[..4].copy_from_slice(&1_u32.to_be_bytes()); assert!(!is_root_handle_control_frame(&frame)); }
}
