const ROOT_ADMISSION_DOMAIN: &[u8] = b"runne/root-admission/v3";
const ROOT_ADMISSION_DIGEST_DOMAIN: &[u8] = b"runne/root-admission/digest/v3\0";
const ROOT_ADMISSION_PAYLOAD_BYTES: usize = 225;

/// Trusted native input accepted only after a protected directory-handle check.
pub struct RootAdmissionRequest {
    context: RootAdmissionVerificationContext,
    workspace_id: WorkspaceId,
    expected_version: u64,
    filesystem_identity_digest: [u8; 32],
    offer_digest: [u8; 32],
    nonce: [u8; 16],
    expires_at_unix_millis: u64,
}

impl RootAdmissionRequest {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        context: RootAdmissionVerificationContext,
        workspace_id: WorkspaceId,
        expected_version: u64,
        filesystem_identity_digest: [u8; 32],
        offer_digest: [u8; 32],
        nonce: [u8; 16],
        expires_at_unix_millis: u64,
    ) -> Result<Self, RootAdmissionValidationError> {
        let digest = admission_digest(&encode_payload(
            &context, workspace_id, expected_version, filesystem_identity_digest, offer_digest, nonce, expires_at_unix_millis,
        ));
        VerifiedRootAdmissionClaims::new(
            context.clone(), RootAdmissionAction::WorkspaceBindRoot, workspace_id, expected_version,
            filesystem_identity_digest, offer_digest, nonce, expires_at_unix_millis, digest,
        )?;
        Ok(Self { context, workspace_id, expected_version, filesystem_identity_digest, offer_digest, nonce, expires_at_unix_millis })
    }
}

/// Authenticates canonical root-admission envelopes using protected activation keys.
pub struct RootAdmissionAuthenticator { key: Zeroizing<[u8; 32]> }
impl RootAdmissionAuthenticator {
    #[must_use]
    pub fn from_protected_activation(keys: &ProtectedActivationKeys) -> Self {
        Self { key: Zeroizing::new(derive_key(keys.readiness_key(), ROOT_ADMISSION_DOMAIN)) }
    }
    pub fn issue(&self, request: RootAdmissionRequest) -> Result<IssuedRootHandleAdmission, RootAdmissionValidationError> {
        let payload = encode_payload(&request.context, request.workspace_id, request.expected_version, request.filesystem_identity_digest, request.offer_digest, request.nonce, request.expires_at_unix_millis);
        let digest = admission_digest(&payload);
        let mac = authenticated_mac(&self.key, ROOT_ADMISSION_DOMAIN, &[payload.as_slice(), &digest].concat());
        let mut envelope = payload.to_vec(); envelope.extend(digest); envelope.extend(mac);
        RootHandleAdmission::from_verified_bytes(envelope).map(IssuedRootHandleAdmission).ok_or(RootAdmissionValidationError::ZeroBinding)
    }
    pub fn verify_issued(&self, admission: IssuedRootHandleAdmission) -> Result<VerifiedRootAdmissionClaims, RootAdmissionValidationError> {
        self.verify(admission.into_admission())
    }
    pub fn verify(&self, admission: RootHandleAdmission) -> Result<VerifiedRootAdmissionClaims, RootAdmissionValidationError> {
        let (payload, tail) = admission.bytes.split_at(ROOT_ADMISSION_PAYLOAD_BYTES);
        let (digest, mac) = tail.split_at(32);
        let calculated = admission_digest(payload);
        let proof = authenticated_mac(&self.key, ROOT_ADMISSION_DOMAIN, &[payload, digest].concat());
        if !bool::from(calculated.ct_eq(digest)) || !bool::from(proof.ct_eq(mac)) { return Err(RootAdmissionValidationError::ZeroBinding); }
        decode_claims(payload, calculated)
    }
}

fn encode_payload(
    context: &RootAdmissionVerificationContext, workspace: WorkspaceId, version: u64, identity: [u8; 32],
    offer: [u8; 32], nonce: [u8; 16], expiry: u64,
) -> [u8; ROOT_ADMISSION_PAYLOAD_BYTES] {
    let mut value = [0; ROOT_ADMISSION_PAYLOAD_BYTES]; let mut index = 0;
    for part in [context.authority_digest().as_slice(), context.session_id().as_slice(), context.launch_generation().to_be_bytes().as_slice(), context.principal_digest().as_slice(), &[1], &3_u64.to_be_bytes(), context.policy_version().to_be_bytes().as_slice(), context.now_unix_millis().to_be_bytes().as_slice(), workspace.as_bytes().as_slice(), version.to_be_bytes().as_slice(), identity.as_slice(), offer.as_slice(), nonce.as_slice(), expiry.to_be_bytes().as_slice()] {
        value[index..index + part.len()].copy_from_slice(part); index += part.len();
    }
    value
}
fn decode_claims(payload: &[u8], digest: [u8; 32]) -> Result<VerifiedRootAdmissionClaims, RootAdmissionValidationError> {
    let mut index = 0;
    let authority = take::<32>(payload, &mut index)?; let session = take::<16>(payload, &mut index)?;
    let generation = take_u64(payload, &mut index)?; let principal = take::<32>(payload, &mut index)?;
    if take::<1>(payload, &mut index)? != [1] || take_u64(payload, &mut index)? != 3 { return Err(RootAdmissionValidationError::ZeroBinding); }
    let policy = take_u64(payload, &mut index)?; let issued = take_u64(payload, &mut index)?;
    let workspace = WorkspaceId::from_bytes(take::<16>(payload, &mut index)?); let version = take_u64(payload, &mut index)?;
    let identity = take::<32>(payload, &mut index)?; let offer = take::<32>(payload, &mut index)?;
    let nonce = take::<16>(payload, &mut index)?; let expiry = take_u64(payload, &mut index)?;
    if index != payload.len() { return Err(RootAdmissionValidationError::ZeroBinding); }
    VerifiedRootAdmissionClaims::new(RootAdmissionVerificationContext::new(authority, session, generation, principal, 3, policy, issued)?, RootAdmissionAction::WorkspaceBindRoot, workspace, version, identity, offer, nonce, expiry, digest)
}
fn admission_digest(payload: &[u8]) -> [u8; 32] {
    let mut value = Sha256::new(); value.update(ROOT_ADMISSION_DIGEST_DOMAIN); value.update(payload); value.finalize().into()
}
fn take_u64(value: &[u8], index: &mut usize) -> Result<u64, RootAdmissionValidationError> { Ok(u64::from_be_bytes(take::<8>(value, index)?)) }
fn take<const N: usize>(value: &[u8], index: &mut usize) -> Result<[u8; N], RootAdmissionValidationError> {
    let end = index.checked_add(N).ok_or(RootAdmissionValidationError::ZeroBinding)?;
    let result = value.get(*index..end).ok_or(RootAdmissionValidationError::ZeroBinding)?; *index = end;
    result.try_into().map_err(|_| RootAdmissionValidationError::ZeroBinding)
}

#[cfg(test)]
mod root_admission_authenticator_tests {
    use super::*;
    fn request() -> RootAdmissionRequest {
        RootAdmissionRequest::new(
            RootAdmissionVerificationContext::new([1; 32], [2; 16], 1, [3; 32], 3, 1, 10).unwrap(),
            WorkspaceId::from_bytes([4; 16]), 1, [5; 32], [6; 32], [7; 16], 20,
        ).unwrap()
    }
    #[test]
    fn v2_envelopes_are_rejected_before_authentication() {
        assert!(RootHandleAdmission::from_verified_bytes(vec![0; 257]).is_none());
    }
    #[test]
    fn v3_envelope_rejects_tampered_payload_and_digest() {
        let authenticator = RootAdmissionAuthenticator::from_protected_activation(&LaunchSecret::from_bytes([7; 32]).unwrap().derive_keys());
        let mut admission = authenticator.issue(request()).unwrap(); admission.0.bytes[177] ^= 1;
        assert!(authenticator.verify_issued(admission).is_err());
        let mut admission = authenticator.issue(request()).unwrap(); admission.0.bytes[225] ^= 1;
        assert!(authenticator.verify_issued(admission).is_err());
    }
}
