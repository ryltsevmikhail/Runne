const ROOT_ADMISSION_DOMAIN: &[u8] = b"gocode/root-admission/v2";
const ROOT_ADMISSION_BODY_BYTES: usize = 225;

/// Trusted native input accepted only after a protected directory-handle check.
pub struct RootAdmissionRequest {
    context: RootAdmissionVerificationContext,
    workspace_id: WorkspaceId,
    expected_version: u64,
    filesystem_identity_digest: [u8; 32],
    nonce: [u8; 16],
    expires_at_unix_millis: u64,
    admission_digest: [u8; 32],
}

impl RootAdmissionRequest {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        context: RootAdmissionVerificationContext, workspace_id: WorkspaceId, expected_version: u64,
        filesystem_identity_digest: [u8; 32], nonce: [u8; 16], expires_at_unix_millis: u64,
        admission_digest: [u8; 32],
    ) -> Result<Self, RootAdmissionValidationError> {
        let claims = VerifiedRootAdmissionClaims::new(
            context.clone(), RootAdmissionAction::WorkspaceBindRoot, workspace_id, expected_version,
            filesystem_identity_digest, nonce, expires_at_unix_millis, admission_digest,
        )?;
        Ok(Self { context, workspace_id, expected_version, filesystem_identity_digest,
            nonce: claims.nonce(), expires_at_unix_millis, admission_digest: claims.admission_digest() })
    }
}

/// Authenticates root-admission envelopes using protected activation key material.
pub struct RootAdmissionAuthenticator {
    key: Zeroizing<[u8; 32]>,
}

impl RootAdmissionAuthenticator {
    /// Creates a native-only issuer/verifier from an established protected launch.
    pub fn from_protected_activation(keys: &ProtectedActivationKeys) -> Self {
        Self { key: Zeroizing::new(derive_key(keys.readiness_key(), ROOT_ADMISSION_DOMAIN)) }
    }

    /// Seals trusted native admission metadata into an opaque renderer-safe envelope.
    pub fn issue(&self, request: RootAdmissionRequest) -> Result<RootHandleAdmission, RootAdmissionValidationError> {
        let body = encode_root_request(&request);
        let mac = authenticated_mac(&self.key, ROOT_ADMISSION_DOMAIN, &body);
        let mut bytes = Vec::with_capacity(ROOT_ADMISSION_BODY_BYTES + mac.len());
        bytes.extend(body);
        bytes.extend(mac);
        RootHandleAdmission::from_verified_bytes(bytes).ok_or(RootAdmissionValidationError::ZeroBinding)
    }

    /// Authenticates and opens one opaque admission without exposing its bytes.
    pub fn verify(&self, admission: RootHandleAdmission) -> Result<VerifiedRootAdmissionClaims, RootAdmissionValidationError> {
        if admission.bytes.len() != ROOT_ADMISSION_BODY_BYTES + 32 { return Err(RootAdmissionValidationError::ZeroBinding); }
        let (body, proof) = admission.bytes.split_at(ROOT_ADMISSION_BODY_BYTES);
        let expected = authenticated_mac(&self.key, ROOT_ADMISSION_DOMAIN, body);
        if !bool::from(expected.ct_eq(proof)) { return Err(RootAdmissionValidationError::ZeroBinding); }
        decode_root_claims(body)
    }
}

fn encode_root_request(request: &RootAdmissionRequest) -> Vec<u8> {
    let context = &request.context;
    let mut body = Vec::with_capacity(ROOT_ADMISSION_BODY_BYTES);
    body.extend(context.authority_digest()); body.extend(context.session_id());
    put_u64(&mut body, context.launch_generation()); body.extend(context.principal_digest());
    put_u64(&mut body, context.capability_version()); put_u64(&mut body, context.policy_version());
    put_u64(&mut body, context.now_unix_millis());
    body.push(1); body.extend(request.workspace_id.as_bytes()); put_u64(&mut body, request.expected_version);
    body.extend(request.filesystem_identity_digest); body.extend(request.nonce);
    put_u64(&mut body, request.expires_at_unix_millis); body.extend(request.admission_digest); body
}

fn decode_root_claims(body: &[u8]) -> Result<VerifiedRootAdmissionClaims, RootAdmissionValidationError> {
    let mut offset = 0;
    let authority = take::<32>(body, &mut offset)?; let session = take::<16>(body, &mut offset)?;
    let generation = take_u64(body, &mut offset)?; let principal = take::<32>(body, &mut offset)?;
    let capability = take_u64(body, &mut offset)?; let policy = take_u64(body, &mut offset)?;
    let now = take_u64(body, &mut offset)?;
    if take::<1>(body, &mut offset)? != [1] { return Err(RootAdmissionValidationError::ZeroBinding); }
    let workspace = WorkspaceId::from_bytes(take::<16>(body, &mut offset)?);
    let version = take_u64(body, &mut offset)?; let identity = take::<32>(body, &mut offset)?;
    let nonce = take::<16>(body, &mut offset)?; let expiry = take_u64(body, &mut offset)?;
    let digest = take::<32>(body, &mut offset)?;
    if offset != body.len() { return Err(RootAdmissionValidationError::ZeroBinding); }
    let context = RootAdmissionVerificationContext::new(authority, session, generation, principal, capability, policy, now)?;
    VerifiedRootAdmissionClaims::new(context, RootAdmissionAction::WorkspaceBindRoot, workspace, version, identity, nonce, expiry, digest)
}

fn put_u64(bytes: &mut Vec<u8>, value: u64) { bytes.extend(value.to_be_bytes()); }
fn take_u64(bytes: &[u8], offset: &mut usize) -> Result<u64, RootAdmissionValidationError> { Ok(u64::from_be_bytes(take::<8>(bytes, offset)?)) }
fn take<const N: usize>(bytes: &[u8], offset: &mut usize) -> Result<[u8; N], RootAdmissionValidationError> {
    let end = offset.checked_add(N).ok_or(RootAdmissionValidationError::ZeroBinding)?;
    let value = bytes.get(*offset..end).ok_or(RootAdmissionValidationError::ZeroBinding)?;
    *offset = end; value.try_into().map_err(|_| RootAdmissionValidationError::ZeroBinding)
}

#[cfg(test)]
mod root_admission_authenticator_tests {
    use super::*;

    #[test]
    fn verifier_rejects_the_fixed_v1_envelope_after_the_v2_hard_cut() {
        const V1_DOMAIN: &[u8] = b"gocode/root-admission/v1";
        let keys = LaunchSecret::from_bytes([7; 32]).unwrap().derive_keys();
        let context = RootAdmissionVerificationContext::new(
            [1; 32], [2; 16], 1, [3; 32], 1, 1, 10,
        ).unwrap();
        let workspace = WorkspaceId::from_bytes([4; 16]);
        let mut body = Vec::with_capacity(233);
        body.extend(context.authority_digest()); body.extend(context.session_id());
        put_u64(&mut body, context.launch_generation()); body.extend(context.principal_digest());
        put_u64(&mut body, context.capability_version()); put_u64(&mut body, context.policy_version());
        put_u64(&mut body, 1); put_u64(&mut body, context.now_unix_millis());
        body.push(1); body.extend(workspace.as_bytes()); put_u64(&mut body, 1);
        body.extend([5; 32]); body.extend([6; 16]); put_u64(&mut body, 20); body.extend([8; 32]);
        assert_eq!(body.len(), 233);
        let key = derive_key(keys.readiness_key(), V1_DOMAIN);
        let mut envelope = body;
        let proof = authenticated_mac(&key, V1_DOMAIN, &envelope);
        envelope.extend(proof);
        assert_eq!(envelope.len(), 265);
        let v1_admission = RootHandleAdmission::from_verified_bytes(envelope).unwrap();
        let v2 = RootAdmissionAuthenticator::from_protected_activation(&keys);
        assert!(v2.verify(v1_admission).is_err());
    }

    #[test]
    fn v2_envelope_has_the_gate_free_fixed_wire_length_and_rejects_tampering() {
        let keys = LaunchSecret::from_bytes([7; 32]).unwrap().derive_keys();
        let request = RootAdmissionRequest::new(
            RootAdmissionVerificationContext::new([1; 32], [2; 16], 1, [3; 32], 1, 1, 10).unwrap(),
            WorkspaceId::from_bytes([4; 16]), 1, [5; 32], [6; 16], 20, [8; 32],
        ).unwrap();
        let authenticator = RootAdmissionAuthenticator::from_protected_activation(&keys);
        let mut admission = authenticator.issue(request).unwrap();
        assert_eq!(admission.bytes.len(), ROOT_ADMISSION_BODY_BYTES + 32);
        assert_eq!(ROOT_ADMISSION_BODY_BYTES, 225);
        admission.bytes[0] ^= 1;
        assert!(authenticator.verify(admission).is_err());
    }
}
