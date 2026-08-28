fn open(
    bytes: &[u8],
    expected_phase: u8,
    unsigned_len: usize,
) -> Result<(&[u8], [u8; 32]), LaunchAuthorityError> {
    if bytes.len() != 4 + unsigned_len + 32
        || u32::from_be_bytes(bytes[..4].try_into().unwrap_or([0; 4])) as usize != bytes.len() - 4
    {
        return Err(LaunchAuthorityError::InvalidContract);
    }
    let unsigned = &bytes[4..4 + unsigned_len];
    if unsigned[..8] != *ENROLLMENT_CONTROL_MAGIC || unsigned[8] != expected_phase {
        return Err(LaunchAuthorityError::InvalidContract);
    }
    Ok((
        unsigned,
        bytes[4 + unsigned_len..]
            .try_into()
            .map_err(|_| LaunchAuthorityError::InvalidContract)?,
    ))
}

fn encode_request(
    value: &ProtectedCredentialEnrollmentRequestBinding,
    sequence: u64,
) -> [u8; REQUEST_BYTES] {
    let mut output = [0; REQUEST_BYTES];
    let mut index = 0;
    for field in [
        &ENROLLMENT_CONTROL_MAGIC[..],
        &[REQUEST_PHASE],
        &value.protected_launch_authority_id,
        &value.protected_session_id,
        &value.daemon_instance_id,
        &value.daemon_launch_generation.to_be_bytes(),
        &value.desktop_supervisor_generation.to_be_bytes(),
        &value.request_id,
        &value.release_tuple_digest,
        &value.tauri_peer_process_evidence_digest,
        &value.native_confirmation_digest,
        &value.broker_process_evidence_digest,
        &value.native_intent_digest,
        &value.action_provider_revision_binding,
        &value.command_identity_binding,
        &value.issued_at_unix_millis.to_be_bytes(),
        &value.expires_at_unix_millis.to_be_bytes(),
        &sequence.to_be_bytes(),
    ] {
        output[index..index + field.len()].copy_from_slice(field);
        index += field.len();
    }
    output
}

fn encode_admission(
    request_digest: [u8; 32],
    value: &ProtectedCredentialEnrollmentAdmissionBinding,
    sequence: u64,
) -> [u8; ADMISSION_BYTES] {
    let mut output = [0; ADMISSION_BYTES];
    let mut index = 0;
    for field in [
        &ENROLLMENT_CONTROL_MAGIC[..],
        &[ADMISSION_PHASE],
        &request_digest,
        &value.installation_identity,
        &value.release_tuple_digest,
        &value.protected_session_binding,
        &value.desktop_supervisor_generation.to_be_bytes(),
        &value.daemon_authority_binding,
        &value.database_generation.to_be_bytes(),
        &value.authenticated_tauri_peer_binding,
        &value.native_confirmation_digest,
        &value.broker_process_evidence_digest,
        &value.admission_id,
        &value.expires_at_unix_millis.to_be_bytes(),
        &sequence.to_be_bytes(),
    ] {
        output[index..index + field.len()].copy_from_slice(field);
        index += field.len();
    }
    output
}

fn decode_request(
    value: &[u8],
) -> Result<(ProtectedCredentialEnrollmentRequestBinding, u64), LaunchAuthorityError> {
    let mut index = 9;
    let binding = ProtectedCredentialEnrollmentRequestBinding::new(
        take_enrollment(value, &mut index)?,
        take_enrollment(value, &mut index)?,
        take_enrollment(value, &mut index)?,
        number(value, &mut index)?,
        number(value, &mut index)?,
        take_enrollment(value, &mut index)?,
        take_enrollment(value, &mut index)?,
        take_enrollment(value, &mut index)?,
        take_enrollment(value, &mut index)?,
        take_enrollment(value, &mut index)?,
        take_enrollment(value, &mut index)?,
        take_enrollment(value, &mut index)?,
        take_enrollment(value, &mut index)?,
        number(value, &mut index)?,
        number(value, &mut index)?,
    )?;
    let sequence = number(value, &mut index)?;
    (index == value.len())
        .then_some((binding, sequence))
        .ok_or(LaunchAuthorityError::InvalidContract)
}

fn decode_admission(
    value: &[u8],
) -> Result<([u8; 32], ProtectedCredentialEnrollmentAdmissionBinding, u64), LaunchAuthorityError> {
    let mut index = 9;
    let request = take_enrollment(value, &mut index)?;
    let binding = ProtectedCredentialEnrollmentAdmissionBinding::new(
        take_enrollment(value, &mut index)?,
        take_enrollment(value, &mut index)?,
        take_enrollment(value, &mut index)?,
        number(value, &mut index)?,
        take_enrollment(value, &mut index)?,
        number(value, &mut index)?,
        take_enrollment(value, &mut index)?,
        take_enrollment(value, &mut index)?,
        take_enrollment(value, &mut index)?,
        take_enrollment(value, &mut index)?,
        number(value, &mut index)?,
    )?;
    let sequence = number(value, &mut index)?;
    (index == value.len())
        .then_some((request, binding, sequence))
        .ok_or(LaunchAuthorityError::InvalidContract)
}

fn take_enrollment<const N: usize>(
    value: &[u8],
    index: &mut usize,
) -> Result<[u8; N], LaunchAuthorityError> {
    let end = index
        .checked_add(N)
        .ok_or(LaunchAuthorityError::InvalidContract)?;
    let bytes = value
        .get(*index..end)
        .ok_or(LaunchAuthorityError::InvalidContract)?;
    *index = end;
    bytes
        .try_into()
        .map_err(|_| LaunchAuthorityError::InvalidContract)
}
fn number(value: &[u8], index: &mut usize) -> Result<u64, LaunchAuthorityError> {
    Ok(u64::from_be_bytes(take_enrollment(value, index)?))
}
fn request_digest(value: &[u8]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(ENROLLMENT_REQUEST_DIGEST_DOMAIN);
    digest.update(value);
    digest.finalize().into()
}
fn next_sequence(previous: u64) -> u64 {
    previous.checked_add(1).unwrap_or(0)
}
fn admission_matches_request(
    request: &VerifiedProtectedCredentialEnrollmentRequest,
    admission: &ProtectedCredentialEnrollmentAdmissionBinding,
) -> bool {
    admission.release_tuple_digest == request.binding.release_tuple_digest
        && admission.desktop_supervisor_generation == request.binding.desktop_supervisor_generation
        && admission.authenticated_tauri_peer_binding
            == request.binding.tauri_peer_process_evidence_digest
        && admission.native_confirmation_digest == request.binding.native_confirmation_digest
        && admission.broker_process_evidence_digest
            == request.binding.broker_process_evidence_digest
        && admission.expires_at_unix_millis <= request.binding.expires_at_unix_millis
}
fn request_is_live_at(request: &VerifiedProtectedCredentialEnrollmentRequest, now: u64) -> bool {
    now >= request.binding.issued_at_unix_millis && now <= request.binding.expires_at_unix_millis
}
fn valid_ids(values: &[[u8; 16]]) -> bool {
    values
        .iter()
        .all(|value| validate_uuid_v7_bytes(value).is_ok())
}
fn valid_digests(values: &[[u8; 32]]) -> bool {
    values.iter().all(|value| *value != [0; 32])
}
