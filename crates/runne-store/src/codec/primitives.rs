use super::*;

pub(super) fn write_u16_be(buf: &mut Vec<u8>, v: u16) {
    buf.extend_from_slice(&v.to_be_bytes());
}

/// Write a u64 in big-endian to a Vec.
pub(super) fn write_u64_be(buf: &mut Vec<u8>, v: u64) {
    buf.extend_from_slice(&v.to_be_bytes());
}

/// Write an i64 in big-endian to a Vec.
pub(super) fn write_i64_be(buf: &mut Vec<u8>, value: i64) {
    buf.extend_from_slice(&value.to_be_bytes());
}

/// Write a length-prefixed byte slice (u16 BE length).
pub(super) fn write_len_prefixed(buf: &mut Vec<u8>, data: &[u8]) {
    let len = data.len() as u16;
    write_u16_be(buf, len);
    buf.extend_from_slice(data);
}

/// Write raw UUID bytes (16 bytes).
pub(super) fn write_uuid(buf: &mut Vec<u8>, bytes: &[u8; 16]) {
    buf.extend_from_slice(bytes);
}

/// Read a u16 BE from bytes at `pos`, advancing `pos`.
pub(super) fn read_u16_be(bytes: &[u8], pos: &mut usize) -> Result<u16, StoreCodecError> {
    if *pos + 2 > bytes.len() {
        return Err(StoreCodecError::Truncated);
    }
    let v = u16::from_be_bytes([bytes[*pos], bytes[*pos + 1]]);
    *pos += 2;
    Ok(v)
}

/// Read a u64 BE from bytes at `pos`, advancing `pos`.
pub(super) fn read_u64_be(bytes: &[u8], pos: &mut usize) -> Result<u64, StoreCodecError> {
    if *pos + 8 > bytes.len() {
        return Err(StoreCodecError::Truncated);
    }
    let v = u64::from_be_bytes([
        bytes[*pos],
        bytes[*pos + 1],
        bytes[*pos + 2],
        bytes[*pos + 3],
        bytes[*pos + 4],
        bytes[*pos + 5],
        bytes[*pos + 6],
        bytes[*pos + 7],
    ]);
    *pos += 8;
    Ok(v)
}

/// Read an i64 BE from bytes at `pos`, advancing `pos`.
pub(super) fn read_i64_be(bytes: &[u8], pos: &mut usize) -> Result<i64, StoreCodecError> {
    if *pos + 8 > bytes.len() {
        return Err(StoreCodecError::Truncated);
    }
    let value = i64::from_be_bytes(
        bytes[*pos..*pos + 8]
            .try_into()
            .map_err(|_| StoreCodecError::Truncated)?,
    );
    *pos += 8;
    Ok(value)
}

/// Read 16 bytes as a UUID from `pos`, advancing `pos`.
pub(super) fn read_uuid(bytes: &[u8], pos: &mut usize) -> Result<[u8; 16], StoreCodecError> {
    if *pos + 16 > bytes.len() {
        return Err(StoreCodecError::Truncated);
    }
    let mut out = [0u8; 16];
    out.copy_from_slice(&bytes[*pos..*pos + 16]);
    *pos += 16;
    Ok(out)
}

/// Read a length-prefixed byte slice (u16 BE length), advancing `pos`.
pub(super) fn read_len_prefixed<'a>(
    bytes: &'a [u8],
    pos: &mut usize,
) -> Result<&'a [u8], StoreCodecError> {
    let len = read_u16_be(bytes, pos)? as usize;
    if *pos + len > bytes.len() {
        return Err(StoreCodecError::Truncated);
    }
    let data = &bytes[*pos..*pos + len];
    *pos += len;
    Ok(data)
}

pub(super) fn write_digest(buf: &mut Vec<u8>, digest: &IntegrityDigest) {
    buf.extend_from_slice(digest.as_bytes());
}

pub(super) fn read_digest(
    bytes: &[u8],
    pos: &mut usize,
) -> Result<IntegrityDigest, StoreCodecError> {
    if *pos + 32 > bytes.len() {
        return Err(StoreCodecError::Truncated);
    }
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&bytes[*pos..*pos + 32]);
    *pos += 32;
    Ok(IntegrityDigest::from_bytes(digest))
}

pub(super) fn write_string(buf: &mut Vec<u8>, value: &str) -> Result<(), StoreCodecError> {
    if value.len() > u16::MAX as usize {
        return Err(StoreCodecError::Oversized {
            field: "string",
            max: u16::MAX as usize,
            actual: value.len(),
        });
    }
    write_len_prefixed(buf, value.as_bytes());
    Ok(())
}

pub(super) fn read_string(
    bytes: &[u8],
    pos: &mut usize,
    context: &'static str,
) -> Result<String, StoreCodecError> {
    String::from_utf8(read_len_prefixed(bytes, pos)?.to_vec())
        .map_err(|_| StoreCodecError::UnknownTag { tag: 0, context })
}

pub(super) fn write_u32_vec(buf: &mut Vec<u8>, values: &[u32]) -> Result<(), StoreCodecError> {
    if values.len() > u16::MAX as usize {
        return Err(StoreCodecError::Oversized {
            field: "u32 vector",
            max: u16::MAX as usize,
            actual: values.len(),
        });
    }
    write_u16_be(buf, values.len() as u16);
    for value in values {
        buf.extend_from_slice(&value.to_be_bytes());
    }
    Ok(())
}

pub(super) fn read_u32_vec(bytes: &[u8], pos: &mut usize) -> Result<Vec<u32>, StoreCodecError> {
    let len = read_u16_be(bytes, pos)? as usize;
    let byte_len = len.checked_mul(4).ok_or(StoreCodecError::Oversized {
        field: "u32 vector",
        max: u16::MAX as usize,
        actual: len,
    })?;
    if *pos + byte_len > bytes.len() {
        return Err(StoreCodecError::Truncated);
    }
    let mut values = Vec::with_capacity(len);
    for _ in 0..len {
        let value = u32::from_be_bytes(
            bytes[*pos..*pos + 4]
                .try_into()
                .map_err(|_| StoreCodecError::Truncated)?,
        );
        *pos += 4;
        values.push(value);
    }
    Ok(values)
}

// ── TaskRunEvent codec ───────────────────────────────────────────────────

/// Event tag constants for TaskRunEvent encoding.
pub(super) const TAG_TASK_RUN_CREATED: u8 = 0x01;
pub(super) const TAG_TASK_RUN_QUEUED: u8 = 0x02;
pub(super) const TAG_TASK_RUN_ADMITTED: u8 = 0x03;
pub(super) const TAG_ATTEMPT_STARTED: u8 = 0x04;
pub(super) const TAG_WAIT_STARTED: u8 = 0x05;
pub(super) const TAG_RESUMED: u8 = 0x06;
pub(super) const TAG_RETRY_STARTED: u8 = 0x07;
pub(super) const TAG_RETRY_COMPLETED: u8 = 0x08;
pub(super) const TAG_CHECKPOINT_STARTED: u8 = 0x09;
pub(super) const TAG_CHECKPOINT_COMMITTED: u8 = 0x0A;
pub(super) const TAG_CANCELLATION_REQUESTED: u8 = 0x0B;
pub(super) const TAG_CANCELLATION_COMPLETED: u8 = 0x0C;
pub(super) const TAG_TASK_RUN_COMPLETED: u8 = 0x0D;
pub(super) const TAG_TASK_RUN_FAILED: u8 = 0x0E;
pub(super) const TAG_BUDGET_EXHAUSTED: u8 = 0x0F;
pub(super) const TAG_POLICY_DENIED: u8 = 0x10;
pub(super) const TAG_RECONCILIATION_STARTED: u8 = 0x11;
pub(super) const TAG_RECONCILED: u8 = 0x12;
pub(super) const TAG_UNRECOVERABLE: u8 = 0x13;
pub(super) const TAG_USER_SUPERSEDE_UNKNOWN: u8 = 0x30;
pub(super) const TAG_TASK_RUN_CANCELLED: u8 = 0x14;
pub(super) const TAG_LOOP_CYCLE_STARTED: u8 = 0x15;
pub(super) const TAG_CONTEXT_COMMITTED: u8 = 0x16;
pub(super) const TAG_PLAN_COMMITTED: u8 = 0x17;
pub(super) const TAG_STEP_OUTCOME_RECORDED: u8 = 0x18;
pub(super) const TAG_LOOP_CYCLE_COMPLETED: u8 = 0x19;
pub(super) const TAG_NEXT_CYCLE_CREATED: u8 = 0x1A;
pub(super) const TAG_RETRY_SCHEDULED: u8 = 0x1B;
pub(super) const TAG_LOOP_CHECKPOINT_RECORDED: u8 = 0x1C;
pub(super) const TAG_ACTIVATE_SCHEDULED_RETRY_ATTEMPT: u8 = 0x1D;
pub(super) const TAG_RECOVERY_RESUME_STARTED: u8 = 0x1E;
pub(super) const TAG_LOOP_CHECKPOINT_STARTED: u8 = 0x1F;
pub(super) const TAG_LOOP_CHECKPOINT_COMMITTED: u8 = 0x20;
pub(super) const TAG_LOOP_WAKE_ACCEPTED: u8 = 0x21;

pub(super) fn parse_codec_uuid<T>(
    bytes: [u8; 16],
    context: &'static str,
) -> Result<T, StoreCodecError>
where
    T: FromStr<Err = runne_domain::id::InvalidIdReason>,
    T: FromUuidBytes,
{
    let value = T::from_uuid_bytes(bytes);
    value
        .to_string()
        .parse::<T>()
        .map_err(|_| StoreCodecError::UnknownTag { tag: 0, context })
}

pub(super) trait FromUuidBytes: Sized + core::fmt::Display {
    fn from_uuid_bytes(bytes: [u8; 16]) -> Self;
}

impl FromUuidBytes for MessageId {
    fn from_uuid_bytes(bytes: [u8; 16]) -> Self {
        Self::from_bytes(bytes)
    }
}

impl FromUuidBytes for ConversationId {
    fn from_uuid_bytes(bytes: [u8; 16]) -> Self {
        Self::from_bytes(bytes)
    }
}

impl FromUuidBytes for TaskRunId {
    fn from_uuid_bytes(bytes: [u8; 16]) -> Self {
        Self::from_bytes(bytes)
    }
}

impl FromUuidBytes for AttemptId {
    fn from_uuid_bytes(bytes: [u8; 16]) -> Self {
        Self::from_bytes(bytes)
    }
}
