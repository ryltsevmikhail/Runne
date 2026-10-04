use super::TaskRunSnapshotError;
use crate::id::{IntegrityDigest, validate_uuid_v7_bytes};

pub(super) const MAX_BYTES: usize = 512 * 1024;
pub(super) const MAX_STRING: usize = MAX_BYTES;
pub(super) const MAX_ITEMS: usize = 65_536;

pub(super) struct Out {
    bytes: Vec<u8>,
    overflowed: bool,
    invalid_id: bool,
}
impl Out {
    pub(super) fn new() -> Self {
        Self {
            bytes: Vec::new(),
            overflowed: false,
            invalid_id: false,
        }
    }
    pub(super) fn finish(self) -> Result<Vec<u8>, TaskRunSnapshotError> {
        if self.overflowed || self.invalid_id {
            return Err(TaskRunSnapshotError::InvalidEncoding);
        }
        Ok(self.bytes)
    }
    pub(super) fn u8(&mut self, value: u8) {
        self.push(&[value]);
    }
    pub(super) fn u32(&mut self, value: u32) {
        self.push(&value.to_be_bytes());
    }
    pub(super) fn u64(&mut self, value: u64) {
        self.push(&value.to_be_bytes());
    }
    pub(super) fn i64(&mut self, value: i64) {
        self.push(&value.to_be_bytes());
    }
    pub(super) fn id(&mut self, value: &[u8; 16]) {
        if validate_uuid_v7_bytes(value).is_err() {
            self.invalid_id = true;
            return;
        }
        self.push(value);
    }
    pub(super) fn digest(&mut self, value: IntegrityDigest) {
        self.push(value.as_bytes());
    }
    pub(super) fn fixed32(&mut self, value: &[u8; 32]) {
        self.push(value);
    }
    pub(super) fn string(&mut self, value: &str) -> Result<(), TaskRunSnapshotError> {
        validate_string(value)?;
        self.u32(u32::try_from(value.len()).map_err(|_| TaskRunSnapshotError::InvalidEncoding)?);
        self.push(value.as_bytes());
        Ok(())
    }
    pub(super) fn len(&mut self, value: usize) -> Result<(), TaskRunSnapshotError> {
        if value > MAX_ITEMS {
            return Err(TaskRunSnapshotError::InvalidEncoding);
        }
        self.u32(u32::try_from(value).map_err(|_| TaskRunSnapshotError::InvalidEncoding)?);
        Ok(())
    }
    fn push(&mut self, value: &[u8]) {
        if self.overflowed
            || self
                .bytes
                .len()
                .checked_add(value.len())
                .is_none_or(|length| length > MAX_BYTES)
        {
            self.overflowed = true;
            return;
        }
        self.bytes.extend_from_slice(value);
    }
}

pub(super) struct In<'a> {
    bytes: &'a [u8],
    offset: usize,
}
impl<'a> In<'a> {
    pub(super) fn new(bytes: &'a [u8]) -> Result<Self, TaskRunSnapshotError> {
        if bytes.len() > MAX_BYTES {
            return Err(TaskRunSnapshotError::InvalidEncoding);
        }
        Ok(Self { bytes, offset: 0 })
    }
    pub(super) fn done(&self) -> bool {
        self.offset == self.bytes.len()
    }
    pub(super) fn u8(&mut self) -> Result<u8, TaskRunSnapshotError> {
        Ok(*self
            .take(1)?
            .first()
            .ok_or(TaskRunSnapshotError::InvalidEncoding)?)
    }
    pub(super) fn u32(&mut self) -> Result<u32, TaskRunSnapshotError> {
        Ok(u32::from_be_bytes(
            self.take(4)?
                .try_into()
                .map_err(|_| TaskRunSnapshotError::InvalidEncoding)?,
        ))
    }
    pub(super) fn u64(&mut self) -> Result<u64, TaskRunSnapshotError> {
        Ok(u64::from_be_bytes(
            self.take(8)?
                .try_into()
                .map_err(|_| TaskRunSnapshotError::InvalidEncoding)?,
        ))
    }
    pub(super) fn i64(&mut self) -> Result<i64, TaskRunSnapshotError> {
        Ok(i64::from_be_bytes(
            self.take(8)?
                .try_into()
                .map_err(|_| TaskRunSnapshotError::InvalidEncoding)?,
        ))
    }
    pub(super) fn id(&mut self) -> Result<[u8; 16], TaskRunSnapshotError> {
        let value: [u8; 16] = self
            .take(16)?
            .try_into()
            .map_err(|_| TaskRunSnapshotError::InvalidEncoding)?;
        validate_uuid_v7_bytes(&value).map_err(|_| TaskRunSnapshotError::InvalidEncoding)?;
        Ok(value)
    }
    pub(super) fn digest(&mut self) -> Result<IntegrityDigest, TaskRunSnapshotError> {
        Ok(IntegrityDigest::from_bytes(
            self.take(32)?
                .try_into()
                .map_err(|_| TaskRunSnapshotError::InvalidEncoding)?,
        ))
    }
    pub(super) fn fixed32(&mut self) -> Result<[u8; 32], TaskRunSnapshotError> {
        self.take(32)?
            .try_into()
            .map_err(|_| TaskRunSnapshotError::InvalidEncoding)
    }
    pub(super) fn string(&mut self) -> Result<String, TaskRunSnapshotError> {
        let length =
            usize::try_from(self.u32()?).map_err(|_| TaskRunSnapshotError::InvalidEncoding)?;
        if length > MAX_STRING {
            return Err(TaskRunSnapshotError::InvalidEncoding);
        }
        let value = String::from_utf8(self.take(length)?.to_vec())
            .map_err(|_| TaskRunSnapshotError::InvalidEncoding)?;
        validate_string(&value)?;
        Ok(value)
    }
    pub(super) fn len(&mut self) -> Result<usize, TaskRunSnapshotError> {
        let value =
            usize::try_from(self.u32()?).map_err(|_| TaskRunSnapshotError::InvalidEncoding)?;
        if value > MAX_ITEMS {
            return Err(TaskRunSnapshotError::InvalidEncoding);
        }
        Ok(value)
    }
    fn take(&mut self, length: usize) -> Result<&'a [u8], TaskRunSnapshotError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(TaskRunSnapshotError::InvalidEncoding)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(TaskRunSnapshotError::InvalidEncoding)?;
        self.offset = end;
        Ok(value)
    }
}

pub(super) fn validate_string(value: &str) -> Result<(), TaskRunSnapshotError> {
    if value.len() > MAX_STRING {
        return Err(TaskRunSnapshotError::InvalidEncoding);
    }
    Ok(())
}
