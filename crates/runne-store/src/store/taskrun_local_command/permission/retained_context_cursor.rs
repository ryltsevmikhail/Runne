use super::retained_context::ContextErrorV1;
use ContextErrorV1::MalformedWire;

pub(super) struct Cursor<'a> {
    bytes: &'a [u8],
    position: usize,
}
impl<'a> Cursor<'a> {
    pub(super) fn new(bytes: &'a [u8]) -> Result<Self, ContextErrorV1> {
        if bytes.is_empty() || bytes.len() > 1048576 {
            return Err(MalformedWire);
        }
        Ok(Self { bytes, position: 0 })
    }
    pub(super) fn take(&mut self, length: usize) -> Result<&'a [u8], ContextErrorV1> {
        let end = self.position.checked_add(length).ok_or(MalformedWire)?;
        let result = self.bytes.get(self.position..end).ok_or(MalformedWire)?;
        self.position = end;
        Ok(result)
    }
    pub(super) fn array<const N: usize>(&mut self) -> Result<[u8; N], ContextErrorV1> {
        self.take(N)?.try_into().map_err(|_| MalformedWire)
    }
    pub(super) fn u8(&mut self) -> Result<u8, ContextErrorV1> {
        Ok(self.array::<1>()?[0])
    }
    pub(super) fn u16(&mut self) -> Result<u16, ContextErrorV1> {
        Ok(u16::from_be_bytes(self.array()?))
    }
    pub(super) fn u32(&mut self) -> Result<u32, ContextErrorV1> {
        Ok(u32::from_be_bytes(self.array()?))
    }
    pub(super) fn u64(&mut self) -> Result<u64, ContextErrorV1> {
        Ok(u64::from_be_bytes(self.array()?))
    }
    pub(super) fn i64(&mut self) -> Result<i64, ContextErrorV1> {
        Ok(i64::from_be_bytes(self.array()?))
    }
    pub(super) fn option(&mut self) -> Result<Option<u64>, ContextErrorV1> {
        match self.u8()? {
            0 => Ok(None),
            1 => Ok(Some(self.u64()?)),
            _ => Err(MalformedWire),
        }
    }
    pub(super) fn finished(&self) -> bool {
        self.position == self.bytes.len()
    }
}
pub(super) fn put_option(out: &mut Vec<u8>, value: Option<u64>) {
    match value {
        None => out.push(0),
        Some(value) => {
            out.push(1);
            out.extend(value.to_be_bytes());
        }
    }
}
