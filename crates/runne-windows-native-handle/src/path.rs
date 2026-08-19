use std::ffi::{OsStr, OsString};
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};

use crate::identity::NativeHandleError;

const MAX_UTF16_UNITS: usize = 32_767;

pub struct ValidatedWindowsPath {
    anchor: PathBuf,
    components: Vec<OsString>,
}

impl ValidatedWindowsPath {
    pub(crate) fn absolute(path: &Path) -> Result<Self, NativeHandleError> {
        let raw = validated_units(path.as_os_str())?;
        if raw.len() < 3
            || !is_ascii_letter(raw[0])
            || raw[1] != u16::from(b':')
            || raw[2] != u16::from(b'\\')
        {
            return Err(NativeHandleError::Rejected);
        }
        let mut anchor = OsString::from_wide(&raw[..2]);
        anchor.push("\\");
        Ok(Self {
            anchor: PathBuf::from(anchor),
            components: parse_components(&raw[3..])?,
        })
    }

    pub(crate) fn relative(path: &Path) -> Result<Vec<OsString>, NativeHandleError> {
        let raw = validated_units(path.as_os_str())?;
        (!raw.is_empty())
            .then_some(parse_components(&raw))
            .ok_or(NativeHandleError::Rejected)?
    }

    pub(crate) fn anchor(&self) -> &Path {
        &self.anchor
    }

    pub(crate) fn components(&self) -> impl Iterator<Item = &OsStr> {
        self.components.iter().map(OsString::as_os_str)
    }
}

fn validated_units(value: &OsStr) -> Result<Vec<u16>, NativeHandleError> {
    let raw = value.encode_wide().collect::<Vec<_>>();
    if raw.len() > MAX_UTF16_UNITS
        || raw.contains(&0)
        || raw.iter().any(|unit| *unit == u16::from(b'/'))
        || reject_raw_windows_grammar(&raw)
    {
        return Err(NativeHandleError::Rejected);
    }
    Ok(raw)
}

fn reject_raw_windows_grammar(raw: &[u16]) -> bool {
    raw.starts_with(&[
        u16::from(b'\\'),
        u16::from(b'\\'),
        u16::from(b'?'),
        u16::from(b'\\'),
    ]) || raw.starts_with(&[
        u16::from(b'\\'),
        u16::from(b'\\'),
        u16::from(b'.'),
        u16::from(b'\\'),
    ]) || raw.starts_with(&[
        u16::from(b'\\'),
        u16::from(b'?'),
        u16::from(b'?'),
        u16::from(b'\\'),
    ]) || raw.starts_with(&[u16::from(b'\\'), u16::from(b'\\')])
}

fn is_ascii_letter(unit: u16) -> bool {
    (u16::from(b'A')..=u16::from(b'Z')).contains(&unit)
        || (u16::from(b'a')..=u16::from(b'z')).contains(&unit)
}

fn parse_components(raw: &[u16]) -> Result<Vec<OsString>, NativeHandleError> {
    if raw.is_empty() {
        return Ok(Vec::new());
    }
    raw.split(|unit| *unit == u16::from(b'\\'))
        .map(validate_component)
        .collect()
}

fn validate_component(component: &[u16]) -> Result<OsString, NativeHandleError> {
    if component.is_empty()
        || component == [u16::from(b'.')]
        || component == [u16::from(b'.'), u16::from(b'.')]
        || component.iter().any(|unit| *unit == u16::from(b':'))
    {
        return Err(NativeHandleError::Rejected);
    }
    Ok(OsString::from_wide(component))
}
