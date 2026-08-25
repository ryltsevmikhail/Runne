//! Signed package format binding for native desktop updates.

#![allow(clippy::missing_errors_doc)]

use std::path::Path;

use thiserror::Error;

/// Signed package formats accepted by the native update backends.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UpdateArtifactKind {
    AppImage,
    Debian,
    MacDmg,
    WindowsNsis,
}

impl UpdateArtifactKind {
    /// Derives the package format from the signed HTTPS target URL.
    pub fn from_url(value: &str) -> Result<Self, UpdateArtifactKindError> {
        let url = reqwest::Url::parse(value).map_err(|_| UpdateArtifactKindError::InvalidUrl)?;
        let filename = url
            .path_segments()
            .and_then(|mut segments| segments.next_back())
            .filter(|value| !value.is_empty())
            .ok_or(UpdateArtifactKindError::InvalidUrl)?
            .to_ascii_lowercase();
        Self::from_filename(&filename)
    }

    /// Derives the package format from a native-owned staged path.
    pub fn from_path(path: &Path) -> Result<Self, UpdateArtifactKindError> {
        let filename = path
            .file_name()
            .and_then(|value| value.to_str())
            .ok_or(UpdateArtifactKindError::InvalidUrl)?
            .to_ascii_lowercase();
        Self::from_filename(&filename)
    }

    fn from_filename(filename: &str) -> Result<Self, UpdateArtifactKindError> {
        if has_extension(filename, "appimage") {
            Ok(Self::AppImage)
        } else if has_extension(filename, "deb") {
            Ok(Self::Debian)
        } else if has_extension(filename, "dmg") {
            Ok(Self::MacDmg)
        } else if has_extension(filename, "exe") {
            Ok(Self::WindowsNsis)
        } else {
            Err(UpdateArtifactKindError::Unsupported)
        }
    }

    /// Returns the canonical staging suffix used by the updater journal.
    #[must_use]
    pub const fn suffix(self) -> &'static str {
        match self {
            Self::AppImage => ".AppImage",
            Self::Debian => ".deb",
            Self::MacDmg => ".dmg",
            Self::WindowsNsis => ".exe",
        }
    }

    /// Checks that a signed package is valid for the target platform.
    #[must_use]
    pub fn supports_platform(self, platform: &str) -> bool {
        matches!(
            (self, platform),
            (Self::AppImage | Self::Debian, "linux")
                | (Self::MacDmg, "macos")
                | (Self::WindowsNsis, "windows")
        )
    }
}

fn has_extension(filename: &str, extension: &str) -> bool {
    Path::new(filename)
        .extension()
        .is_some_and(|value| value.eq_ignore_ascii_case(extension))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Error)]
pub enum UpdateArtifactKindError {
    #[error("update artifact URL is invalid")]
    InvalidUrl,
    #[error("update artifact format is unsupported")]
    Unsupported,
}
