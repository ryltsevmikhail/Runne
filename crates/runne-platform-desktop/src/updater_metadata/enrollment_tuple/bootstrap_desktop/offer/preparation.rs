use std::path::{Path, PathBuf};

use super::super::run_root::FreshQualificationRunRoot;
use super::VerifiedDesktopQualificationOffer;

/// Fresh qualification journal copy retained with its admitted desktop offer.
///
/// This preparation grants no runtime or credential authority. The daemon must
/// independently validate the candidate and obtain the root acknowledgement.
///
/// ```compile_fail
/// use runne_platform_desktop::PreparedDesktopQualificationRun;
/// let _ = PreparedDesktopQualificationRun {};
/// ```
///
/// ```compile_fail
/// use runne_platform_desktop::PreparedDesktopQualificationRun;
/// fn requires_clone<T: Clone>() {}
/// requires_clone::<PreparedDesktopQualificationRun>();
/// ```
///
/// ```compile_fail
/// use runne_platform_desktop::PreparedDesktopQualificationRun;
/// fn requires_wire<T: serde::Serialize>() {}
/// requires_wire::<PreparedDesktopQualificationRun>();
/// ```
pub struct PreparedDesktopQualificationRun {
    offer: VerifiedDesktopQualificationOffer,
    root: FreshQualificationRunRoot,
}

impl VerifiedDesktopQualificationOffer {
    /// Creates one fresh run root from the fixed OS-account profile's signed journals.
    /// Existing run directories are rejected; failures never reuse a prior run.
    #[must_use]
    pub fn prepare_run(self) -> Option<PreparedDesktopQualificationRun> {
        let offer = self.revalidate()?;
        confirm_account_profile(&offer.desktop.profile_directory)?;
        let root = FreshQualificationRunRoot::create(
            &offer.desktop.profile_directory,
            &offer.binding().qualification_directory_name(),
        )?;
        PreparedDesktopQualificationRun { offer, root }.revalidate()
    }
}

impl PreparedDesktopQualificationRun {
    /// Rechecks the exact retained root, both journal admissions, and live XPC peer.
    #[must_use]
    pub fn revalidate(self) -> Option<Self> {
        let Self { offer, root } = self;
        root.revalidate()?;
        let offer = offer.revalidate()?;
        confirm_account_profile(&offer.desktop.profile_directory)?;
        let policy = crate::updater_metadata::enrollment_daemon_installed::compiled_policy()?;
        let trust = crate::CompiledUpdateTrustRootV2::load()?.into_trust_root();
        crate::updater_metadata::enrollment_daemon_installed::refresh_retained_admission_at(
            root.path(),
            &offer.desktop.paths,
            &trust,
            &policy,
            &offer.desktop.admission,
            super::super::now()?,
        )?;
        root.revalidate()?;
        let offer = offer.revalidate()?;
        Some(Self { offer, root })
    }
}

fn confirm_account_profile(profile: &Path) -> Option<()> {
    let expected = account_profile()?;
    (profile == expected && std::fs::canonicalize(profile).ok()? == expected).then_some(())
}

fn account_profile() -> Option<PathBuf> {
    Some(
        runne_macos_xpc::current_login_account_home()
            .ok()?
            .join("Library/Application Support/com.runne.desktop/bundled-runtime"),
    )
}
