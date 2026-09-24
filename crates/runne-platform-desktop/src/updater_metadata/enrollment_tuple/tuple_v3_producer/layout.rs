use std::fs::File;
use std::path::{Path, PathBuf};

#[cfg(unix)]
use rustix::fs::{FileType, fstat};

use runne_api::{
    NativeEnrollmentTupleError, NativeEnrollmentTupleV3CodeIdentities, UpdateTargetV2,
};

use super::super::enrollment_measurement::OpenedNativeEnrollmentFile;
#[cfg(unix)]
use super::super::enrollment_paths::{open_absolute_directory, open_rooted_file, same_directory};
use super::resources::{ValidatedTupleV3Resources, validate_resources};
use super::{CodeIdentityObserver, code_identities};

const DESKTOP: &[&str] = &["Contents", "MacOS", "runne-desktop"];
const WRITER: &[&str] = &["Contents", "MacOS", "runne"];
const DAEMON: &[&str] = &["Contents", "MacOS", "runned"];
const SERVICE: &[&str] = &[
    "Contents",
    "Library",
    "Helpers",
    "RunneCredentialService.app",
    "Contents",
    "MacOS",
    "runne-credential-service",
];
const LAUNCH_AGENT: &[&str] = &[
    "Contents",
    "Library",
    "LaunchAgents",
    "com.runne.credential-service.plist",
];
const ENTITLEMENTS: &[&str] = &[
    "Contents",
    "Resources",
    "native-enrollment",
    "credential-service.entitlements.plist",
];
const PROVISIONING: &[&str] = &[
    "Contents",
    "Library",
    "Helpers",
    "RunneCredentialService.app",
    "Contents",
    "embedded.provisionprofile",
];
const XPC_PROTOCOL: &[&str] = &[
    "Contents",
    "Resources",
    "native-enrollment",
    "xpc-protocol-v1.json",
];
const CONTRACT: &[&str] = &[
    "Contents",
    "Resources",
    "contracts",
    "gocode-ui-client-3",
    "bundle.json",
];
const CANDIDATE: &[&str] = &[
    "Contents",
    "Resources",
    "native-enrollment",
    "release-candidate-binding.json",
];

pub(super) struct MeasuredTupleV3Artifacts {
    pub(super) desktop: String,
    pub(super) writer: String,
    pub(super) daemon: String,
    pub(super) credential_service: String,
    pub(super) launch_agent: String,
    pub(super) entitlements: String,
    pub(super) provisioning: String,
    pub(super) xpc_protocol: String,
    pub(super) contract: String,
}

pub(super) struct StagedTupleV3Artifacts {
    application: PathBuf,
    #[cfg(unix)]
    root: File,
    files: [OpenedNativeEnrollmentFile; 10],
}

impl StagedTupleV3Artifacts {
    pub(super) fn capture(application: &Path) -> Result<Self, NativeEnrollmentTupleError> {
        if !application.is_absolute()
            || application
                .file_name()
                .is_none_or(|name| name != "Runne.app")
        {
            return Err(NativeEnrollmentTupleError::Rejected);
        }
        let metadata = std::fs::symlink_metadata(application)
            .map_err(|_| NativeEnrollmentTupleError::Rejected)?;
        if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
            return Err(NativeEnrollmentTupleError::Rejected);
        }
        let application =
            std::fs::canonicalize(application).map_err(|_| NativeEnrollmentTupleError::Rejected)?;
        #[cfg(unix)]
        {
            let root = open_absolute_directory(&application)?;
            let files = [
                open_artifact(&root, DESKTOP, true)?,
                open_artifact(&root, WRITER, true)?,
                open_artifact(&root, DAEMON, true)?,
                open_artifact(&root, SERVICE, true)?,
                open_artifact(&root, LAUNCH_AGENT, false)?,
                open_artifact(&root, ENTITLEMENTS, false)?,
                open_artifact(&root, PROVISIONING, false)?,
                open_artifact(&root, XPC_PROTOCOL, false)?,
                open_artifact(&root, CONTRACT, false)?,
                open_artifact(&root, CANDIDATE, false)?,
            ];
            Ok(Self {
                application,
                root,
                files,
            })
        }
        #[cfg(not(unix))]
        {
            Err(NativeEnrollmentTupleError::Rejected)
        }
    }

    pub(super) fn application_path(&self) -> &Path {
        &self.application
    }

    pub(super) fn validate_resources(
        &self,
        target: &UpdateTargetV2,
    ) -> Result<ValidatedTupleV3Resources, NativeEnrollmentTupleError> {
        validate_resources(
            &self.files[4],
            &self.files[5],
            &self.files[7],
            &self.files[9],
            target,
        )
    }

    pub(super) fn measure(&self) -> Result<MeasuredTupleV3Artifacts, NativeEnrollmentTupleError> {
        let measured = MeasuredTupleV3Artifacts {
            desktop: self.files[0].measure()?,
            writer: self.files[1].measure()?,
            daemon: self.files[2].measure()?,
            credential_service: self.files[3].measure()?,
            launch_agent: self.files[4].measure()?,
            entitlements: self.files[5].measure()?,
            provisioning: self.files[6].measure()?,
            xpc_protocol: self.files[7].measure()?,
            contract: self.files[8].measure()?,
        };
        self.confirm_current()?;
        Ok(measured)
    }

    pub(super) fn observe_identities(
        &self,
        observer: &impl CodeIdentityObserver,
    ) -> Result<NativeEnrollmentTupleV3CodeIdentities, NativeEnrollmentTupleError> {
        let paths = [DESKTOP, WRITER, DAEMON, SERVICE]
            .map(|components| rooted_path(&self.application, components));
        code_identities(observer, paths.each_ref().map(PathBuf::as_path))
    }

    pub(super) fn confirm_current(&self) -> Result<(), NativeEnrollmentTupleError> {
        #[cfg(unix)]
        {
            let root = open_absolute_directory(&self.application)?;
            if !same_directory(&self.root, &root) {
                return Err(NativeEnrollmentTupleError::Rejected);
            }
            all_paths()
                .into_iter()
                .enumerate()
                .try_for_each(|(index, path)| {
                    let current = open_rooted_file(&self.root, path)?;
                    self.files[index]
                        .matches_file(&current)?
                        .then_some(())
                        .ok_or(NativeEnrollmentTupleError::Rejected)
                })
        }
        #[cfg(not(unix))]
        {
            Err(NativeEnrollmentTupleError::Rejected)
        }
    }
}

const fn all_paths() -> [&'static [&'static str]; 10] {
    [
        DESKTOP,
        WRITER,
        DAEMON,
        SERVICE,
        LAUNCH_AGENT,
        ENTITLEMENTS,
        PROVISIONING,
        XPC_PROTOCOL,
        CONTRACT,
        CANDIDATE,
    ]
}

fn rooted_path(root: &Path, components: &[&str]) -> PathBuf {
    components
        .iter()
        .fold(root.to_path_buf(), |path, component| path.join(component))
}

#[cfg(unix)]
fn open_artifact(
    root: &File,
    path: &[&str],
    executable: bool,
) -> Result<OpenedNativeEnrollmentFile, NativeEnrollmentTupleError> {
    let file = open_rooted_file(root, path)?;
    let stat = fstat(&file).map_err(|_| NativeEnrollmentTupleError::Rejected)?;
    if !FileType::from_raw_mode(stat.st_mode).is_file() || (executable && stat.st_mode & 0o111 == 0)
    {
        return Err(NativeEnrollmentTupleError::Rejected);
    }
    OpenedNativeEnrollmentFile::new(file)
}
