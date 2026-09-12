use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use runne_macos_xpc::{QualificationRunnerXpcClient, QualificationRunnerXpcListener};
use runne_platform_desktop::{ProfileLock, VerifiedInstalledQualificationGuiExecutor};

use crate::coordinator::RunCoordinator;
use crate::root_bridge::RootBridge;

mod sessions;

#[derive(Clone, Copy, Debug)]
pub struct Error;
pub type Result<T> = std::result::Result<T, Error>;

const ROOT_PREPARE_LIMIT: Duration = Duration::from_mins(15);

pub fn run() -> Result<()> {
    let profile_directory = profile_directory()?;
    let lock_path = profile_directory
        .parent()
        .ok_or(Error)?
        .join("profile.lock");
    drop(ProfileLock::acquire(&lock_path).map_err(|_| Error)?);

    let admission = VerifiedInstalledQualificationGuiExecutor::admit_current_for_gui_executor(
        &profile_directory,
    )
    .ok_or(Error)?;
    let (admission, root_configuration) = admission.root_consume_configuration().ok_or(Error)?;
    let (admission, desktop_configuration) =
        admission.desktop_bootstrap_configuration().ok_or(Error)?;
    let (admission, runtime_configuration) =
        admission.runtime_bootstrap_configuration().ok_or(Error)?;

    let root_client = QualificationRunnerXpcClient::connect_root_consume(&root_configuration)
        .map_err(|_| Error)?;
    let root_bridge = Arc::new(RootBridge::start(root_client).ok_or(Error)?);
    let prepare_deadline = Instant::now()
        .checked_add(ROOT_PREPARE_LIMIT)
        .ok_or(Error)?;
    let prepared = root_bridge.prepare(prepare_deadline).map_err(|_| Error)?;
    let deadline = deadline_from_unix(prepared.expires_at())?.min(prepare_deadline);
    require_launch_window(deadline)?;
    let admission = admission
        .confirm_bootstrap_binding(prepared.binding())
        .ok_or(Error)?;

    let coordinator = Arc::new(RunCoordinator::new(prepared, deadline));
    let mut opening = OpeningGuard::new(Arc::clone(&coordinator));
    let admission_slot = Arc::new(AdmissionSlot::empty());
    let desktop_listener = QualificationRunnerXpcListener::bind(
        &desktop_configuration,
        Arc::new(sessions::DesktopFactory::new(
            Arc::clone(&coordinator),
            Arc::clone(&admission_slot),
        )),
    )
    .map_err(|_| Error)?;
    let runtime_listener = QualificationRunnerXpcListener::bind(
        &runtime_configuration,
        Arc::new(sessions::RuntimeFactory::new(
            Arc::clone(&coordinator),
            root_bridge,
            Arc::clone(&admission_slot),
        )),
    )
    .map_err(|_| Error)?;

    require_launch_window(deadline)?;
    let admission = admission.open_installed_application().ok_or(Error)?;
    admission_slot.install(admission)?;
    opening.opened()?;
    coordinator.wait_until_deadline_or_terminal();
    desktop_listener.invalidate();
    runtime_listener.invalidate();
    Err(Error)
}

pub struct AdmissionSlot(Mutex<Option<VerifiedInstalledQualificationGuiExecutor>>);

impl AdmissionSlot {
    const fn empty() -> Self {
        Self(Mutex::new(None))
    }

    fn install(&self, admission: VerifiedInstalledQualificationGuiExecutor) -> Result<()> {
        let mut slot = self.0.lock().map_err(|_| Error)?;
        slot.is_none().then_some(()).ok_or(Error)?;
        *slot = Some(admission);
        drop(slot);
        Ok(())
    }

    pub(super) fn refresh(&self) -> Result<()> {
        let admission = self.0.lock().map_err(|_| Error)?.take().ok_or(Error)?;
        let admission = admission.revalidate().ok_or(Error)?;
        let mut slot = self.0.lock().map_err(|_| Error)?;
        slot.is_none().then_some(()).ok_or(Error)?;
        *slot = Some(admission);
        drop(slot);
        Ok(())
    }
}

fn profile_directory() -> Result<PathBuf> {
    runne_macos_xpc::current_login_account_home()
        .map(|home| {
            home.join("Library")
                .join("Application Support")
                .join("com.runne.desktop")
                .join("bundled-runtime")
        })
        .map_err(|_| Error)
}

fn deadline_from_unix(expires_at: u64) -> Result<Instant> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Error)?
        .as_secs();
    let remaining = expires_at
        .checked_sub(now)
        .filter(|value| *value > 0)
        .ok_or(Error)?;
    Instant::now()
        .checked_add(Duration::from_secs(remaining))
        .ok_or(Error)
}

fn require_launch_window(deadline: Instant) -> Result<()> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|remaining| *remaining > Duration::from_secs(10))
        .map(|_| ())
        .ok_or(Error)
}

struct OpeningGuard {
    coordinator: Arc<RunCoordinator>,
    opened: bool,
}

impl OpeningGuard {
    const fn new(coordinator: Arc<RunCoordinator>) -> Self {
        Self {
            coordinator,
            opened: false,
        }
    }

    fn opened(&mut self) -> Result<()> {
        self.coordinator.opened().map_err(|_| Error)?;
        self.opened = true;
        Ok(())
    }
}

impl Drop for OpeningGuard {
    fn drop(&mut self) {
        if !self.opened {
            self.coordinator.fail();
        }
    }
}
