use std::sync::mpsc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use gtk::prelude::{ContainerExt, DialogExt, GtkWindowExt, LabelExt, WidgetExt};
use runne_api::{
    PermissionControlContextV1, PermissionControlModeChallengeV1, PermissionModeSelectionV1,
};

#[path = "native_warning_text.rs"]
mod native_warning_text;
pub(super) use native_warning_text::warning_message;

use super::{LinuxReauthenticationError, native_confirmation_binding_digest};

/// Opaque, move-only native acknowledgement. It has no public constructor or clone operation.
///
/// ```compile_fail
/// use runne_platform_desktop::permission_reauth_linux::NativePermissionWarningConfirmationV1;
/// let _ = NativePermissionWarningConfirmationV1 { challenge_id: [0; 16] };
/// ```
///
/// ```compile_fail
/// use runne_platform_desktop::permission_reauth_linux::NativePermissionWarningConfirmationV1;
/// fn clone_token(value: NativePermissionWarningConfirmationV1) { let _ = value.clone(); }
/// ```
pub struct NativePermissionWarningConfirmationV1 {
    challenge_id: [u8; 16],
    confirmed_binding_digest: [u8; 32],
    warning_version: u16,
    requested_mode: PermissionModeSelectionV1,
    confirmed_at_unix_ms: u64,
}

impl NativePermissionWarningConfirmationV1 {
    pub(crate) fn matches_exchange(
        &self,
        context: &PermissionControlContextV1,
        challenge: &PermissionControlModeChallengeV1,
        binding_digest: [u8; 32],
        now_unix_ms: u64,
    ) -> bool {
        self.challenge_id == challenge.challenge_id
            && self.confirmed_binding_digest == binding_digest
            && self.warning_version == challenge.native_warning_version
            && self.requested_mode == challenge.requested_mode
            && self.confirmed_at_unix_ms >= context.issued_at_unix_ms
            && self.confirmed_at_unix_ms < challenge.ceremony_expires_at_unix_ms
            && now_unix_ms < challenge.ceremony_expires_at_unix_ms
    }
}

/// A platform-created UI task. Bridges can only run it on the native UI thread or cancel it.
pub struct NativePermissionWarningUiTask(
    Option<Box<dyn FnOnce(Option<gtk::ApplicationWindow>) + Send>>,
);

impl NativePermissionWarningUiTask {
    pub(super) fn new(task: impl FnOnce(Option<gtk::ApplicationWindow>) + Send + 'static) -> Self {
        Self(Some(Box::new(task)))
    }

    pub fn run(mut self, parent: gtk::ApplicationWindow) {
        if let Some(task) = self.0.take() {
            task(Some(parent));
        }
    }

    pub fn cancel(mut self) {
        if let Some(task) = self.0.take() {
            task(None);
        }
    }
}

/// Scheduling-only bridge to the existing native GTK main thread.
pub trait NativePermissionWarningMainThreadScheduler: Send + Sync {
    /// Schedules the warning task on the native UI thread.
    ///
    /// # Errors
    /// Returns an opaque error when the UI thread cannot accept the task.
    #[expect(
        clippy::result_unit_err,
        reason = "Scheduling failures are intentionally opaque at this native UI boundary."
    )]
    fn schedule(&self, task: NativePermissionWarningUiTask) -> Result<(), ()>;
}

/// Presents the platform-owned warning closure and returns only a real GTK Continue token.
///
/// # Errors
/// Returns an error when the binding is invalid, the ceremony expires, or the warning is rejected.
pub fn request_native_permission_warning(
    challenge: &PermissionControlModeChallengeV1,
    context: &PermissionControlContextV1,
    scheduler: &dyn NativePermissionWarningMainThreadScheduler,
) -> Result<NativePermissionWarningConfirmationV1, LinuxReauthenticationError> {
    if gtk::is_initialized_main_thread() {
        return Err(LinuxReauthenticationError::NativeWarningRejected);
    }
    let now = unix_millis().ok_or(LinuxReauthenticationError::Expired)?;
    let expires = challenge.ceremony_expires_at_unix_ms;
    if now >= expires {
        return Err(LinuxReauthenticationError::Expired);
    }
    let digest = native_confirmation_binding_digest(context, challenge)
        .map_err(|()| LinuxReauthenticationError::InvalidBinding)?;
    let (sender, receiver) = mpsc::sync_channel(1);
    let challenge = challenge.clone();
    let context = context.clone();
    let task = NativePermissionWarningUiTask::new(move |parent| {
        let Some(parent) = parent else {
            let _ = sender.send(Err(()));
            return;
        };
        if present_warning(&parent, &challenge, &context, digest, sender.clone()).is_err() {
            let _ = sender.send(Err(()));
        }
    });
    scheduler
        .schedule(task)
        .map_err(|()| LinuxReauthenticationError::NativeWarningRejected)?;
    let timeout = Duration::from_millis(expires.saturating_sub(now));
    match receiver.recv_timeout(timeout) {
        Ok(Ok(token)) if unix_millis().is_some_and(|current| current < expires) => Ok(token),
        Ok(Ok(_)) | Err(mpsc::RecvTimeoutError::Timeout) => {
            Err(LinuxReauthenticationError::Expired)
        }
        Ok(Err(())) => Err(LinuxReauthenticationError::NativeWarningRejected),
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            Err(LinuxReauthenticationError::NativeWarningRejected)
        }
    }
}

fn present_warning(
    parent: &gtk::ApplicationWindow,
    challenge: &PermissionControlModeChallengeV1,
    context: &PermissionControlContextV1,
    digest: [u8; 32],
    sender: mpsc::SyncSender<Result<NativePermissionWarningConfirmationV1, ()>>,
) -> Result<(), ()> {
    if !gtk::is_initialized_main_thread()
        || !parent.is_visible()
        || unix_millis().ok_or(())? >= challenge.ceremony_expires_at_unix_ms
    {
        return Err(());
    }
    let message = warning_message(challenge);
    let dialog = gtk::Dialog::with_buttons(
        Some("Confirm permission mode"),
        Some(parent),
        gtk::DialogFlags::MODAL | gtk::DialogFlags::DESTROY_WITH_PARENT,
        &[
            ("Cancel", gtk::ResponseType::Cancel),
            ("Continue", gtk::ResponseType::Accept),
        ],
    );
    dialog.set_resizable(false);
    let label = gtk::Label::new(Some(&message));
    label.set_line_wrap(true);
    label.set_max_width_chars(64);
    label.set_margin_top(16);
    label.set_margin_bottom(16);
    label.set_margin_start(16);
    label.set_margin_end(16);
    dialog.content_area().add(&label);
    label.set_use_markup(false);
    let captured = challenge.clone();
    let captured_context = context.clone();
    let completed = std::rc::Rc::new(std::cell::Cell::new(false));
    let response_completed = std::rc::Rc::clone(&completed);
    let response_sender = sender.clone();
    dialog.connect_response(move |dialog, response| {
        if response_completed.replace(true) {
            dialog.hide();
            return;
        }
        let result = confirmation_for_response(
            response,
            &captured,
            &captured_context,
            digest,
            unix_millis(),
        );
        let _ = response_sender.try_send(result.ok_or(()));
        dialog.hide();
    });
    let destroyed_completed = std::rc::Rc::clone(&completed);
    let destroyed_sender = sender;
    dialog.connect_destroy(move |_| {
        if !destroyed_completed.replace(true) {
            let _ = destroyed_sender.try_send(Err(()));
        }
    });
    dialog.connect_delete_event(|dialog, _| {
        dialog.response(gtk::ResponseType::Cancel);
        gtk::glib::Propagation::Stop
    });
    let timer_completed = std::rc::Rc::clone(&completed);
    let timer_dialog = dialog.clone();
    let timer_parent = parent.clone();
    let expires = challenge.ceremony_expires_at_unix_ms;
    gtk::glib::timeout_add_local(Duration::from_millis(50), move || {
        if timer_completed.get() {
            gtk::glib::ControlFlow::Break
        } else if !timer_parent.is_visible() || unix_millis().is_none_or(|now| now >= expires) {
            timer_dialog.response(gtk::ResponseType::Cancel);
            gtk::glib::ControlFlow::Break
        } else {
            gtk::glib::ControlFlow::Continue
        }
    });
    dialog.show_all();
    Ok(())
}

fn confirmation_for_response(
    response: gtk::ResponseType,
    challenge: &PermissionControlModeChallengeV1,
    context: &PermissionControlContextV1,
    digest: [u8; 32],
    now: Option<u64>,
) -> Option<NativePermissionWarningConfirmationV1> {
    let confirmed_at_unix_ms = now?;
    if response != gtk::ResponseType::Accept
        || confirmed_at_unix_ms < context.issued_at_unix_ms
        || confirmed_at_unix_ms >= challenge.ceremony_expires_at_unix_ms
    {
        return None;
    }
    Some(NativePermissionWarningConfirmationV1 {
        challenge_id: challenge.challenge_id,
        confirmed_binding_digest: digest,
        warning_version: challenge.native_warning_version,
        requested_mode: challenge.requested_mode,
        confirmed_at_unix_ms,
    })
}

#[cfg(feature = "test-support")]
#[doc(hidden)]
#[expect(
    clippy::redundant_pub_crate,
    reason = "The test helper is reachable only through the private warning module."
)]
pub(crate) fn mock_native_permission_warning_confirmation(
    challenge: &PermissionControlModeChallengeV1,
    context: &PermissionControlContextV1,
) -> Result<NativePermissionWarningConfirmationV1, LinuxReauthenticationError> {
    let now = unix_millis().ok_or(LinuxReauthenticationError::Expired)?;
    let digest = native_confirmation_binding_digest(context, challenge)
        .map_err(|()| LinuxReauthenticationError::InvalidBinding)?;
    confirmation_for_response(
        gtk::ResponseType::Accept,
        challenge,
        context,
        digest,
        Some(now),
    )
    .ok_or(LinuxReauthenticationError::Expired)
}

fn unix_millis() -> Option<u64> {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()?
            .as_millis(),
    )
    .ok()
}

#[cfg(test)]
#[path = "native_consent_tests.rs"]
mod tests;
