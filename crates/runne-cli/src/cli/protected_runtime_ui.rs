use super::{
    CliError, OutputFormat, ParsedPermissionsCommand, ProcessOutcome, parse_global_options,
    process_outcome, protected_runtime_owner,
};
use std::cell::{Cell, RefCell};
use std::ffi::OsString;
use std::rc::Rc;
use std::sync::{Arc, mpsc};
use std::time::Duration;

use gtk::prelude::*;
use runne_platform_desktop::permission_reauth_linux::{
    NativePermissionWarningMainThreadScheduler, NativePermissionWarningUiTask, PamCancellation,
    PamConversationHandler, PamInteractionError, PamMessageKind,
};
use zeroize::{Zeroize, Zeroizing};

#[path = "protected_runtime_seed.rs"]
mod protected_runtime_seed;

fn uses_main_thread_approval(arguments: &[OsString]) -> bool {
    parse_global_options(arguments.to_vec())
        .ok()
        .and_then(|state| protected_runtime_owner::parse_invocation(state).ok())
        .is_some_and(|(_, command)| {
            matches!(
                command.command,
                ParsedPermissionsCommand::ApprovalRespond(_)
            )
        })
}

pub fn run(arguments: Vec<OsString>) -> ProcessOutcome {
    if protected_runtime_seed::is_seed_only_invocation(&arguments) {
        return protected_runtime_seed::run(arguments);
    }
    run_permissions_ui(arguments)
}

fn run_permissions_ui(arguments: Vec<OsString>) -> ProcessOutcome {
    let state = match parse_global_options(arguments.clone()) {
        Ok(state) => state,
        Err(error) => return process_outcome(Err(error), OutputFormat::Text),
    };
    let format = state.format;
    let (_, command) = match protected_runtime_owner::parse_invocation(state) {
        Ok(command) => command,
        Err(error) => return process_outcome(Err(error), format),
    };
    if matches!(command.command, ParsedPermissionsCommand::Read(_)) {
        let (warning_sender, warning_receiver) = mpsc::channel();
        let (pam_sender, pam_receiver) = mpsc::channel();
        drop(warning_receiver);
        drop(pam_receiver);
        let scheduler: Arc<dyn NativePermissionWarningMainThreadScheduler> =
            Arc::new(GtkWarningScheduler(warning_sender));
        let pam: Arc<dyn PamConversationHandler> = Arc::new(GtkPamHandler(pam_sender));
        return protected_runtime_owner::run(arguments, scheduler, pam);
    }
    if gtk::init().is_err() {
        return process_outcome(Err(CliError::Runtime), format);
    }
    let application = gtk::Application::new(
        Some("com.runne.cli.protected-runtime"),
        gtk::gio::ApplicationFlags::NON_UNIQUE,
    );
    let completed = Rc::new(RefCell::new(None));
    let completed_outcome = Rc::clone(&completed);
    let input = Rc::new(RefCell::new(Some(arguments)));
    application.connect_activate(move |application| {
        let Some(arguments) = input.borrow_mut().take() else {
            return;
        };
        let parent = gtk::ApplicationWindow::new(application);
        parent.set_title("Runne protected runtime");
        parent.set_default_size(420, 120);
        parent.set_resizable(false);
        parent.set_position(gtk::WindowPosition::Center);
        parent.add(&gtk::Label::new(Some("Protected runtime operation")));
        parent.connect_delete_event(|_, _| gtk::glib::Propagation::Stop);
        parent.show_all();

        let (warning_sender, warning_receiver) = mpsc::channel();
        let (pam_sender, pam_receiver) = mpsc::channel();
        let (done_sender, done_receiver) = mpsc::channel();
        let scheduler: Arc<dyn NativePermissionWarningMainThreadScheduler> =
            Arc::new(GtkWarningScheduler(warning_sender));
        let pam: Arc<dyn PamConversationHandler> = Arc::new(GtkPamHandler(pam_sender));
        if uses_main_thread_approval(&arguments) {
            *completed_outcome.borrow_mut() =
                Some(protected_runtime_owner::run(arguments, scheduler, pam));
            let application = application.clone();
            gtk::glib::idle_add_local_once(move || application.quit());
            return;
        }
        let worker_scheduler = Arc::clone(&scheduler);
        let worker_pam = Arc::clone(&pam);
        if std::thread::Builder::new()
            .name("runne-protected-cli".into())
            .spawn(move || {
                let outcome = protected_runtime_owner::run(arguments, worker_scheduler, worker_pam);
                let _ = done_sender.send(outcome);
            })
            .is_err()
        {
            *completed_outcome.borrow_mut() = Some(process_outcome(Err(CliError::Runtime), format));
            application.quit();
            return;
        }

        let application = application.clone();
        let completed_outcome = Rc::clone(&completed_outcome);
        gtk::glib::timeout_add_local(Duration::from_millis(20), move || {
            for task in warning_receiver.try_iter() {
                task.run(parent.clone());
            }
            for prompt in pam_receiver.try_iter() {
                present_pam_prompt(&parent, prompt);
            }
            match done_receiver.try_recv() {
                Ok(outcome) => {
                    *completed_outcome.borrow_mut() = Some(outcome);
                    application.quit();
                    gtk::glib::ControlFlow::Break
                }
                Err(mpsc::TryRecvError::Disconnected) => {
                    *completed_outcome.borrow_mut() =
                        Some(process_outcome(Err(CliError::Runtime), format));
                    application.quit();
                    gtk::glib::ControlFlow::Break
                }
                Err(mpsc::TryRecvError::Empty) => gtk::glib::ControlFlow::Continue,
            }
        });
    });
    let _ = application.run_with_args(&["runne"]);
    completed
        .borrow_mut()
        .take()
        .unwrap_or_else(|| process_outcome(Err(CliError::Runtime), format))
}

struct GtkWarningScheduler(mpsc::Sender<NativePermissionWarningUiTask>);

impl NativePermissionWarningMainThreadScheduler for GtkWarningScheduler {
    fn schedule(&self, task: NativePermissionWarningUiTask) -> Result<(), ()> {
        self.0.send(task).map_err(|_| ())
    }
}

struct PamPrompt {
    kind: PamMessageKind,
    message: String,
    cancellation: PamCancellation,
    response: mpsc::SyncSender<Result<Option<Zeroizing<Vec<u8>>>, PamInteractionError>>,
}

struct GtkPamHandler(mpsc::Sender<PamPrompt>);

impl PamConversationHandler for GtkPamHandler {
    fn present(
        &self,
        kind: PamMessageKind,
        message: &str,
        cancellation: &PamCancellation,
    ) -> Result<Option<Zeroizing<Vec<u8>>>, PamInteractionError> {
        if cancellation.is_cancelled() || message.len() > 1024 {
            return Err(PamInteractionError::Cancelled);
        }
        let (sender, receiver) = mpsc::sync_channel(1);
        self.0
            .send(PamPrompt {
                kind,
                message: message.to_owned(),
                cancellation: cancellation.clone(),
                response: sender,
            })
            .map_err(|_| PamInteractionError::Rejected)?;
        loop {
            if cancellation.is_cancelled() {
                return Err(PamInteractionError::Cancelled);
            }
            match receiver.recv_timeout(Duration::from_millis(50)) {
                Ok(response) => return response,
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    return Err(PamInteractionError::Rejected);
                }
            }
        }
    }
}

fn present_pam_prompt(parent: &gtk::ApplicationWindow, prompt: PamPrompt) {
    if !gtk::is_initialized_main_thread() || prompt.cancellation.is_cancelled() {
        let _ = prompt.response.send(Err(PamInteractionError::Cancelled));
        return;
    }
    let dialog = gtk::Dialog::with_buttons(
        Some("System authentication"),
        Some(parent),
        gtk::DialogFlags::MODAL | gtk::DialogFlags::DESTROY_WITH_PARENT,
        &[
            ("Cancel", gtk::ResponseType::Cancel),
            ("Continue", gtk::ResponseType::Accept),
        ],
    );
    dialog.set_default_response(gtk::ResponseType::Cancel);
    let label = gtk::Label::new(Some(if prompt.message.is_empty() {
        "Confirm your system account to continue."
    } else {
        &prompt.message
    }));
    label.set_line_wrap(true);
    label.set_max_width_chars(64);
    dialog.content_area().add(&label);
    let entry = if prompt.kind == PamMessageKind::EchoOff {
        let entry = gtk::Entry::new();
        entry.set_visibility(false);
        entry.set_input_purpose(gtk::InputPurpose::Password);
        entry.set_max_length(4096);
        entry.set_activates_default(true);
        dialog.content_area().add(&entry);
        Some(entry)
    } else {
        None
    };
    let finished = Rc::new(Cell::new(false));
    let response_finished = Rc::clone(&finished);
    let response_entry = entry.clone();
    let response_sender = prompt.response.clone();
    dialog.connect_response(move |dialog, response| {
        if response_finished.replace(true) {
            dialog.hide();
            return;
        }
        let outcome = if response == gtk::ResponseType::Accept {
            pam_response(response_entry.as_ref())
        } else {
            Err(PamInteractionError::Cancelled)
        };
        if let Some(entry) = response_entry.as_ref() {
            entry.set_text("");
        }
        let _ = response_sender.try_send(outcome);
        dialog.hide();
    });
    let close_finished = Rc::clone(&finished);
    let close_entry = entry.clone();
    let close_sender = prompt.response;
    dialog.connect_destroy(move |_| {
        if !close_finished.replace(true) {
            if let Some(entry) = close_entry.as_ref() {
                entry.set_text("");
            }
            let _ = close_sender.try_send(Err(PamInteractionError::Cancelled));
        }
    });
    dialog.connect_delete_event(|dialog, _| {
        dialog.response(gtk::ResponseType::Cancel);
        gtk::glib::Propagation::Stop
    });
    let timer_finished = Rc::clone(&finished);
    let timer_dialog = dialog.clone();
    let timer_parent = parent.clone();
    gtk::glib::timeout_add_local(Duration::from_millis(50), move || {
        if timer_finished.get() {
            gtk::glib::ControlFlow::Break
        } else if prompt.cancellation.is_cancelled() || !timer_parent.is_visible() {
            timer_dialog.response(gtk::ResponseType::Cancel);
            gtk::glib::ControlFlow::Break
        } else {
            gtk::glib::ControlFlow::Continue
        }
    });
    dialog.show_all();
    if let Some(entry) = entry {
        entry.grab_focus();
    }
}

fn pam_response(
    entry: Option<&gtk::Entry>,
) -> Result<Option<Zeroizing<Vec<u8>>>, PamInteractionError> {
    let Some(entry) = entry else {
        return Ok(None);
    };
    let mut text = entry.text().to_string();
    if text.is_empty() || text.len() > 4096 || text.as_bytes().contains(&0) {
        text.zeroize();
        return Err(PamInteractionError::Rejected);
    }
    Ok(Some(Zeroizing::new(std::mem::take(&mut text).into_bytes())))
}
