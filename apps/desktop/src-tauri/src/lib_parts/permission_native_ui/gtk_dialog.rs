use std::cell::Cell;
use std::rc::Rc;
use std::sync::mpsc;
use std::time::Duration;

use gtk::prelude::{ContainerExt, DialogExt, EntryExt, LabelExt, WidgetExt};
use runne_platform_desktop::permission_reauth_linux::{
    PamCancellation, PamConversationHandler, PamInteractionError, PamMessageKind,
};
use tauri::WebviewWindow;
use zeroize::{Zeroize, Zeroizing};

pub(super) struct GtkPamConversationHandler {
    window: WebviewWindow,
}

impl GtkPamConversationHandler {
    pub(super) const fn new(window: WebviewWindow) -> Self {
        Self { window }
    }
}

impl PamConversationHandler for GtkPamConversationHandler {
    fn present(
        &self,
        kind: PamMessageKind,
        message: &str,
        cancellation: &PamCancellation,
    ) -> Result<Option<Zeroizing<Vec<u8>>>, PamInteractionError> {
        if cancellation.is_cancelled() {
            return Err(PamInteractionError::Cancelled);
        }
        if message.len() > 1024 {
            return Err(PamInteractionError::Rejected);
        }
        let message = message.to_owned();
        let (sender, receiver) = mpsc::sync_channel(1);
        let window = self.window.clone();
        let ui_window = window.clone();
        let ui_cancellation = cancellation.clone();
        window
            .run_on_main_thread(move || {
                let outcome = ui_window
                    .gtk_window()
                    .map_err(|_| PamInteractionError::Rejected)
                    .and_then(|parent| {
                        show_prompt(&parent, kind, &message, ui_cancellation, sender.clone())
                    });
                if let Err(error) = outcome {
                    let _ = sender.send(Err(error));
                }
            })
            .map_err(|_| PamInteractionError::Rejected)?;
        loop {
            if cancellation.is_cancelled() {
                return Err(PamInteractionError::Cancelled);
            }
            match receiver.recv_timeout(Duration::from_millis(50)) {
                Ok(result) => return result,
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    return Err(PamInteractionError::Rejected);
                }
            }
        }
    }
}

fn show_prompt(
    parent: &gtk::ApplicationWindow,
    kind: PamMessageKind,
    message: &str,
    cancellation: PamCancellation,
    sender: mpsc::SyncSender<Result<Option<Zeroizing<Vec<u8>>>, PamInteractionError>>,
) -> Result<(), PamInteractionError> {
    if !gtk::is_initialized_main_thread() || cancellation.is_cancelled() {
        return Err(PamInteractionError::Cancelled);
    }
    let echo_off = kind == PamMessageKind::EchoOff;
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
    let label = gtk::Label::new(Some(if message.is_empty() {
        "Confirm your system account to continue."
    } else {
        message
    }));
    label.set_line_wrap(true);
    label.set_max_width_chars(64);
    dialog.content_area().add(&label);
    let entry = echo_off.then(|| {
        let entry = gtk::Entry::new();
        entry.set_visibility(false);
        entry.set_input_purpose(gtk::InputPurpose::Password);
        entry.set_max_length(4096);
        entry.set_activates_default(true);
        dialog.content_area().add(&entry);
        entry
    });
    let finished = Rc::new(Cell::new(false));
    let response_finished = Rc::clone(&finished);
    let response_entry = entry.clone();
    let response_sender = sender.clone();
    dialog.connect_response(move |dialog, response| {
        if response_finished.replace(true) {
            dialog.hide();
            return;
        }
        let outcome = if response == gtk::ResponseType::Accept {
            password_response(response_entry.as_ref())
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
    let close_sender = sender;
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
        } else if cancellation.is_cancelled() || !timer_parent.is_visible() {
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
    Ok(())
}

fn password_response(
    entry: Option<&gtk::Entry>,
) -> Result<Option<Zeroizing<Vec<u8>>>, PamInteractionError> {
    let Some(entry) = entry else {
        return Ok(None);
    };
    let mut text = entry.text().to_string();
    let bytes = text.as_bytes();
    if bytes.is_empty() || bytes.len() > 4096 {
        text.zeroize();
        return Err(PamInteractionError::Rejected);
    }
    Ok(Some(Zeroizing::new(std::mem::take(&mut text).into_bytes())))
}
