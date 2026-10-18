use std::cell::{Cell, RefCell};
use std::rc::Rc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use gtk::prelude::{ContainerExt, DialogExt, GtkWindowExt, LabelExt, WidgetExt};
use runne_runtime_client::{ApprovalDecisionDto, CanonicalId};

const MAX_DISCLOSURE_BYTES: usize = 4096;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApprovalConfirmationError {
    InvalidReview,
    Unavailable,
    Declined,
    Expired,
}

/// Canonical, non-authoritative material shown before an approval decision.
pub struct LinuxApprovalReview {
    pub approval_id: CanonicalId,
    pub task_run_id: CanonicalId,
    pub attempt_id: Option<CanonicalId>,
    pub invocation_id: CanonicalId,
    pub command_id: CanonicalId,
    pub action: String,
    pub resource: String,
    pub risk_summary: String,
    pub action_digest: [u8; 32],
    pub policy_revision: u64,
    pub request_version: u64,
    pub approval_generation: u64,
    pub decision: ApprovalDecisionDto,
    pub digest: [u8; 32],
    pub expires_at_unix_ms: i64,
}

impl LinuxApprovalReview {
    /// Checks the bounds and required fields before rendering the review.
    ///
    /// # Errors
    /// Returns `InvalidReview` when disclosure or binding fields are invalid.
    pub fn validate(&self) -> Result<(), ApprovalConfirmationError> {
        if self.action.is_empty()
            || self.resource.is_empty()
            || self.risk_summary.is_empty()
            || self.action.len() > MAX_DISCLOSURE_BYTES
            || self.resource.len() > MAX_DISCLOSURE_BYTES
            || self.risk_summary.len() > MAX_DISCLOSURE_BYTES
            || self.action.chars().any(char::is_control)
            || self.resource.chars().any(char::is_control)
            || self.risk_summary.chars().any(char::is_control)
            || self.action_digest == [0; 32]
            || self.policy_revision == 0
            || self.request_version == 0
            || self.approval_generation == 0
            || self.digest == [0; 32]
            || self.expires_at_unix_ms <= 0
        {
            return Err(ApprovalConfirmationError::InvalidReview);
        }
        Ok(())
    }
}

/// One-shot native confirmation bound to the exact review digest and expiry.
pub struct LinuxApprovalConfirmation {
    digest: [u8; 32],
    expires_at_unix_ms: i64,
    confirmed_at_unix_ms: i64,
}

impl LinuxApprovalConfirmation {
    /// Consumes the native result only for the same review before its deadline.
    #[must_use]
    pub fn consume(self, digest: [u8; 32], expires_at_unix_ms: i64) -> bool {
        self.digest == digest
            && self.expires_at_unix_ms == expires_at_unix_ms
            && self.confirmed_at_unix_ms < expires_at_unix_ms
            && unix_millis().is_some_and(|now| now < expires_at_unix_ms)
    }
}

/// Shows the requested decision in a GTK dialog on the calling main thread.
///
/// # Errors
/// Returns an error when review is invalid, GTK is unavailable, the prompt expires, or it is declined.
pub fn confirm_linux_approval(
    review: &LinuxApprovalReview,
) -> Result<LinuxApprovalConfirmation, ApprovalConfirmationError> {
    review.validate()?;
    if !gtk::is_initialized_main_thread() {
        gtk::init().map_err(|_| ApprovalConfirmationError::Unavailable)?;
    }
    if !gtk::is_initialized_main_thread() {
        return Err(ApprovalConfirmationError::Unavailable);
    }
    let now = unix_millis().ok_or(ApprovalConfirmationError::Unavailable)?;
    let remaining = review
        .expires_at_unix_ms
        .checked_sub(now)
        .filter(|remaining| *remaining > 0)
        .ok_or(ApprovalConfirmationError::Expired)?;
    let delay = Duration::from_millis(
        u64::try_from(remaining).map_err(|_| ApprovalConfirmationError::Expired)?,
    );

    let dialog = gtk::Dialog::with_buttons(
        Some("Confirm approval decision"),
        None::<&gtk::Window>,
        gtk::DialogFlags::MODAL,
        &[
            ("Cancel", gtk::ResponseType::Cancel),
            (decision_button(review.decision), gtk::ResponseType::Accept),
        ],
    );
    dialog.set_modal(true);
    dialog.set_resizable(false);
    dialog.set_default_response(gtk::ResponseType::Cancel);
    let label = gtk::Label::new(Some(&review_text(review)));
    label.set_use_markup(false);
    label.set_line_wrap(true);
    label.set_max_width_chars(76);
    label.set_margin_top(16);
    label.set_margin_bottom(16);
    label.set_margin_start(16);
    label.set_margin_end(16);
    dialog.content_area().add(&label);

    let accepted = Rc::new(RefCell::new(None));
    let response_accepted = Rc::clone(&accepted);
    let digest = review.digest;
    let expires_at_unix_ms = review.expires_at_unix_ms;
    dialog.connect_response(move |dialog, response| {
        let active = dialog.is_active();
        let visible = dialog.is_visible();
        let now = unix_millis();
        if let Some(now) = now.filter(|current| {
            response_authorizes(
                response,
                active,
                visible,
                Some(*current),
                expires_at_unix_ms,
            )
        }) {
            *response_accepted.borrow_mut() = Some(LinuxApprovalConfirmation {
                digest,
                expires_at_unix_ms,
                confirmed_at_unix_ms: now,
            });
        }
    });
    dialog.connect_delete_event(|dialog, _| {
        dialog.response(gtk::ResponseType::Cancel);
        gtk::glib::Propagation::Stop
    });

    let expired = Rc::new(Cell::new(false));
    let timer_expired = Rc::clone(&expired);
    let timer_dialog = dialog.clone();
    let timer = gtk::glib::timeout_add_local_once(delay, move || {
        timer_expired.set(true);
        timer_dialog.response(gtk::ResponseType::Cancel);
    });
    dialog.show_all();
    let _ = dialog.run();
    if !expired.get() {
        timer.remove();
    }

    if expired.get() {
        return Err(ApprovalConfirmationError::Expired);
    }
    accepted
        .borrow_mut()
        .take()
        .ok_or(ApprovalConfirmationError::Declined)
}

fn response_authorizes(
    response: gtk::ResponseType,
    active: bool,
    visible: bool,
    now: Option<i64>,
    expires_at_unix_ms: i64,
) -> bool {
    response == gtk::ResponseType::Accept
        && active
        && visible
        && now.is_some_and(|current| current < expires_at_unix_ms)
}

const fn decision_button(decision: ApprovalDecisionDto) -> &'static str {
    match decision {
        ApprovalDecisionDto::Approve => "Confirm approve",
        ApprovalDecisionDto::Deny => "Confirm deny",
    }
}

fn review_text(review: &LinuxApprovalReview) -> String {
    let attempt = review
        .attempt_id
        .map_or_else(|| "none".to_owned(), |id| id.to_string());
    format!(
        "Approval ID: {}\nTask run ID: {}\nAttempt ID: {attempt}\nInvocation ID: {}\nCommand ID: {}\nDecision: {}\nAction: {}\nResource: {}\nRisk summary: {}\nAction digest: {}\nPolicy revision: {}\nRequest version: {}\nApproval generation: {}\nExpires at (Unix ms): {}",
        review.approval_id,
        review.task_run_id,
        review.invocation_id,
        review.command_id,
        decision_name(review.decision),
        escape_bidi_and_controls(&review.action),
        escape_bidi_and_controls(&review.resource),
        escape_bidi_and_controls(&review.risk_summary),
        hex::encode(review.action_digest),
        review.policy_revision,
        review.request_version,
        review.approval_generation,
        review.expires_at_unix_ms,
    )
}

const fn decision_name(decision: ApprovalDecisionDto) -> &'static str {
    match decision {
        ApprovalDecisionDto::Approve => "approve",
        ApprovalDecisionDto::Deny => "deny",
    }
}

fn escape_bidi_and_controls(value: &str) -> String {
    let mut rendered = String::with_capacity(value.len());
    for character in value.chars() {
        if character.is_control() || is_bidi_control(character) {
            use std::fmt::Write as _;
            let _ = write!(rendered, "\\u{{{:04X}}}", character as u32);
        } else {
            rendered.push(character);
        }
    }
    rendered
}

const fn is_bidi_control(character: char) -> bool {
    matches!(character as u32, 0x061c | 0x200e | 0x200f | 0x202a..=0x202e | 0x2066..=0x206f)
}

fn unix_millis() -> Option<i64> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()?
        .as_millis();
    i64::try_from(millis).ok()
}

#[cfg(test)]
#[path = "approval_confirmation_linux/tests.rs"]
mod tests;
