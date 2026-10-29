use super::{UiEvent, UiSnapshot, editor::Editor};
use zeroize::Zeroizing;

#[derive(Default, PartialEq)]
pub(super) enum Panel {
    #[default]
    Chat,
    Actions,
    Diff,
    Permissions,
    Sessions,
    Help,
}

#[derive(Default)]
pub(super) struct State {
    pub snapshot: UiSnapshot,
    pub editor: Editor,
    pub panel: Panel,
    pub scroll: usize,
    pub selection: usize,
    pub notice: String,
    pub query: String,
    pub exit_allowed: bool,
    pub submission_pending: bool,
    pub submitted_approvals: std::collections::HashSet<(String, String)>,
    pub credential_prompt: Option<crate::ProviderCredentialId>,
    pub secret: Zeroizing<String>,
}

impl State {
    pub fn event(&mut self, event: UiEvent) {
        match event {
            UiEvent::SubmissionFinished { rejected_draft } => {
                self.submission_pending = false;
                if let Some(rejected) = rejected_draft {
                    let newer = self.editor.take();
                    self.editor.restore_rejected(rejected, &newer);
                    self.notice.push_str(
                        "; unsent message restored before any newer draft; review before sending",
                    );
                }
            }
            UiEvent::ApprovalHandled { id, review_key } => {
                self.submitted_approvals.remove(&(id, review_key));
            }
            UiEvent::ShowSessions => self.panel = Panel::Sessions,
            UiEvent::ExitAllowed => self.exit_allowed = true,
            UiEvent::Snapshot(mut snapshot) => {
                snapshot.messages = bounded(snapshot.messages);
                snapshot.actions = bounded(snapshot.actions);
                self.submitted_approvals.retain(|(id, key)| {
                    snapshot
                        .approvals
                        .iter()
                        .any(|a| &a.id == id && &a.review_key == key)
                });
                self.snapshot = snapshot;
            }
            UiEvent::Text(text) => {
                self.snapshot.messages.push(text);
                self.snapshot.messages = bounded(std::mem::take(&mut self.snapshot.messages));
            }
            UiEvent::Status(text) => self.notice = text,
            UiEvent::Error(text) => self.notice = format!("Error: {text}"),
        }
    }

    pub fn push_secret(&mut self, text: &str) {
        if self.secret.len() >= runne_secure_store::MAX_PROVIDER_CREDENTIAL_BYTES {
            return;
        }
        let remaining = runne_secure_store::MAX_PROVIDER_CREDENTIAL_BYTES - self.secret.len();
        let mut end = text.len().min(remaining);
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        self.secret.push_str(&text[..end]);
    }

    pub fn cancel_credential(&mut self) {
        self.credential_prompt = None;
        self.secret.clear();
        self.notice = "Credential entry cancelled".into();
    }

    pub fn sessions(&self) -> Vec<&super::SessionEntry> {
        self.snapshot
            .sessions
            .iter()
            .filter(|s| s.title.to_lowercase().contains(&self.query.to_lowercase()))
            .collect()
    }
}

fn bounded(mut values: Vec<String>) -> Vec<String> {
    if values.len() > 2000 {
        values.drain(..values.len() - 2000);
    }
    for value in &mut values {
        if value.len() > 65536 {
            let mut end = 65536;
            while !value.is_char_boundary(end) {
                end -= 1;
            }
            value.truncate(end);
            value.push_str("\n[display truncated]");
        }
    }
    values
}
