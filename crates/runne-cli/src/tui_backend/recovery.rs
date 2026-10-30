use super::{Backend, journal::Journal, pending};
use runne_runtime_client::{
    CommandReconciliationDisposition as Disposition, CommandReconciliationOutcome as Outcome,
};
impl Backend {
    pub(super) fn journal(&mut self) -> Result<&Journal, String> {
        if self.journal.is_none() {
            let workspace = self.owner.workspace_id.ok_or("Project root not admitted")?;
            let state =
                crate::state_dir::state_root().ok_or("Command journal directory unavailable")?;
            self.journal = Some(Journal::open(
                &state,
                pending::scope(self.owner.client.session_info(), workspace),
            )?);
        }
        self.journal
            .as_ref()
            .ok_or_else(|| "Command journal unavailable".into())
    }
    pub(super) async fn recover_pending(&mut self) -> Result<(), String> {
        let records = self.journal()?.pending()?;
        self.submit_uncertain = !records.is_empty();
        for record in records {
            if Some(record.workspace) != self.owner.workspace_id
                || record.scope
                    != pending::scope(self.owner.client.session_info(), record.workspace)
            {
                return Err("Pending command project/session scope changed".into());
            }
            let result = self
                .owner
                .client
                .reconcile_command(record.witness()?)
                .await
                .map_err(|error| format!("Pending command reconciliation unavailable: {error}"))?;
            let not_committed = matches!(&result, Disposition::NotCommittedRetryable);
            match result {
                Disposition::DurablyRecorded(Outcome::ConversationCreated(created))
                    if record.prompt.is_none() =>
                {
                    select_recovered(&mut self.selected, created.conversation_id);
                }
                Disposition::DurablyRecorded(Outcome::TaskRunSubmitted(_))
                    if record.prompt.is_some() =>
                {
                    select_recovered(&mut self.selected, record.conversation);
                }
                Disposition::NotCommittedRetryable => {
                    self.snapshot.status =
                        "Pending command was not committed; no automatic resend".into();
                }
                _ => return Err("Pending command remains uncertain; no automatic replay".into()),
            }
            self.journal()?.resolved(&record)?;
            if not_committed && let Some(prompt) = record.prompt {
                self.recovered_drafts.push(prompt);
            }
        }
        self.submit_uncertain = false;
        Ok(())
    }
}

const fn select_recovered(
    selected: &mut Option<runne_runtime_client::CanonicalId>,
    recovered: runne_runtime_client::CanonicalId,
) {
    if selected.is_none() {
        *selected = Some(recovered);
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn recovering_previous_session_does_not_retarget_explicit_selection() {
        let previous = runne_runtime_client::CanonicalId::now_v7();
        let explicit = runne_runtime_client::CanonicalId::now_v7();
        let mut selected = Some(explicit);
        super::select_recovered(&mut selected, previous);
        assert_eq!(selected, Some(explicit));
        let mut absent = None;
        super::select_recovered(&mut absent, previous);
        assert_eq!(absent, Some(previous));
    }
}
