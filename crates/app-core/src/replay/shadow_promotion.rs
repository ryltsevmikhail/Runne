use super::{AppCoreError, map_store_error};
use crate::RuntimeOperationContext;
use gocode_local_store::{
    ReplayBaselineSeed, ReplayScopeKey, ReplayTransition, ShadowPromotionCoordinates,
};
use gocode_runtime_client::{ReplayRetentionBaselineV2, ReplayScope, replay_persistence_digest};

impl crate::AppCore {
    /// Promotes a server-authenticated V2 baseline without acknowledging it
    /// until the sealed local selector has been committed and read back.
    #[allow(clippy::too_many_lines)]
    pub(crate) async fn promote_retention_baseline_v2_under_operation(
        &self,
        context: &RuntimeOperationContext,
        scope: ReplayScope,
        scope_key: &ReplayScopeKey,
        expected_active: Option<&gocode_local_store::ReplayCheckpoint>,
        baseline: &ReplayRetentionBaselineV2,
    ) -> Result<(), AppCoreError> {
        self.require_current_operation_context(context)?;
        let Some(security) = self.mutation_security.as_ref() else {
            return Err(AppCoreError::MutationUnavailable);
        };
        let secure = security.secure.as_ref();
        let seed = ReplayBaselineSeed::from_authenticated_v2(
            scope_key,
            baseline.authenticated_capability(),
        )
        .map_err(|error| map_store_error(&error))?;
        let payload = baseline
            .authenticated_capability()
            .local_projection()
            .map_err(|_| AppCoreError::LocalProjectionUnavailable)?
            .local_persistence_bytes()
            .to_vec();
        let digest = replay_persistence_digest(&payload);
        let shadow = std::sync::Mutex::new(None);
        let local_error = std::sync::Mutex::new(None);
        let pending = context
            .client
            .begin_resume_from_retention_baseline_v2(
                scope,
                baseline,
                |checkpoint, verified_baseline| {
                    let Ok(mut store) = self.store.lock() else {
                        *local_error.lock().expect("local error lock") =
                            Some(AppCoreError::StateUnavailable);
                        return Err(());
                    };
                    let created = store
                        .begin_anchored_shadow_replay(secure, scope_key, &seed)
                        .and_then(|id| {
                            store.accept_authenticated_anchored_shadow_baseline(
                                secure,
                                scope_key,
                                &id,
                                verified_baseline.authenticated_capability(),
                                checkpoint,
                                ShadowPromotionCoordinates {
                                    generation: context.identity.launch_generation,
                                    projection_revision: 1,
                                },
                            )?;
                            Ok(id)
                        });
                    match created {
                        Ok(id) => {
                            *shadow.lock().expect("shadow lock") = Some(id);
                            Ok(())
                        }
                        Err(error) => {
                            *local_error.lock().expect("local error lock") =
                                Some(map_store_error(&error));
                            Err(())
                        }
                    }
                },
                |delivery, _final_suffix| {
                    let Some(shadow) = shadow.lock().expect("shadow lock").clone() else {
                        *local_error.lock().expect("local error lock") =
                            Some(AppCoreError::LocalProjectionUnavailable);
                        return Err(());
                    };
                    let Ok(mut store) = self.store.lock() else {
                        *local_error.lock().expect("local error lock") =
                            Some(AppCoreError::StateUnavailable);
                        return Err(());
                    };
                    let expected = match store
                        .authenticated_shadow_replay_checkpoint(secure, scope_key, &shadow)
                    {
                        Ok(value) => value,
                        Err(error) => {
                            *local_error.lock().expect("local error lock") =
                                Some(map_store_error(&error));
                            return Err(());
                        }
                    };
                    let outcome = delivery.persist_with(|handoff| {
                        store.apply_anchored_shadow_replay_transition(
                            secure,
                            &shadow,
                            &ReplayTransition {
                                scope: scope_key,
                                expected_checkpoint: expected.as_ref(),
                                event_id: &delivery.event_id().to_string(),
                                cursor: handoff.cursor_value(),
                                generation: context.identity.launch_generation,
                                event_sequence: delivery.event().sequence(),
                                event_bytes: handoff.canonical_event_bytes(),
                                event_digest: handoff.event_digest().to_owned(),
                                projection_revision: expected
                                    .as_ref()
                                    .map_or(1, |value| value.projection_revision),
                                projection_bytes: &payload,
                                projection_digest: digest.clone(),
                            },
                        )
                    });
                    if let Err(error) = outcome {
                        *local_error.lock().expect("local error lock") =
                            Some(map_store_error(&error));
                        return Err(());
                    }
                    Ok(())
                },
            )
            .await;
        let pending = match pending {
            Ok(pending) => pending,
            Err(error) => {
                return Err(local_error
                    .lock()
                    .expect("local error lock")
                    .take()
                    .unwrap_or_else(|| self.map_replay_failure(&error, scope_key)));
            }
        };
        let Some(shadow) = shadow.lock().expect("shadow lock").take() else {
            pending.abort().await;
            return Err(AppCoreError::LocalProjectionUnavailable);
        };
        let local_commit = (|| {
            let mut store = self
                .store
                .lock()
                .map_err(|_| AppCoreError::StateUnavailable)?;
            store
                .finalize_authenticated_anchored_shadow_projection(
                    secure,
                    scope_key,
                    &shadow,
                    pending.accepted_promotion().capability(),
                    2,
                )
                .map_err(|error| map_store_error(&error))?;
            store
                .seal_anchored_shadow_promotion(secure, scope_key, &shadow, expected_active)
                .map_err(|error| map_store_error(&error))?;
            store
                .commit_anchored_shadow_promotion(secure, scope_key, &shadow)
                .map_err(|error| map_store_error(&error))?;
            drop(store);
            Ok::<(), AppCoreError>(())
        })();
        if let Err(error) = local_commit {
            pending.abort().await;
            return Err(error);
        }
        self.require_current_operation_context(context)?;
        pending
            .activate()
            .await
            .map(|_| ())
            .map_err(|error| self.map_replay_failure(&error, scope_key))
    }
}
