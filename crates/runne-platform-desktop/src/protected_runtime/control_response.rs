use super::ProtectedBundledRuntimeError;

pub(super) trait RejoinRegistration {
    async fn register(
        &self,
        prepared: super::PreparedCredentialServiceRejoin,
    ) -> Result<super::RegisteredCredentialServiceSession, ProtectedBundledRuntimeError>;
}

pub(super) struct NativeRegistration;

impl RejoinRegistration for NativeRegistration {
    async fn register(
        &self,
        prepared: super::PreparedCredentialServiceRejoin,
    ) -> Result<super::RegisteredCredentialServiceSession, ProtectedBundledRuntimeError> {
        prepared.register().await
    }
}

pub(super) enum Response<T> {
    Complete(T),
    Rejoin,
}

pub(super) trait ControlSteps {
    type Output;
    async fn read(&mut self) -> Result<Response<Self::Output>, ProtectedBundledRuntimeError>;
    async fn rejoin(&mut self) -> Result<(), ProtectedBundledRuntimeError>;
}

pub(super) async fn run<S: ControlSteps>(
    mut steps: S,
) -> Result<S::Output, ProtectedBundledRuntimeError> {
    match steps.read().await? {
        Response::Complete(ids) => Ok(ids),
        Response::Rejoin => {
            steps.rejoin().await?;
            match steps.read().await? {
                Response::Complete(ids) => Ok(ids),
                Response::Rejoin => Err(ProtectedBundledRuntimeError::OwnershipMismatch),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};

    struct Steps {
        responses: VecDeque<Response<Vec<[u8; 16]>>>,
        events: Arc<Mutex<Vec<&'static str>>>,
        fail_rejoin: bool,
    }
    impl ControlSteps for Steps {
        type Output = Vec<[u8; 16]>;
        async fn read(&mut self) -> Result<Response<Self::Output>, ProtectedBundledRuntimeError> {
            self.events.lock().unwrap().push("read");
            self.responses
                .pop_front()
                .ok_or(ProtectedBundledRuntimeError::InvalidState)
        }
        async fn rejoin(&mut self) -> Result<(), ProtectedBundledRuntimeError> {
            self.events.lock().unwrap().push("rejoin");
            if self.fail_rejoin {
                Err(ProtectedBundledRuntimeError::OwnershipMismatch)
            } else {
                Ok(())
            }
        }
    }

    #[tokio::test]
    async fn discovery_services_one_rejoin_then_returns_original_response() {
        let events = Arc::new(Mutex::new(vec![]));
        let result = run(Steps {
            responses: VecDeque::from([Response::Rejoin, Response::Complete(vec![[7; 16]])]),
            events: Arc::clone(&events),
            fail_rejoin: false,
        })
        .await;
        assert_eq!(result.unwrap(), vec![[7; 16]]);
        assert_eq!(*events.lock().unwrap(), ["read", "rejoin", "read"]);
    }

    #[tokio::test]
    async fn failed_or_repeated_rejoin_never_retries_registration() {
        for fail_rejoin in [false, true] {
            let events = Arc::new(Mutex::new(vec![]));
            assert!(
                run(Steps {
                    responses: VecDeque::from([Response::Rejoin, Response::Rejoin]),
                    events: Arc::clone(&events),
                    fail_rejoin,
                })
                .await
                .is_err()
            );
            let expected = if fail_rejoin {
                vec!["read", "rejoin"]
            } else {
                vec!["read", "rejoin", "read"]
            };
            assert_eq!(*events.lock().unwrap(), expected);
        }
    }
}
