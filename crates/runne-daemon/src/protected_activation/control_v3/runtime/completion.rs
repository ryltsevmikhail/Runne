use runne_api::LaunchAuthorityError;

// Keeps completion owned by the caller while the control owner services rejoin.
pub(in crate::protected_activation) fn with_control<T: Send>(
    completion: impl FnOnce() -> Result<T, LaunchAuthorityError> + Send,
    mut service: impl FnMut() -> Result<(), LaunchAuthorityError>,
) -> Result<T, LaunchAuthorityError> {
    std::thread::scope(|scope| {
        let (finished, ready) = std::sync::mpsc::channel();
        let worker = scope.spawn(move || {
            let result = completion();
            let _ = finished.send(());
            result
        });
        let control = loop {
            match ready.recv_timeout(std::time::Duration::from_millis(10)) {
                Ok(()) | Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break Ok(()),
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                    if let Err(error) = service() {
                        break Err(error);
                    }
                }
            }
        };
        // Join even on control failure: the caller retains its writer/session ownership.
        let result = worker
            .join()
            .map_err(|_| LaunchAuthorityError::InvalidContract)?;
        control?;
        result
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc,
    };
    use std::time::Duration;

    #[test]
    fn completion_can_wait_for_control_without_repeating_effect() {
        let (request, pending) = mpsc::channel();
        let (ack, accepted) = mpsc::channel();
        let result = with_control(
            move || {
                request.send(()).unwrap();
                accepted
                    .recv_timeout(Duration::from_secs(1))
                    .map_err(|_| LaunchAuthorityError::ProtectedChannelUnavailable)?;
                Ok(41)
            },
            || {
                if pending.try_recv().is_ok() {
                    let _ = ack.send(());
                }
                Ok(())
            },
        );
        assert_eq!(result.unwrap(), 41);
    }

    #[test]
    fn failed_or_panicking_readback_never_becomes_success() {
        let failed = with_control::<()>(|| Err(LaunchAuthorityError::OwnershipMismatch), || Ok(()));
        assert!(matches!(
            failed,
            Err(LaunchAuthorityError::OwnershipMismatch)
        ));
        let panicked = with_control::<()>(|| panic!("readback worker failure"), || Ok(()));
        assert!(matches!(
            panicked,
            Err(LaunchAuthorityError::InvalidContract)
        ));
    }

    #[test]
    fn control_failure_does_not_detach_completion_or_publish_success() {
        let finished = Arc::new(AtomicBool::new(false));
        let observed = Arc::clone(&finished);
        let (stop, stopped) = mpsc::channel();
        let result = with_control(
            move || {
                let _ = stopped.recv_timeout(Duration::from_secs(1));
                observed.store(true, Ordering::SeqCst);
                Ok(41)
            },
            || {
                let _ = stop.send(());
                Err(LaunchAuthorityError::OwnershipMismatch)
            },
        );
        assert!(matches!(
            result,
            Err(LaunchAuthorityError::OwnershipMismatch)
        ));
        assert!(finished.load(Ordering::SeqCst));
    }
}
