//! Revokes status authority on every V2 control-loop exit.

pub(super) struct SessionRevocationGuard<F: FnMut([u8; 16])> {
    session: [u8; 16],
    revoke: F,
}

impl<F: FnMut([u8; 16])> SessionRevocationGuard<F> {
    pub(super) fn new(session: [u8; 16], revoke: F) -> Self {
        Self { session, revoke }
    }

    pub(super) fn revoke(&mut self) {
        (self.revoke)(self.session);
    }

    pub(super) fn track(&mut self, next: [u8; 16]) {
        self.revoke();
        self.session = next;
    }
}

impl<F: FnMut([u8; 16])> Drop for SessionRevocationGuard<F> {
    fn drop(&mut self) {
        self.revoke();
    }
}

#[cfg(test)]
mod tests {
    use super::SessionRevocationGuard;
    use std::cell::RefCell;

    #[test]
    fn error_exit_revokes_current_session_after_renewal() {
        let events = RefCell::new(Vec::new());
        let fail = || -> Result<(), ()> {
            let mut guard = SessionRevocationGuard::new([1; 16], |id| events.borrow_mut().push(id));
            guard.track([2; 16]);
            Err(())?;
            Ok(())
        };
        assert_eq!(fail(), Err(()));
        assert_eq!(*events.borrow(), vec![[1; 16], [2; 16]]);
    }

    #[test]
    fn explicit_shutdown_revokes_before_ack_and_drop_is_idempotent_for_host() {
        let current = RefCell::new(Some([1; 16]));
        let mut guard = SessionRevocationGuard::new([1; 16], |id| {
            let mut facts = current.borrow_mut();
            if *facts == Some(id) {
                *facts = None;
            }
        });
        guard.revoke();
        assert_eq!(*current.borrow(), None);
        drop(guard);
        assert_eq!(*current.borrow(), None);
    }
}
