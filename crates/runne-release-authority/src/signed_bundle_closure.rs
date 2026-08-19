//! Internal move-only effect closure attached to one prevalidated bundle.

use crate::{AuthorityError, FixturePrevalidatedSignedBundle};

impl FixturePrevalidatedSignedBundle {
    pub(crate) fn attach_effect_closure(
        &self,
        closure: crate::rc2_effect_lease::FixtureRc2EffectClosure,
    ) -> Result<(), AuthorityError> {
        let mut stored = self.effect_closure.borrow_mut();
        if stored.is_some() {
            return Err(AuthorityError::BindingMismatch);
        }
        *stored = Some(closure);
        Ok(())
    }
    pub(crate) fn take_effect_closure(
        &self,
    ) -> Result<crate::rc2_effect_lease::FixtureRc2EffectClosure, AuthorityError> {
        self.effect_closure
            .borrow_mut()
            .take()
            .ok_or(AuthorityError::BindingMismatch)
    }
    pub(crate) fn restore_effect_closure(
        &self,
        closure: crate::rc2_effect_lease::FixtureRc2EffectClosure,
    ) {
        *self.effect_closure.borrow_mut() = Some(closure);
    }
}
