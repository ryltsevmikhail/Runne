impl AppCore {
    fn load_or_prepare_text_only_conversation_reference(
        &self,
    ) -> Result<StoredConversationReference, AppCoreError> {
        let mut store = self
            .store
            .lock()
            .map_err(|_| AppCoreError::StateUnavailable)?;
        Self::load_or_prepare_conversation_reference_in_store(
            &mut store,
            ConversationReferenceOwner::TextOnly,
        )
    }

    fn load_workspace_conversation_reference(
        &self,
        workspace_id: &str,
    ) -> Result<StoredConversationReference, AppCoreError> {
        let workspace_id =
            CanonicalId::parse(workspace_id).map_err(|_| AppCoreError::ProjectUnavailable)?;
        let store = self
            .store
            .lock()
            .map_err(|_| AppCoreError::StateUnavailable)?;
        let key = ConversationReferenceOwner::Workspace(workspace_id).key();
        let serialized = store
            .get_setting(&key)?
            .ok_or(AppCoreError::ProjectUnavailable)?;
        let reference = parse_conversation_reference(&serialized);
        drop(store);
        reference
    }

    fn load_text_only_conversation_reference(
        &self,
    ) -> Result<StoredConversationReference, AppCoreError> {
        let store = self
            .store
            .lock()
            .map_err(|_| AppCoreError::StateUnavailable)?;
        let serialized = store
            .get_setting(&ConversationReferenceOwner::TextOnly.key())?
            .ok_or(AppCoreError::ProjectUnavailable)?;
        let reference = parse_conversation_reference(&serialized)?;
        if !reference.text_only() {
            return Err(AppCoreError::InvalidConversationReference);
        }
        drop(store);
        Ok(reference)
    }

    fn bind_conversation_reference_for_owner(
        &self,
        owner: ConversationReferenceOwner,
        reference: StoredConversationReference,
        identity: &replay::StableRuntimeIdentity,
    ) -> Result<StoredConversationReference, AppCoreError> {
        if reference.text_only() != owner.text_only() {
            return Err(AppCoreError::InvalidConversationReference);
        }
        if let Some(bound) = reference.bound() {
            if identity.matches_reference(bound) {
                return Ok(reference);
            }
            self.set_runtime_failure(RuntimeAvailability::Fatal)?;
            return Err(AppCoreError::RuntimeIdentityConflict);
        }
        let mut bound = identity.bind_reference(&reference);
        bound.text_only = reference.text_only();
        let bound = StoredConversationReference::V2(bound);
        let serialized = serde_json::to_string(&bound)
            .map_err(|_| AppCoreError::InvalidConversationReference)?;
        let mut store = self
            .store
            .lock()
            .map_err(|_| AppCoreError::StateUnavailable)?;
        store.set_setting(&owner.key(), &serialized)?;
        drop(store);
        Ok(bound)
    }
}
