#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(untagged)]
enum StoredConversationReference {
    V1(StoredConversationReferenceV1),
    V2(StoredConversationReferenceV2),
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StoredConversationReferenceV1 {
    schema_version: u32,
    conversation_id: CanonicalId,
    workspace_id: CanonicalId,
    create_command_id: CanonicalId,
    idempotency_key: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StoredConversationReferenceV2 {
    schema_version: u32,
    conversation_id: CanonicalId,
    workspace_id: CanonicalId,
    create_command_id: CanonicalId,
    idempotency_key: String,
    runtime_authority: String,
    principal: String,
    lineage: String,
    profile_id: String,
    schema_hash: String,
    capability_digest: String,
}

impl StoredConversationReference {
    const fn conversation_id(&self) -> CanonicalId {
        match self {
            Self::V1(reference) => reference.conversation_id,
            Self::V2(reference) => reference.conversation_id,
        }
    }

    const fn workspace_id(&self) -> CanonicalId {
        match self {
            Self::V1(reference) => reference.workspace_id,
            Self::V2(reference) => reference.workspace_id,
        }
    }

    const fn create_command_id(&self) -> CanonicalId {
        match self {
            Self::V1(reference) => reference.create_command_id,
            Self::V2(reference) => reference.create_command_id,
        }
    }

    fn idempotency_key(&self) -> &str {
        match self {
            Self::V1(reference) => &reference.idempotency_key,
            Self::V2(reference) => &reference.idempotency_key,
        }
    }

    const fn bound(&self) -> Option<&StoredConversationReferenceV2> {
        match self {
            Self::V1(_) => None,
            Self::V2(reference) => Some(reference),
        }
    }
}

fn parse_conversation_reference(value: &str) -> Result<StoredConversationReference, AppCoreError> {
    let reference: StoredConversationReference =
        serde_json::from_str(value).map_err(|_| AppCoreError::InvalidConversationReference)?;
    let valid_schema = matches!(
        &reference,
        StoredConversationReference::V1(value) if value.schema_version == 1
    ) || matches!(
        &reference,
        StoredConversationReference::V2(value)
            if value.schema_version == CONVERSATION_REFERENCE_SCHEMA_VERSION
                && !value.runtime_authority.is_empty()
                && !value.principal.is_empty()
                && !value.lineage.is_empty()
                && !value.profile_id.is_empty()
                && !value.schema_hash.is_empty()
                && !value.capability_digest.is_empty()
    );
    if !valid_schema
        || CommandIdentity::new(
            reference.create_command_id(),
            reference.idempotency_key().to_owned(),
        )
        .is_err()
    {
        return Err(AppCoreError::InvalidConversationReference);
    }
    Ok(reference)
}

const fn map_profile_state(error: LocalProfileError) -> RuntimeAvailability {
    match error {
        LocalProfileError::Unavailable => RuntimeAvailability::Reconnecting,
        LocalProfileError::InsecurePermissions | LocalProfileError::InvalidProfile => {
            RuntimeAvailability::Incompatible
        }
        LocalProfileError::InvalidCredential => RuntimeAvailability::Revoked,
    }
}

const fn map_connect_state(error: &LocalRuntimeConnectError) -> RuntimeAvailability {
    match error {
        LocalRuntimeConnectError::Transport(_) => RuntimeAvailability::Reconnecting,
        LocalRuntimeConnectError::Api(error) => match error.kind() {
            RuntimeApiErrorKind::Unauthorized => RuntimeAvailability::Revoked,
            RuntimeApiErrorKind::Incompatible | RuntimeApiErrorKind::InvalidResponse => {
                RuntimeAvailability::Incompatible
            }
            RuntimeApiErrorKind::InvalidRequest
            | RuntimeApiErrorKind::NotFound
            | RuntimeApiErrorKind::Conflict
            | RuntimeApiErrorKind::Backpressure
            | RuntimeApiErrorKind::Unavailable
            | RuntimeApiErrorKind::ResponseTooLarge => RuntimeAvailability::Reconnecting,
        },
    }
}
