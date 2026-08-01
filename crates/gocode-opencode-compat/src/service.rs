//! Fail-closed `POST /session` compatibility orchestration.

use std::collections::BTreeMap;
use std::sync::Arc;

use gocode_api::{
    ApiCommandContext, CreateConversationInput, CreateConversationOutput, NonNegativeUnixMillis,
    OpenCodeSessionInfo, SessionHostPort,
};
use gocode_domain::id::{CommandId, ConversationId, IdempotencyKey, WorkspaceId};
use jsonschema::JSONSchema;
use sha2::{Digest, Sha256};

use crate::binding::{
    BindingRuntimeAuthorityId, EnsurePendingResult, MAX_RECOVERY_PENDING_LIMIT,
    SessionBindingContext, SessionBindingKey, SessionBindingStatus, SessionBindingStore,
    SessionCreateFingerprint,
};
use crate::error::{RecoveryListError, SessionCreateError};
use crate::profile::{
    OPENCODE_BASELINE_INVENTORY_PROFILE_ID, ProfileRef, SESSION_CREATE_PROFILE_REVISION,
};

const MAX_PROMPT_PARTS: usize = 256;
const MAX_PROMPT_TEXT_BYTES: usize = 1024 * 1024;
const MAX_PROMPT_RESPONSE_BYTES: usize = 2 * 1024 * 1024;

include!("service_parts/session_create.rs");
include!("service_parts/session_create_helpers.rs");
include!("service_parts/session_v1_types.rs");
include!("service_parts/session_v1_service.rs");
include!("service_parts/prompt.rs");
