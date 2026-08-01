use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

use crate::id::{InvalidProviderId, ProviderCallId, ProviderId, bounded_identifier};

include!("model/model_ref.rs");
include!("model/call.rs");
include!("model/extensions.rs");
include!("model/finish_reason.rs");
