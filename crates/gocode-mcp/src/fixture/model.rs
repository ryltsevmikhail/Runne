use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::{FixtureMcpFailure, McpConnectionId, McpRuntimeInstanceId, McpServerId, McpSessionId};

const MAX_SCRIPT_STEPS: usize = 64;
const MAX_TEXT_BYTES: usize = 256;

include!("model/identity.rs");
include!("model/tool.rs");
include!("model/script.rs");
include!("model/limits.rs");
include!("model/helpers.rs");
