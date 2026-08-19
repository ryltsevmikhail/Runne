use std::collections::HashMap;

use base64::Engine;
use runne_domain::id::SecretRefId;
use runne_domain::security::SecretRef;
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

use crate::prohibited_content::{ProhibitedContentGuard, SharedSecretRegistry};

include!("secret/types.rs");
include!("secret/representations.rs");
include!("secret/broker.rs");

#[cfg(test)]
mod tests {
    include!("secret/tests.rs");
}
