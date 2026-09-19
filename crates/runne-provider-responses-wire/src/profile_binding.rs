use crate::ResponsesProfile;
use serde_json::{Value, json};

impl ResponsesProfile {
    pub(crate) fn effective_binding_extension(&self) -> Value {
        if self.binding_extension().is_null() {
            json!({
                "profile_id": self.profile_id(),
                "profile_digest": hex::encode(self.profile_digest()),
                "pricing_revision_digest": hex::encode(self.pricing_revision_digest()),
            })
        } else {
            self.binding_extension().clone()
        }
    }
}
