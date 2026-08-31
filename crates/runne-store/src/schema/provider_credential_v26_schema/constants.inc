const V26_TABLE: &str = "provider_online_credential_effect_bindings";
const V26_ISSUANCE_EVIDENCE_TABLE: &str = "provider_online_dispatch_issuance_evidence";
const V26_CLAIM_PROVIDER_TABLE: &str = "provider_online_dispatch_claim_providers";
const V26_TRIGGERS: [&str; 9] = [
    "provider_online_dispatch_issuance_evidence_insert_current",
    "provider_online_dispatch_issuance_evidence_immutable",
    "provider_online_dispatch_issuance_evidence_no_delete",
    "provider_online_dispatch_claim_provider_insert_authorized",
    "provider_online_dispatch_claim_provider_immutable",
    "provider_online_dispatch_claim_provider_no_delete",
    "provider_online_credential_effect_binding_insert_current",
    "provider_online_credential_effect_binding_immutable",
    "provider_online_credential_effect_binding_no_delete",
];
